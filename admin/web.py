import errno
import hmac
import ipaddress
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import threading
import time

from settings import AUTH_PATH, WORKER_SOCKET, load_settings, password_hash


WEB_ROOT = Path(__file__).with_name('static')
MAX_BODY = 192 * 1024
SESSION_AGE = 8 * 3600
COOKIE = 'vpn_admin_session'
STATIC = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
    '/style.css': ('style.css', 'text/css; charset=utf-8'),
}
MUTATIONS = {
    '/api/devices': ('create_device', ('name',)),
    '/api/devices/revoke': ('revoke_device', ('id',)),
    '/api/upstreams': ('set_upstream', ('id', 'name', 'kind', 'config')),
    '/api/upstreams/toggle': ('toggle_upstream', ('id', 'enabled')),
}
state_lock = threading.Lock()
hash_slot = threading.BoundedSemaphore(2)
sessions = {}
attempts = {}


def worker_call(action, **parameters):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(110)
        connection.connect(WORKER_SOCKET)
        connection.sendall(json.dumps({'action': action, **parameters}, ensure_ascii=False).encode())
        connection.shutdown(socket.SHUT_WR)
        with connection.makefile('rb') as stream:
            data = stream.read(MAX_BODY + 1)
    if not data or len(data) > MAX_BODY:
        raise ValueError('invalid worker response')
    value = json.loads(data)
    if not isinstance(value, dict) or not isinstance(value.get('ok'), bool):
        raise ValueError('invalid worker response')
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = 'VPN Admin'
    sys_version = ''

    def setup(self):
        self.request.settimeout(15)
        super().setup()

    def log_message(self, *_):
        pass

    def accepted_host(self):
        source = ipaddress.IPv4Address(self.client_address[0])
        config = self.server.config
        host = self.headers.get('Host')
        port = config.listen_port
        if self.server.server_address[0] == '127.0.0.1':
            return source.is_loopback and host in (f'127.0.0.1:{port}', f'localhost:{port}')
        return source in config.vpn_client_network and host == f'{config.vpn_bind_ipv4}:{port}'

    def send_payload(self, status, data, content_type, cookie=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        if cookie is not None:
            self.send_header('Set-Cookie', f'{COOKIE}={cookie}; Max-Age={SESSION_AGE if cookie else 0}; Path=/; HttpOnly; SameSite=Strict')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass

    def json(self, status, data, cookie=None):
        payload = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode()
        self.send_payload(status, payload, 'application/json; charset=utf-8', cookie)

    def error(self, status, message):
        self.json(status, {'ok': False, 'error': message})

    def session_key(self):
        try:
            cookies = SimpleCookie(self.headers.get('Cookie', ''))
        except CookieError:
            return ''
        return cookies[COOKIE].value if COOKIE in cookies else ''

    def session(self):
        key = self.session_key()
        with state_lock:
            item = sessions.get(key)
            if item and item['expires'] <= time.monotonic():
                sessions.pop(key, None)
                return None
        return item

    def do_GET(self):
        if not self.accepted_host():
            return self.error(400, 'Неверный адрес панели.')
        if self.path in STATIC:
            filename, content_type = STATIC[self.path]
            return self.send_payload(200, (WEB_ROOT / filename).read_bytes(), content_type)
        session = self.session()
        if self.path == '/api/session':
            data = {'authenticated': False, 'csrf': '', 'username': ''}
            if session:
                data.update(authenticated=True, csrf=session['csrf'], username=session['username'])
            return self.json(200, data)
        if self.path == '/api/state':
            if not session:
                return self.error(401, 'Войди в панель, чтобы управлять VPN.')
            return self.forward('state', {})
        return self.error(404, 'Страница отсутствует.')

    def read_body(self):
        if self.headers.get_content_type() != 'application/json' or self.headers.get('Transfer-Encoding'):
            raise ValueError('expected JSON')
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 < size <= MAX_BODY:
            raise ValueError('invalid request length')
        data = json.loads(self.rfile.read(size))
        if not isinstance(data, dict):
            raise ValueError('expected an object')
        return data

    def do_POST(self):
        host = self.headers.get('Host')
        if not self.accepted_host() or self.headers.get('Origin') != f'http://{host}':
            return self.error(403, 'Запрос отклонён. Открой панель по её адресу.')
        try:
            data = self.read_body()
        except (ValueError, UnicodeError, OSError):
            return self.error(400, 'Неверный формат запроса.')
        if self.path == '/api/login':
            return self.login(data)
        session = self.session()
        if not session:
            return self.error(401, 'Сеанс завершён. Войди снова.')
        token = self.headers.get('X-CSRF-Token', '')
        if not hmac.compare_digest(session['csrf'].encode(), token.encode()):
            return self.error(403, 'Сеанс устарел. Обнови страницу.')
        if self.path == '/api/logout':
            with state_lock:
                sessions.pop(self.session_key(), None)
            return self.json(200, {'ok': True}, '')
        if self.path not in MUTATIONS:
            return self.error(404, 'Страница отсутствует.')
        action, fields = MUTATIONS[self.path]
        return self.forward(action, {key: data[key] for key in fields if key in data})

    def login(self, data):
        username, password = data.get('username'), data.get('password')
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 80 or len(password) > 256:
            return self.error(400, 'Введи логин и пароль.')
        now = time.monotonic()
        address = self.client_address[0]
        with state_lock:
            for client, (limit, _) in list(attempts.items()):
                if limit <= now:
                    del attempts[client]
            limit, count = attempts.get(address, (now + 120, 0))
            if count >= 6:
                return self.error(429, 'Слишком много попыток. Попробуй через пару минут.')
            attempts[address] = (limit, count + 1)
        if not hash_slot.acquire(blocking=False):
            return self.error(429, 'Подожди несколько секунд и попробуй снова.')
        try:
            auth = json.loads(AUTH_PATH.read_text())
            valid_username = hmac.compare_digest(username.encode(), auth['username'].encode())
            valid_password = hmac.compare_digest(password_hash(password, bytes.fromhex(auth['salt'])), bytes.fromhex(auth['hash']))
        except (ValueError, UnicodeError, OSError, KeyError, TypeError):
            return self.error(503, 'Вход временно недоступен.')
        finally:
            hash_slot.release()
        if not valid_username or not valid_password:
            return self.error(401, 'Неверный логин или пароль.')
        key, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with state_lock:
            attempts.pop(address, None)
            sessions.pop(self.session_key(), None)
            for current, item in list(sessions.items()):
                if item['expires'] <= now:
                    del sessions[current]
            if len(sessions) >= 128:
                sessions.pop(next(iter(sessions)))
            sessions[key] = {'csrf': csrf, 'username': auth['username'], 'expires': now + SESSION_AGE}
        return self.json(200, {'authenticated': True, 'csrf': csrf, 'username': auth['username']}, key)

    def forward(self, action, fields):
        try:
            outcome = worker_call(action, **fields)
        except (OSError, ValueError):
            return self.error(503, 'VPN сейчас недоступен для управления. Попробуй чуть позже.')
        return self.json(200 if outcome['ok'] else 400, outcome)


def serve_private(config):
    while True:
        try:
            server = ThreadingHTTPServer((str(config.vpn_bind_ipv4), config.listen_port), Handler)
        except OSError as error:
            if error.errno != errno.EADDRNOTAVAIL:
                raise
            time.sleep(2)
            continue
        server.config = config
        with server:
            server.serve_forever()
        return


def main():
    try:
        config = load_settings()
    except (OSError, ValueError) as error:
        raise SystemExit(f'Не удалось прочитать настройки веб-панели: {error}') from None
    if config.vpn_bind_ipv4 is not None:
        threading.Thread(target=serve_private, args=(config,), daemon=True).start()
    with ThreadingHTTPServer(('127.0.0.1', config.listen_port), Handler) as loopback:
        loopback.config = config
        loopback.serve_forever()


if __name__ == '__main__':
    main()
