"""Привилегированные операции панели управления VPN."""

import base64
import contextlib
from dataclasses import dataclass
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib
import unicodedata

from settings import load_settings


WG = 'wg'
WG_QUICK = 'wg-quick'
AWG = 'awg'
AWG_QUICK = 'awg-quick'
SYSTEMCTL = 'systemctl'
IP = 'ip'
PING = 'ping'
SERVICE = 'vpn-orchestrator.service'
LOCK = Path('/run/lock/vpn-admin.lock')
PROFILE_DIRS = {'wireguard': Path('/etc/wireguard'), 'amneziawg': Path('/etc/amnezia')}
MAX_REQUEST = 128 * 1024
MAX_PROFILE = 24 * 1024
PEER_HEADER = re.compile(r'(?im)^[ \t]*\[peer\][ \t]*(?:#.*)?$')
TABLE_HEADER = re.compile(r'(?m)^[ \t]*(\[\[[^\]\r\n]+\]\]|\[[^\]\r\n]+\])[ \t]*(?:#.*)?$')
INTERFACE_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_-]{0,14}')
AWG_NUMBERS = {'Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4'}
AWG_HEADERS = {f'H{i}' for i in range(1, 5)}
AWG_SIGNATURES = {f'I{i}' for i in range(1, 6)}
ENVIRONMENT = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}


class UserError(Exception):
    pass


@dataclass(frozen=True)
class Runtime:
    interface: str
    ingress: Path
    subnet: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    endpoint: str
    endpoint_host: str
    client_dns: tuple[str, ...]
    client_mtu: int
    orchestrator: Path
    orchestrator_text: str

    def device_number(self, address):
        first = self.subnet.network_address + (1 if self.subnet.prefixlen < 31 else 0)
        return int(address) - int(first) + (address < self.gateway)


def load_runtime():
    settings = load_settings()
    raw = settings.orchestrator_config.read_text(encoding='utf-8')
    try:
        server = tomllib.loads(raw)['server']
        interface = server['interface']
        server_type = server.get('type', server.get('server_type', 'wireguard'))
        subnet = ipaddress.IPv4Network(server['subnet'], strict=False)
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise UserError('Проверьте раздел [server] в конфигурации vpn-orchestrator.') from exc
    if server_type != 'wireguard':
        raise UserError('Панель поддерживает входящий интерфейс WireGuard.')
    if not isinstance(interface, str) or not INTERFACE_NAME.fullmatch(interface) or interface in {'all', 'interfaces'}:
        raise UserError('Укажите допустимое имя входящего интерфейса WireGuard.')
    path = server.get('config_path', str(PROFILE_DIRS['wireguard'] / f'{interface}.conf'))
    if not isinstance(path, str):
        raise UserError('Проверьте путь к входящему конфигу WireGuard.')
    ingress = Path(path)
    if not ingress.is_absolute() or ingress.name != f'{interface}.conf':
        raise UserError('Укажите абсолютный путь к входящему конфигу с именем интерфейса.')
    if not ingress.is_file() or ingress.is_symlink():
        raise UserError('Панели нужен обычный файл входящего конфига WireGuard.')
    interface_config, _ = read_device_config(ingress)
    values = re.findall(r'(?im)^[ \t]*Address[ \t]*=[ \t]*([^#\n]+)', interface_config)
    try:
        addresses = [ipaddress.ip_interface(item.strip()) for value in values for item in value.split(',')]
    except ValueError as exc:
        raise UserError('Проверьте поле Address во входящем конфиге WireGuard.') from exc
    gateways = {item.ip for item in addresses if item.version == 4 and item.ip in subnet}
    if len(gateways) != 1:
        raise UserError('Укажите один IPv4-адрес входящего интерфейса из подсети [server].subnet.')
    return Runtime(
        interface, ingress, subnet, gateways.pop(), settings.endpoint, settings.endpoint_host,
        settings.client_dns, settings.client_mtu, settings.orchestrator_config, raw,
    )


def command(arguments, *, body=None, timeout=8):
    try:
        return subprocess.run(
            arguments, input=body if body is not None else b'', capture_output=True,
            timeout=timeout, env=ENVIRONMENT, check=False,
        )
    except FileNotFoundError as exc:
        raise UserError(f'Установите системную утилиту {arguments[0]}.') from exc


def output(arguments, *, body=None, message, timeout=8):
    result = command(arguments, body=body, timeout=timeout)
    if result.returncode:
        raise UserError(message)
    return result.stdout


def string_field(request, field, limit=60):
    value = request.get(field)
    if not isinstance(value, str):
        raise UserError('Заполните обязательные поля.')
    value = value.strip()
    if not 1 <= len(value) <= limit or any(unicodedata.category(c).startswith('C') for c in value):
        raise UserError(f'Введите название длиной до {limit} символов.')
    return value


def read_device_config(path):
    raw = path.read_text(encoding='utf-8')
    headers = list(PEER_HEADER.finditer(raw))
    if not headers:
        return raw, []
    blocks = [raw[header.start():headers[i+1].start() if i+1 < len(headers) else len(raw)]
              for i, header in enumerate(headers)]
    return raw[:headers[0].start()], blocks


def peer_data(blocks, runtime):
    devices = []
    for block in blocks:
        allowed = re.search(r'(?im)^[ \t]*AllowedIPs[ \t]*=[ \t]*([^#\r\n]+)', block)
        public = re.search(r'(?im)^[ \t]*PublicKey[ \t]*=[ \t]*([^#\r\n]+)', block)
        title = re.search(r'(?m)^# Название: ([^\r\n]+)', block)
        if not allowed or not public:
            raise UserError('Один из профилей устройств во входящем конфиге не содержит адрес или ключ.')
        address = ipaddress.IPv4Interface(allowed.group(1).strip())
        if address.network.prefixlen != 32 or address.ip not in runtime.subnet or address.ip == runtime.gateway:
            raise UserError('Во входящем конфиге найден профиль с адресом за пределами подсети устройств.')
        devices.append({
            'id': str(address.ip), 'address': str(address),
            'name': title.group(1).strip() if title else f'Устройство {runtime.device_number(address.ip)}',
            'public_key': public.group(1).strip(),
        })
    if len({device['id'] for device in devices}) != len(devices):
        raise UserError('Во входящем конфиге обнаружены повторяющиеся адреса устройств.')
    return devices


def service_active():
    return command([SYSTEMCTL, 'is-active', '--quiet', SERVICE]).returncode == 0


def upstream_data(raw):
    try:
        parsed = tomllib.loads(raw)
        configs = parsed['upstream']
        table = parsed.get('routing', {}).get('route_table', 100)
        if type(table) is not int or not 0 < table <= 0xFFFFFFFF or table in {253, 254, 255}:
            raise ValueError
        if not isinstance(configs, list) or any(not isinstance(item, dict) for item in configs):
            raise ValueError
        if any(not all(isinstance(item.get(key), str) for key in ('name', 'interface', 'type')) for item in configs):
            raise ValueError
        return configs, table
    except (tomllib.TOMLDecodeError, KeyError, TypeError, ValueError) as exc:
        raise UserError('Не удалось прочитать конфигурацию vpn-orchestrator.') from exc


def active_interface(table):
    result = command([IP, '-j', '-4', 'route', 'show', 'table', str(table), 'default'])
    if result.returncode:
        return None
    routes = json.loads(result.stdout)
    return next((route.get('dev') for route in routes if route.get('dev')), None)


def state(_request, runtime):
    _, blocks = read_device_config(runtime.ingress)
    handshakes = command([WG, 'show', runtime.interface, 'latest-handshakes'])
    times = {}
    if handshakes.returncode == 0:
        for row in handshakes.stdout.decode('ascii').splitlines():
            public, when = row.split()
            times[public] = int(when)
    devices = []
    now = int(time.time())
    for device in peer_data(blocks, runtime):
        last = times.get(device.pop('public_key'), 0)
        devices.append({**device, 'active': 0 < last and now-last < 180, 'last_handshake': last})

    configs, table = upstream_data(runtime.orchestrator_text)
    active = active_interface(table)
    upstreams = [{
        'id': item['interface'], 'name': item['name'], 'kind': item['type'],
        'enabled': item.get('enabled', True), 'active': item['interface'] == active,
        'replaceable': managed_upstream_path(item) is not None,
        'toggleable': item['type'] in PROFILE_DIRS,
    } for item in configs]
    return {
        'devices': devices, 'upstreams': upstreams, 'endpoint': runtime.endpoint,
        'service_active': service_active(),
        'active_upstream': active if any(item['active'] for item in upstreams) else None,
    }


def atomic_write(path, data):
    fd, filename = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    temporary = Path(filename)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def update_devices(candidate, runtime):
    message = 'WireGuard отклонил изменение. Проверьте состояние входящего интерфейса.'
    previous = output([WG_QUICK, 'strip', str(runtime.ingress)], message=message)
    with tempfile.TemporaryDirectory(prefix='.vpn-admin-', dir=runtime.ingress.parent) as directory:
        temp = Path(directory) / runtime.ingress.name
        payload = candidate.encode('utf-8')
        atomic_write(temp, payload)
        stripped = output([WG_QUICK, 'strip', str(temp)], message=message)
        try:
            output([WG, 'syncconf', runtime.interface, '/dev/stdin'], body=stripped, message=message)
            os.replace(temp, runtime.ingress)
        except (UserError, OSError, subprocess.TimeoutExpired) as exc:
            output([WG, 'syncconf', runtime.interface, '/dev/stdin'], body=previous,
                   message='Не удалось восстановить список устройств в запущенном WireGuard.')
            raise UserError(message) from exc


def create_device(request, runtime):
    name = string_field(request, 'name')
    interface, blocks = read_device_config(runtime.ingress)
    used = {ipaddress.IPv4Address(device['id']) for device in peer_data(blocks, runtime)}
    address = next((ip for ip in runtime.subnet.hosts() if ip != runtime.gateway and ip not in used), None)
    if address is None:
        raise UserError('В подсети WireGuard больше нет свободных адресов.')
    message = 'Не удалось создать ключи WireGuard.'
    private = output([WG, 'genkey'], message=message).decode('ascii').strip()
    public = output([WG, 'pubkey'], body=(private+'\n').encode('ascii'), message=message).decode('ascii').strip()
    preshared = output([WG, 'genpsk'], message=message).decode('ascii').strip()
    server_public = output([WG, 'show', runtime.interface, 'public-key'], message=message).decode('ascii').strip()
    cidr = f'{address}/32'
    candidate = (interface+''.join(blocks)).rstrip()
    candidate += f'\n\n[Peer]\n# Название: {name}\nPublicKey = {public}\nPresharedKey = {preshared}\nAllowedIPs = {cidr}\n'
    update_devices(candidate, runtime)
    dns_line = f'DNS = {", ".join(runtime.client_dns)}\n' if runtime.client_dns else ''
    profile = (
        f'[Interface]\nPrivateKey = {private}\nAddress = {cidr}\n{dns_line}MTU = {runtime.client_mtu}\n\n'
        f'[Peer]\nPublicKey = {server_public}\nPresharedKey = {preshared}\nEndpoint = {runtime.endpoint}\n'
        'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n'
    )
    return {
        'device': {'id': str(address), 'address': cidr, 'name': name},
        'filename': f'vpn-{runtime.device_number(address):02d}.conf', 'config': profile,
    }


def revoke_device(request, runtime):
    interface, blocks = read_device_config(runtime.ingress)
    selected = request.get('id')
    for index, device in enumerate(peer_data(blocks, runtime)):
        if device['id'] == selected:
            del blocks[index]
            update_devices(interface+''.join(blocks), runtime)
            return {}
    raise UserError('Устройство уже удалено или не найдено.')


def valid_key(value):
    return re.fullmatch(r'[A-Za-z0-9+/]{43}=', value) and len(base64.b64decode(value, validate=True)) == 32


def profile_endpoint(value, runtime):
    host, separator, port = value.rpartition(':')
    if not separator or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise UserError('Укажите Endpoint с адресом и портом исходящего VPN.')
    host_key = host.lower().rstrip('.')
    if host.startswith('[') and host.endswith(']'):
        address = ipaddress.IPv6Address(host[1:-1])
    elif not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?', host):
        raise UserError('Проверьте адрес в Endpoint.')
    elif re.fullmatch(r'[0-9.]+', host_key):
        address = ipaddress.IPv4Address(host_key)
    else:
        address = None
    if address and (address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or getattr(address, 'scope_id', None)):
        raise UserError('Для Endpoint нужен доступный адрес VPN-сервера.')
    if host_key == runtime.endpoint_host or host_key == 'localhost':
        raise UserError('В качестве Endpoint укажите адрес исходящего VPN-сервера.')
    return value


def normalize_profile(raw, kind, interface, runtime):
    if not isinstance(raw, str) or len(raw.encode('utf-8')) > MAX_PROFILE:
        raise UserError('Вставьте конфигурацию VPN размером до 24 КБ.')
    data = {}
    section = None
    interface_keys = {'PrivateKey', 'Address', 'MTU', 'DNS', 'Table', 'ListenPort'}
    if kind == 'amneziawg':
        interface_keys |= AWG_NUMBERS | AWG_HEADERS | AWG_SIGNATURES
    peer_keys = {'PublicKey', 'PresharedKey', 'Endpoint', 'AllowedIPs', 'PersistentKeepalive'}
    for raw_line in raw.removeprefix('\ufeff').split('\n'):
        line = raw_line.partition('#')[0].strip()
        if not line:
            continue
        if line in ('[Interface]', '[Peer]'):
            if line in data or (line == '[Peer]' and '[Interface]' not in data):
                raise UserError('Для исходящего VPN нужен один раздел [Interface] и один [Peer].')
            section = line
            data[section] = {}
            continue
        key, separator, value = (part.strip() for part in line.partition('='))
        keys = interface_keys if section == '[Interface]' else peer_keys
        if section is None or not separator or key not in keys or key in data[section]:
            raise UserError('В конфиге VPN есть неизвестная, повторная или небезопасная директива.')
        if any(ord(character) < 32 or ord(character) > 126 for character in value):
            raise UserError('В параметрах VPN найдены недопустимые символы.')
        data[section][key] = value
    if set(data) != {'[Interface]', '[Peer]'}:
        raise UserError('Для исходящего VPN нужны разделы [Interface] и [Peer].')
    local, remote = data['[Interface]'], data['[Peer]']
    if not valid_key(local.get('PrivateKey', '')) or not valid_key(remote.get('PublicKey', '')):
        raise UserError('Проверьте PrivateKey и PublicKey в конфиге VPN.')
    if 'PresharedKey' in remote and not valid_key(remote['PresharedKey']):
        raise UserError('Проверьте PresharedKey в конфиге VPN.')
    addresses = [ipaddress.ip_interface(item.strip()) for item in local.get('Address', '').split(',') if item.strip()]
    addresses = [addr.ip for addr in addresses if addr.version == 4]
    if len(addresses) != 1:
        raise UserError('Укажите один IPv4-адрес в поле Address исходящего VPN.')
    address = addresses[0]
    live = json.loads(output([IP, '-j', '-4', 'addr', 'show'], message='Не удалось проверить адрес VPN.'))
    occupied = {addr['local'] for info in live if info['ifname'] != interface for addr in info.get('addr_info', [])}
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address in runtime.subnet or str(address) in occupied:
        raise UserError('Адрес исходящего VPN конфликтует с сетевыми адресами ВМ.')
    local['Address'] = f'{address}/32'
    local.pop('DNS', None)
    local.pop('ListenPort', None)
    local['Table'] = 'off'
    if 'MTU' in local and (not local['MTU'].isdigit() or not 576 <= int(local['MTU']) <= 1500):
        raise UserError('MTU должен быть числом от 576 до 1500.')
    routes = {ipaddress.ip_network(item.strip(), strict=False) for item in remote.get('AllowedIPs', '').split(',') if item.strip()}
    if ipaddress.IPv4Network('0.0.0.0/0') not in routes:
        raise UserError('Добавьте 0.0.0.0/0 в AllowedIPs исходящего VPN.')
    remote['AllowedIPs'] = '0.0.0.0/0'
    remote['Endpoint'] = profile_endpoint(remote.get('Endpoint', ''), runtime)
    keepalive = remote.get('PersistentKeepalive', '25')
    if keepalive.lower() == 'off':
        keepalive = '0'
    if not keepalive.isdigit() or not 0 <= int(keepalive) <= 65535:
        raise UserError('PersistentKeepalive должен быть числом от 0 до 65535.')
    remote['PersistentKeepalive'] = keepalive
    for key in local.keys() & AWG_NUMBERS:
        limit = 128 if key == 'Jc' else 1500
        if not re.fullmatch(r'[0-9]{1,4}', local[key]) or int(local[key]) > limit:
            raise UserError('Проверьте числовые параметры AmneziaWG.')
    for key in local.keys() & AWG_HEADERS:
        if not re.fullmatch(r'[0-9]{1,10}(?:\s*-\s*[0-9]{1,10})?', local[key]):
            raise UserError('Проверьте диапазоны заголовков AmneziaWG.')
    for key in local.keys() & AWG_SIGNATURES:
        if not local[key]:
            del local[key]
            continue
        if not re.fullmatch(r'(?:\s*<[A-Za-z0-9 _.,:+x=\-]{1,4096}>\s*)+', local[key]):
            raise UserError('Проверьте параметры сигнатур AmneziaWG.')
    return '\n\n'.join(section+'\n'+'\n'.join(f'{key} = {value}' for key, value in fields.items())
                       for section, fields in data.items())+'\n'


def managed_config_path(kind, interface):
    if kind not in PROFILE_DIRS or not INTERFACE_NAME.fullmatch(interface) or interface in {'all', 'interfaces'}:
        raise UserError('Этот VPN-конфиг управляется вне панели.')
    return PROFILE_DIRS[kind] / f'{interface}.conf'


def managed_upstream_path(item):
    try:
        path = managed_config_path(item['type'], item['interface'])
    except UserError:
        return None
    return path if item.get('config_path') == str(path) else None


def render_upstream(raw, configs, index, fields):
    lines = []
    for key, value in fields.items():
        if not re.fullmatch(r'[a-z_]+', key) or type(value) not in (str, bool, int):
            raise UserError('Этот VPN-конфиг использует параметры, недоступные для редактирования.')
        lines.append(f'{key} = {json.dumps(value, ensure_ascii=False)}')
    block = '[[upstream]]\n'+'\n'.join(lines)+'\n'
    if index is None:
        return raw.rstrip()+'\n\n'+block
    headers = list(TABLE_HEADER.finditer(raw))
    upstream_headers = [position for position, header in enumerate(headers) if header[1] == '[[upstream]]']
    if len(upstream_headers) != len(configs):
        raise UserError('Не удалось найти блок исходящего VPN в TOML.')
    position = upstream_headers[index]
    start = headers[position].start()
    end = headers[position+1].start() if position+1 < len(headers) else len(raw)
    if tomllib.loads(raw[start:end]).get('upstream') != [configs[index]]:
        raise UserError('Не удалось проверить блок исходящего VPN в TOML.')
    return raw[:start]+block+'\n'+raw[end:]


def available_interface(kind, configs, runtime):
    used = {runtime.interface, *(item['interface'] for item in configs)}
    prefix = 'awg' if kind == 'amneziawg' else 'wg'
    start = 0 if kind == 'amneziawg' else 1
    for number in range(start, 32):
        interface = f'{prefix}{number}'
        if interface not in used and not (Path('/sys/class/net') / interface).exists() and not managed_config_path(kind, interface).exists():
            return interface
    raise UserError('Не удалось подобрать свободное имя интерфейса для исходящего VPN.')


def wait_upstream(table, enabled, probe):
    deadline = time.monotonic()+13
    while time.monotonic() < deadline:
        if service_active() and active_interface(table) in enabled:
            if not probe:
                return
            ping = [PING, '-n', '-q', '-c', '1', '-W', '2', '-I', probe['interface'], probe.get('health_check_target', '1.1.1.1')]
            if command(ping, timeout=4).returncode == 0:
                if probe['type'] == 'xray':
                    return
                protocol = AWG if probe['type'] == 'amneziawg' else WG
                status = command([protocol, 'show', probe['interface'], 'latest-handshakes'], timeout=3)
                when = [int(row.split()[-1]) for row in status.stdout.splitlines() if row.split()]
                if status.returncode == 0 and any(value > time.time()-120 for value in when):
                    return
        time.sleep(0.5)
    raise UserError('Исходящий VPN не прошёл проверку связи.')


def apply_upstreams(runtime, candidate, *, path=None, profile=None, probe=None):
    configs, table = upstream_data(candidate)
    enabled = {item['interface'] for item in configs if item.get('enabled', True)}
    if not enabled:
        raise UserError('Оставьте включённым хотя бы один исходящий VPN.')
    previous_profile = path.read_bytes() if path is not None and path.exists() else None
    message = 'Не удалось перезапустить vpn-orchestrator.'
    modified = False
    try:
        output([SYSTEMCTL, 'stop', SERVICE], message=message, timeout=12)
        modified = True
        if path is not None:
            atomic_write(path, profile.encode('utf-8'))
        atomic_write(runtime.orchestrator, candidate.encode('utf-8'))
        output([SYSTEMCTL, 'start', SERVICE], message=message, timeout=12)
        wait_upstream(table, enabled, probe)
    except (UserError, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        try:
            if modified:
                try:
                    command([SYSTEMCTL, 'stop', SERVICE], timeout=12)
                except subprocess.TimeoutExpired:
                    pass
                atomic_write(runtime.orchestrator, runtime.orchestrator_text.encode('utf-8'))
                if path is not None:
                    if previous_profile is None:
                        path.unlink(missing_ok=True)
                    else:
                        atomic_write(path, previous_profile)
            output([SYSTEMCTL, 'start', SERVICE], message=message, timeout=12)
            if not service_active():
                raise UserError(message)
        except (UserError, OSError, subprocess.TimeoutExpired) as rollback_error:
            raise UserError('Не удалось вернуть прежнюю конфигурацию. Проверьте vpn-orchestrator через SSH.') from rollback_error
        raise UserError('Новый исходящий VPN не запустился. Прежняя конфигурация восстановлена.') from exc


def find_upstream(configs, interface):
    for index, item in enumerate(configs):
        if item['interface'] == interface:
            return index, item
    raise UserError('Исходящий VPN не найден.')


def set_upstream(request, runtime):
    name = string_field(request, 'name')
    kind = request.get('kind')
    if not isinstance(kind, str) or kind not in PROFILE_DIRS:
        raise UserError('Выберите WireGuard или AmneziaWG.')
    raw = runtime.orchestrator_text
    configs, _ = upstream_data(raw)
    requested_id = request.get('id')
    index, previous = find_upstream(configs, requested_id) if requested_id else (None, {})
    if any(item['name'] == name and i != index for i, item in enumerate(configs)):
        raise UserError('VPN с таким названием уже существует.')
    previous_path = None
    if previous:
        previous_path = managed_upstream_path(previous)
        if previous_path is None:
            raise UserError('Этот VPN-конфиг управляется вне панели.')
    interface = previous['interface'] if previous.get('type') == kind else available_interface(kind, configs, runtime)
    path = managed_config_path(kind, interface)
    profile = normalize_profile(request.get('config'), kind, interface, runtime)
    quick = AWG_QUICK if kind == 'amneziawg' else WG_QUICK
    with tempfile.TemporaryDirectory(prefix='.vpn-admin-', dir=path.parent) as directory:
        temp = Path(directory) / path.name
        atomic_write(temp, profile.encode('utf-8'))
        output([quick, 'strip', str(temp)], message='Утилита VPN не смогла прочитать конфигурацию.')
    fields = {
        'name': name, 'type': kind, 'interface': interface, 'config_path': str(path),
        'health_check_interval': 10, 'health_check_timeout': 3, 'failover_threshold': 3,
        'health_check_target': '1.1.1.1', **previous,
    }
    fields.update(name=name, type=kind, interface=interface, config_path=str(path))
    candidate = render_upstream(raw, configs, index, fields)
    apply_upstreams(runtime, candidate, path=path, profile=profile, probe=fields if fields.get('enabled', True) else None)
    if previous_path is not None and previous_path != path:
        shared = any(i != index and item.get('config_path') == str(previous_path) for i, item in enumerate(configs))
        if not shared:
            with contextlib.suppress(OSError):
                previous_path.unlink(missing_ok=True)
    return {}


def toggle_upstream(request, runtime):
    enabled = request.get('enabled')
    if type(enabled) is not bool:
        raise UserError('Укажите, включить или выключить исходящий VPN.')
    raw = runtime.orchestrator_text
    configs, _ = upstream_data(raw)
    index, existing = find_upstream(configs, request.get('id'))
    if existing['type'] not in PROFILE_DIRS:
        raise UserError('Этот тип исходящего VPN доступен только для просмотра.')
    if existing.get('enabled', True) == enabled:
        return {}
    fields = {**existing, 'enabled': enabled}
    candidate = render_upstream(raw, configs, index, fields)
    apply_upstreams(runtime, candidate, probe=fields if enabled else None)
    return {}


OPERATIONS = {
    'state': state, 'create_device': create_device, 'revoke_device': revoke_device,
    'set_upstream': set_upstream, 'toggle_upstream': toggle_upstream,
}


def main():
    try:
        raw = sys.stdin.buffer.readline(MAX_REQUEST+1)
        if len(raw) > MAX_REQUEST:
            raise UserError('Запрос превышает допустимый размер.')
        request = json.loads(raw)
        if not isinstance(request, dict) or not isinstance(request.get('action'), str) or request['action'] not in OPERATIONS:
            raise UserError('Неизвестная операция.')
        action = request['action']
        with LOCK.open('a') as lock:
            lock_type = fcntl.LOCK_SH if action == 'state' else fcntl.LOCK_EX
            try:
                fcntl.flock(lock, lock_type | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise UserError('Изменение VPN уже выполняется. Повторите запрос после завершения.') from exc
            result = OPERATIONS[action](request, load_runtime())
        answer = {'ok': True, **result}
    except UserError as exc:
        answer = {'ok': False, 'error': str(exc)}
    except (ValueError, TypeError, KeyError, UnicodeError):
        answer = {'ok': False, 'error': 'Проверьте формат указанных параметров и конфигурации VPN.'}
    except subprocess.TimeoutExpired:
        answer = {'ok': False, 'error': 'Сетевая команда не завершилась вовремя.'}
    except OSError:
        answer = {'ok': False, 'error': 'Не удалось прочитать или сохранить настройки VPN.'}
    print(json.dumps(answer, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    os.umask(0o077)
    main()
