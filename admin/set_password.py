import argparse
import getpass
import grp
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile

from settings import AUTH_PATH, password_hash


USERNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')


def main():
    parser = argparse.ArgumentParser(description='Задать пароль администратора VPN-панели.')
    parser.add_argument('username', nargs='?', default='admin', help='имя администратора')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('запустите команду от root')
    if not USERNAME.fullmatch(args.username):
        parser.error('имя должно содержать от 1 до 64 латинских букв, цифр, точек, дефисов или подчёркиваний')
    if not sys.stdin.isatty():
        parser.error('откройте интерактивный терминал, чтобы ввести пароль')

    password = getpass.getpass('Новый пароль: ')
    if not 16 <= len(password) <= 256:
        parser.error('пароль должен содержать от 16 до 256 символов')
    if password != getpass.getpass('Повторите пароль: '):
        parser.error('пароли не совпали')

    salt = secrets.token_bytes(16)
    content = {'username': args.username, 'salt': salt.hex(), 'hash': password_hash(password, salt).hex()}
    group = grp.getgrnam('vpn-admin').gr_gid
    fd, name = tempfile.mkstemp(prefix='.auth-', dir=AUTH_PATH.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            os.fchown(output.fileno(), 0, group)
            os.fchmod(output.fileno(), 0o640)
            json.dump(content, output)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, AUTH_PATH)
    finally:
        temporary.unlink(missing_ok=True)
    print('Пароль задан. Если панель запущена, перезапустите её, чтобы завершить текущие сеансы.')


if __name__ == '__main__':
    main()
