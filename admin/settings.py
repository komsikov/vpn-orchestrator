"""Настройки веб-панели и проверка формата общих параметров."""

from dataclasses import dataclass
import hashlib
import ipaddress
from pathlib import Path
import re
import tomllib


SETTINGS_PATH = Path('/etc/vpn-orchestrator-admin/config.toml')
AUTH_PATH = Path('/etc/vpn-orchestrator-admin/auth.json')
WORKER_SOCKET = '/run/vpn-admin-worker.sock'
HOST_LABEL = re.compile(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?')
PRIVATE_NETWORKS = tuple(map(ipaddress.IPv4Network, ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')))


@dataclass(frozen=True)
class Settings:
    endpoint: str
    endpoint_host: str
    listen_port: int
    vpn_bind_ipv4: ipaddress.IPv4Address | None
    vpn_client_network: ipaddress.IPv4Network | None
    client_dns: tuple[str, ...]
    client_mtu: int
    orchestrator_config: Path


def endpoint_parts(value):
    if not isinstance(value, str):
        raise ValueError('Укажите endpoint в формате имя-хоста:порт.')
    host, separator, raw_port = value.strip().rpartition(':')
    host = host.rstrip('.').lower()
    if not separator or not host or len(host) > 253 or not re.fullmatch(r'[0-9]{1,5}', raw_port):
        raise ValueError('Укажите endpoint в формате имя-хоста:порт.')
    port = int(raw_port)
    if not 1 <= port <= 65535 or not all(HOST_LABEL.fullmatch(label) for label in host.split('.')):
        raise ValueError('Endpoint должен содержать DNS-имя или IPv4 и допустимый порт.')
    if all(label.isascii() and label.isdecimal() for label in host.split('.')):
        host = str(ipaddress.IPv4Address(host))
    return f'{host}:{port}', host


def load_settings(path=SETTINGS_PATH):
    with path.open('rb') as source:
        data = tomllib.load(source)
    allowed = {'endpoint', 'listen_port', 'vpn_bind_ipv4', 'vpn_client_network',
               'client_dns', 'client_mtu', 'orchestrator_config'}
    if data.keys() - allowed:
        raise ValueError('В конфигурации веб-панели есть неизвестные параметры.')

    endpoint, host = endpoint_parts(data.get('endpoint'))
    listen_port = data.get('listen_port', 8787)
    if type(listen_port) is not int or not 1024 <= listen_port <= 65535:
        raise ValueError('listen_port должен быть целым числом от 1024 до 65535.')

    bind = data.get('vpn_bind_ipv4')
    network = data.get('vpn_client_network')
    if (bind is None) != (network is None):
        raise ValueError('Укажите vpn_bind_ipv4 и vpn_client_network вместе.')
    vpn_address = vpn_network = None
    if bind is not None:
        if not isinstance(bind, str) or not isinstance(network, str):
            raise ValueError('Укажите IPv4-адрес и подсеть VPN в виде строк.')
        vpn_address = ipaddress.IPv4Address(bind)
        vpn_network = ipaddress.IPv4Network(network)
        if not any(vpn_network.subnet_of(private) for private in PRIVATE_NETWORKS):
            raise ValueError('vpn_client_network должна быть частной IPv4-подсетью RFC 1918.')
        reserved = vpn_network.prefixlen < 31 and vpn_address in (vpn_network.network_address, vpn_network.broadcast_address)
        if vpn_address not in vpn_network or reserved:
            raise ValueError('vpn_bind_ipv4 должен быть адресом узла в vpn_client_network.')

    dns = data.get('client_dns', ['1.1.1.1', '1.0.0.1'])
    if not isinstance(dns, list) or len(dns) > 8 or any(not isinstance(value, str) for value in dns):
        raise ValueError('client_dns должен содержать до восьми IPv4-адресов.')
    client_dns = tuple(str(ipaddress.IPv4Address(value)) for value in dns)
    mtu = data.get('client_mtu', 1280)
    if type(mtu) is not int or not 576 <= mtu <= 9000:
        raise ValueError('client_mtu должен быть целым числом от 576 до 9000.')
    config = data.get('orchestrator_config', '/etc/vpn-orchestrator/config.toml')
    if not isinstance(config, str) or not Path(config).is_absolute():
        raise ValueError('orchestrator_config должен содержать абсолютный путь.')

    return Settings(endpoint, host, listen_port, vpn_address, vpn_network, client_dns, mtu, Path(config))


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=3,
                          dklen=32, maxmem=64 * 1024 * 1024)
