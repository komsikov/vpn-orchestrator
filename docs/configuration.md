# Конфигурация и маршрутизация

Конфиг TOML читается при запуске. Изменение любого поля требует перезапуска процесса. Нужен хотя бы один `[[upstream]]` с `enabled = true`.

```toml
[server]
interface = "wg0"
type = "wireguard"
subnet = "10.42.42.0/24"
listen_port = 51820
# config_path = "/etc/wireguard/wg0.conf"

[[upstream]]
name = "primary-wg"
type = "wireguard"
interface = "wg1"
config_path = "/etc/wireguard/wg1.conf"
health_check_interval = 10
health_check_target = "8.8.8.8"
health_check_timeout = 3
failover_threshold = 3

[routing]
enable_ip_forward = true
route_table = 100
extra_prefixes = []

[nat]
masquerade = true
use_nftables = true
```

## `[server]`

| Поле | Default | Описание |
| --- | --- | --- |
| `interface` | — | Серверный интерфейс, принимающий клиентов. |
| `type` | `wireguard` | `wireguard` или `amneziawg`. Старое имя `server_type` принимается для совместимости. |
| `subnet` | — | IPv4 CIDR подсети клиентов. |
| `listen_port` | `51820` | Значение для логов. Реальный порт задаётся `ListenPort` в WG/AWG-конфиге либо внешним менеджером. |
| `config_path` | — | Путь к конфигу. Если интерфейс отсутствует, сервис поднимает его через `wg-quick`/`awg-quick`; иначе интерфейс должен быть поднят извне. |

Для WG/AWG базовое имя файла обязано совпадать с интерфейсом: `interface = "wg0"` требует путь, оканчивающийся на `wg0.conf`. `--skip-server` отключает только управление серверным интерфейсом; upstream-ы всё равно запускаются и проверяются.

## `[[upstream]]`

| Поле | Default | Описание |
| --- | --- | --- |
| `name` | — | Уникальное среди включённых upstream имя; используется в метке метрик `vpn`. |
| `type` | — | `wireguard`, `amneziawg` или `xray`. |
| `interface` | — | Имя создаваемого или внешнего интерфейса. |
| `enabled` | `true` | При `false` upstream не запускается, не проверяется, не получает таблицу проб и не попадает в метрики. Неизвестные поля upstream приводят к ошибке запуска. |
| `config_path` | — | Путь к конфигу. Если не задан, интерфейс считается внешне управляемым. |
| `health_check_interval` | `10` | Интервал проверки активного upstream в секундах. |
| `health_check_target` | `8.8.8.8` | IPv4-адрес для `ping` через интерфейс. |
| `health_check_timeout` | `3` | Таймаут `ping` в секундах. |
| `failover_threshold` | `3` | Число последовательных неудач до failover. |

Включённые upstream и сервер должны иметь разные имена интерфейсов. Для WireGuard и AmneziaWG имя файла `config_path` должно совпадать с интерфейсом. Для Xray нужен TUN inbound, имя которого совпадает с `interface`; SOCKS/HTTP-конфига недостаточно.

## `[routing]` и `[nat]`

| Поле | Default | Описание |
| --- | --- | --- |
| `routing.enable_ip_forward` | `true` | Включает `net.ipv4.ip_forward`. В Docker с host networking включите его на хосте и задайте `false`. |
| `routing.route_table` | `100` | Клиентская таблица. Следующие N таблиц используются для проб N включённых upstream. |
| `routing.extra_prefixes` | `[]` | Дополнительные IPv4-префиксы в клиентской таблице. |
| `nat.masquerade` | `true` | Создаёт NAT и FORWARD-правила. При `false` сервис их не меняет; обратную маршрутизацию настраивает администратор. |
| `nat.use_nftables` | `true` | Использовать nftables; `false` выбирает iptables. |

Нельзя использовать таблицы 0, 253–255 или диапазон, пересекающий их. `extra_prefixes` не добавляет новых источников к policy routing: ей подлежит только трафик из `server.subnet`.

Сервис использует правила с приоритетами 98–101: отдельные таблицы проб, выход IP серверного интерфейса через `main`, клиентская таблица и защитное `unreachable`-правило. Не используйте эти приоритеты для сторонних правил. При остановке таблицы и правила сервиса очищаются.

При fallback выбирается обычный IPv4 default route из `main` с наименьшей metric. Серверный и все перечисленные VPN-интерфейсы исключаются, включая отключённые. ECMP/nexthop default route не поддерживается.

## `[speed_test]`

```toml
[speed_test]
enabled = false
url = "https://speed.cloudflare.com/__down?bytes=10000000"
interval = 300
timeout = 30
min_mbps = 0.0
```

При включении сервис загружает файл через каждый upstream. `min_mbps = 0` оставляет только запись результатов в лог; положительное значение позволяет перейти на более быстрый здоровый upstream, если активный ниже порога. Пробы создают трафик и выполняются последовательно в фоновой задаче: health-check и failover не ждут завершения загрузки. Upstream, уже отмеченный мониторингом как `UNHEALTHY`, не тестируется. Для переключений по скорости также применяются `monitoring.selector.minimum_hold_secs`, `cooldown_secs`, `minimum_advantage` и `consecutive_wins`, даже если сам selector по ICMP выключен. По умолчанию нужны три последовательных выигрыша с преимуществом не менее 10%, удержание 180 секунд и cooldown 300 секунд. После любого успешного переключения оба механизма обновляют время удержания и сбрасывают кандидатов.

URL должен возвращать непосредственно бинарный файл размером не менее 100 000 байт с HTTP 200. Редиректы и текстовые ответы отвергаются. Замер характеризует одно HTTP-соединение до этого URL, а не общую пропускную способность VPN; диагностические поля описаны в [мониторинге](monitoring.md).

## Конфиги WireGuard и Xray

Для upstream WG/AWG используйте `Table = off`, иначе `wg-quick` может изменить default route хоста.

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.10.0.2/24
Table = off

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn-server.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Для Xray требуется [TUN inbound](https://xtls.github.io/en/config/inbounds/tun.html). Не включайте в Xray автоматическое перенаправление всего хостового трафика: системный default route должен оставаться доступен для туннелей и fallback.
