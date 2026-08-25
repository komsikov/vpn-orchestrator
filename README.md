# vpn-orchestrator

VPN-оркестратор: принимает WireGuard-клиентов на **серверном** интерфейсе и маршрутизирует их трафик через **активный upstream VPN**. Upstream-ы — это клиентские подключения к удалённым VPN-серверам (WireGuard, AmneziaWG, Xray/3x-ui). При недоступности текущего upstream-а оркестратор автоматически переключается на следующий работающий.

## Схема работы

```
[WG-клиенты]
    │
    ▼
  wg0 (сервер)          ← принимает подключения, подсеть 10.42.42.0/24
    │
    ▼
  vpn-orchestrator      ← NAT + policy routing + health-check + failover
    │
    ▼
  активный upstream      ← wg1 / awg0 / tun0 (клиент к удалённому VPN-серверу)
    │
    ▼
  [удалённый VPN-сервер] → интернет
```

Клиенты подключаются к серверному интерфейсу `wg0`. Их трафик через policy routing (table 100) направляется на активный upstream-интерфейс, NAT маскарадит пакеты, и они уходят через туннель к удалённому VPN-серверу. Сами пакеты туннеля идут через основную таблицу маршрутизации — колец не возникает.

## Поддерживаемые upstream-протоколы

| Тип         | Бинарник     | Интерфейс | Описание                                |
|-------------|-------------|-----------|-----------------------------------------|
| `wireguard` | `wg-quick`  | `wgX`     | WireGuard                               |
| `amneziawg` | `awg-quick` | `awgX`    | AmneziaWG (обфусцированный WireGuard)   |
| `xray`      | `xray`      | `tunX`    | Xray / 3x-ui (VLESS/VMess/Trojan + TUN)  |

Каждый upstream — это клиентское подключение к VPN-серверу на другой машине. Оркестратор создаёт сетевой интерфейс (WG/AWG/TUN) и переключает маршрутизацию между ними.

## Установка

**Требования:**
- Linux с загруженным модулем ядра `wireguard` (на macOS собирается, но работает только на Linux)
- Для AmneziaWG: загруженный модуль ядра `amneziawg` (`awg-quick` без него не создаст интерфейс)
- Утилиты: `ip`, `ping`, `nft` (или `iptables`)
- Для upstream-ов: `wg-quick` и/или `awg-quick` и/или `xray` — в зависимости от используемых типов
- `curl` — для замера скорости (если включён `[speed_test]`)

```bash
cargo build --release
```

## Конфигурация

```bash
sudo mkdir -p /etc/vpn-orchestrator
sudo cp config.example.toml /etc/vpn-orchestrator/config.toml
```

### Пример конфига

```toml
[server]
interface = "wg0"
type = "wireguard"            # wireguard (по умолчанию) или amneziawg
subnet = "10.42.42.0/24"
listen_port = 51820
# config_path не указан — если интерфейс управляется внешне (wg-easy и т.д.)

# Несколько upstream в порядке приоритета.
# Каждый — клиент к удалённому VPN-серверу.

[[upstream]]
name = "primary-wg"
type = "wireguard"
interface = "wg1"
config_path = "/etc/wireguard/wg1.conf"
health_check_interval = 10       # секунды между проверками
health_check_target = "8.8.8.8"  # IP для ping через интерфейс
health_check_timeout = 3         # таймаут ping (секунды)
failover_threshold = 3           # неудач подряд до переключения

[[upstream]]
name = "backup-awg"
type = "amneziawg"
interface = "awg0"
config_path = "/etc/amnezia/backup.conf"
health_check_interval = 10
health_check_target = "1.1.1.1"
failover_threshold = 3

[[upstream]]
name = "backup-3xui"
type = "xray"
interface = "tun0"
config_path = "/etc/xray/config.json"
health_check_interval = 15
health_check_target = "1.1.1.1"
failover_threshold = 3

[routing]
enable_ip_forward = true
route_table = 100
extra_prefixes = []

[nat]
masquerade = true
use_nftables = true

[speed_test]
enabled = false
```

### Поля upstream

| Поле                    | Тип     | Default   | Описание                                                       |
|-------------------------|---------|-----------|----------------------------------------------------------------|
| `name`                  | string  | —         | Человекочитаемое имя                                           |
| `type`                 | enum    | —         | `wireguard` / `amneziawg` / `xray`                            |
| `interface`             | string  | —         | Имя сетевого интерфейса                                        |
| `enabled`              | bool    | `true`   | Включён ли upstream. Если false — игнорируется                 |
| `config_path`           | string? | —         | Путь к конфигу. Если не указан — интерфейс управляется внешне  |
| `health_check_interval` | u64     | `10`      | Секунды между проверками                                       |
| `health_check_target`   | string  | `8.8.8.8` | IP для ping через интерфейс                                     |
| `health_check_timeout`  | u64     | `3`       | Таймаут ping (секунды)                                         |
| `failover_threshold`    | u32     | `3`       | Неудач подряд до переключения                                  |

## Запуск

```bash
sudo ./target/release/vpn-orchestrator -c /etc/vpn-orchestrator/config.toml
```

### Параметры CLI

```
vpn-orchestrator [OPTIONS]

  -c, --config <CONFIG>              Путь к TOML-конфигу [default: /etc/vpn-orchestrator/config.toml]
      --monitor-interval <SECS>      Интервал мониторинга пиров сервера [default: 30]
      --skip-server                  Не вызывать wg-quick up/down для серверного интерфейса
      --log-file <PATH>              Путь к файлу логов (переопределяет [logging].file)
      --quiet                        Отключить логирование
```

## Логирование

По умолчанию логи выводятся в stdout. Уровень — `info` (переопределяется через `RUST_LOG`).

**Запись в файл** — через конфиг:

```toml
[logging]
enabled = true                                      # false или --quiet для отключения
file = "/var/log/vpn-orchestrator.log"              # писать в файл вместо stdout
level = "debug"                                      # trace / debug / info / warn / error
max_size_mb = 10                                     # ротация при превышении (0 = без лимита)
keep_mb = 1                                          # сколько МБ оставить при ротации
```

При превышении `max_size_mb` файл обрезается — сохраняются последние `keep_mb` мегабайт. Актуальные логи не теряются, файл всегда один.

Или через CLI:

```bash
sudo vpn-orchestrator --log-file /var/log/vpn-orchestrator.log
sudo vpn-orchestrator --quiet   # отключить логирование
```

CLI-флаг `--log-file` переопределяет `[logging].file` из конфига.

| Поле         | Тип     | Default | Описание                                            |
|--------------|---------|---------|-----------------------------------------------------|
| `enabled`    | bool    | `true`  | Включить/выключить логирование                      |
| `file`       | string? | —       | Путь к файлу логов. Если не указан — stdout        |
| `level`      | string? | `info`  | Уровень логирования (trace/debug/info/warn/error)  |
| `max_size_mb`| u64     | `0`     | Макс. размер файла в МБ (0 = без лимита)           |
| `keep_mb`    | u64     | `1`     | Сколько МБ оставить при ротации                     |

## Как работает failover

1. При запуске поднимаются **все** upstream-интерфейсы.
2. Первый прошедший health-check (ping через интерфейс) становится активным.
3. Маршрутизация и NAT настраиваются на активный интерфейс.
4. Периодически проверяется активный upstream.
5. После N (`failover_threshold`) неудач подряд — переключение на следующий здоровый upstream.
6. Переключение: `ip route flush table` + новый default route + пересоздание NAT-правил (миллисекунды).
7. Если все upstream-ы недоступны — оркестратор ждёт и периодически пытается восстановить подключение.
8. При восстановлении ранее упавшего upstream-а — он снова доступен для failover.
9. Xray: при падении процесса оркестратор перезапускает его автоматически при следующей попытке активации.

## Замер скорости

Периодически оркестратор замеряет скорость каждого upstream-интерфейса, загружая тестовый файл через `curl --interface <iface>`. Замер не мешает активному подключению — каждый интерфейс тестируется независимо, так как `curl --interface` привязывает сокет к конкретному устройству.

Результаты логируются с указанием upstream-а, интерфейса и скорости в Мбит/с.

Если задан `min_mbps > 0` и активный upstream опускается ниже порога, оркестратор переключается на самый быстрый из протестированных.

```toml
[speed_test]
enabled = true
url = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10 MB
interval = 300          # секунды между замерами
timeout = 30            # таймаут загрузки (секунды)
min_mbps = 5.0          # порог переключения (0 = только логирование)
```

| Поле       | Тип    | Default | Описание                                              |
|------------|--------|---------|-------------------------------------------------------|
| `enabled`  | bool   | `false` | Включить периодический замер                          |
| `url`      | string | Cloudflare speed test | URL тестового файла                  |
| `interval` | u64    | `300`   | Секунды между замерами                                |
| `timeout`  | u64    | `30`    | Таймаут загрузки (секунды)                            |
| `min_mbps` | f64    | `0.0`   | Порог переключения в Мбит/с (0 = только логирование) |

## Docker

Многоэтапная сборка: первый stage компилирует Rust-бинарник на Alpine, второй — минимальный Alpine со всеми upstream-инструментами (`wg-quick`, `awg-quick`, `xray`).

```bash
docker build -t vpn-orchestrator .
```

Контейнер управляет сетевыми интерфейсами хоста, поэтому требует `NET_ADMIN`, `SYS_ADMIN`, host-networking и доступ к `/dev/net/tun`.

**Важно:** с `--network host` Docker не разрешает менять sysctl (`net.ipv4.ip_forward`) и загружать модули ядра внутри контейнера. Эти операции нужно выполнить на хосте до запуска контейнера (см. [Подготовка хоста](#подготовка-хоста-для-docker) ниже), а в `config.toml` отключить соответствующие опции.

```bash
docker run -d \
  --name vpn-orchestrator \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add SYS_ADMIN \
  --device /dev/net/tun \
  -v /etc/vpn-orchestrator:/etc/vpn-orchestrator \
  -v /etc/wireguard:/etc/wireguard \
  -v /etc/amnezia:/etc/amnezia \
  -v /etc/xray:/etc/xray \
  donakan/vpn-orchestrator:1.0.0
```

> Монтируйте только те директории, которые используете (например, если нет Xray — уберите `-v /etc/xray`).

- `--network host` — доступ к интерфейсам хоста (wg0, wg1, awg0, tun0)
- `--cap-add NET_ADMIN` — `ip`, `nft`/`iptables`, `wg-quick`, `awg-quick`
- `--cap-add SYS_ADMIN` — запись в `/proc/sys/net/ipv4/ip_forward`
- `--device /dev/net/tun` — создание TUN-интерфейсов для Xray
- Тома: конфиг оркестратора, wg-конфиги, amnezia-конфиги и xray-конфиги монтируются с хоста

> Не используйте `--sysctl net.ipv4.ip_forward=1` — с `--network host` Docker выдаст ошибку. Настройте на хосте (см. ниже).

Образ включает `wg-quick`, `awg-quick` и `xray` — все три протокола доступны из коробки. В образе установлена заглушка `resolvconf` (`/bin/true`), чтобы `wg-quick`/`awg-quick` не падали при настройке DNS в контейнере.

### Подготовка хоста для Docker

С `--network host` контейнер использует ядро хоста напрямую. Docker запрещает менять sysctl и загружать модули ядра в host-network namespace, поэтому это нужно сделать на хосте до запуска контейнера:

**1. IP Forwarding**

Docker с `--network host` не разрешает `--sysctl`. Включите на хосте:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
# Для сохранения после перезагрузки:
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-vpn-orchestrator.conf
sudo sysctl --system
```

И отключите в конфиге, чтобы оркестратор не пытался писать в read-only `/proc/sys`:

```toml
[routing]
enable_ip_forward = false
```

**2. Модуль ядра AmneziaWG**

`awg-quick` требует модуль ядра `amneziawg`, который должен быть загружен на хосте:

```bash
sudo apt install amneziawg-dkms
sudo modprobe amneziawg
# Для автозагрузки после перезагрузки:
echo 'amneziawg' | sudo tee /etc/modules-load.d/amneziawg.conf
```

Без этого `awg-quick up` падает с ошибкой `Unknown device type. Protocol not supported`.

**3. Модуль ядра WireGuard**

На большинстве современных ядер WireGuard уже встроен. Если нет:

```bash
sudo modprobe wireguard
```

### docker-compose

```yaml
services:
  vpn-orchestrator:
    image: donakan/vpn-orchestrator:1.0.0
    # build: .  # если собираете локально
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    devices:
      - /dev/net/tun
    volumes:
      - ./config:/etc/vpn-orchestrator
      - ./wireguard:/etc/wireguard
      - ./amnezia:/etc/amnezia
      - ./xray:/etc/xray
    environment:
      - RUST_LOG=vpn_orchestrator=info
    restart: unless-stopped
```

> Не забудьте подготовить хост (см. выше): IP forwarding и модули ядра.

## systemd

```bash
sudo cp target/release/vpn-orchestrator /usr/local/bin/
```

Unit-файл `/etc/systemd/system/vpn-orchestrator.service`:

```ini
[Unit]
Description=VPN-оркестратор (wg0 -> upstream)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/vpn-orchestrator -c /etc/vpn-orchestrator/config.toml
Environment=RUST_LOG=vpn_orchestrator=info
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now vpn-orchestrator
sudo systemctl status vpn-orchestrator
```

## Структура проекта

```
src/
├── main.rs            — точка входа, CLI, оркестрация
├── config.rs          — парсинг и валидация TOML-конфига
├── server.rs          — серверный WireGuard-интерфейс (приём клиентов)
├── routing.rs         — policy routing (ip rule, ip route)
├── nat.rs             — NAT/FORWARD (nftables / iptables)
├── util.rs            — хелперы: ping, проверка интерфейса, замер скорости, ip_forward
└── upstream/
    ├── mod.rs         — enum dispatch + UpstreamManager (health-check, failover)
    ├── wireguard.rs   — адаптер WireGuard и AmneziaWG
    └── xray.rs        — адаптер Xray / 3x-ui
```

## Добавление нового протокола

1. Создать структуру в `src/upstream/<type>.rs` с методами `start()`, `stop()`, `health_check()`, `name()`, `interface()`, `health_check_interval()`, `failover_threshold()`.
2. Добавить вариант в `enum UpstreamKind` (`src/upstream/mod.rs`).
3. Добавить match-ветки во все методы `UpstreamKind`.
4. Добавить тип в `UpstreamType` (`src/config.rs`) и в `create_upstream`.

## Пример wg-конфигов

Пример конфигурации оркестратора: `config.example.toml`.

Примеры wg-конфигов не входят в репозиторий. Ниже — шаблоны:

**Серверный** (`/etc/wireguard/wg0.conf`):
```ini
[Interface]
Address = 10.42.42.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

[Peer]
# Клиент 1
PublicKey = <client-public-key>
AllowedIPs = 10.42.42.2/32
```

**Upstream-клиент** (`/etc/wireguard/wg1.conf`):
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

**Важно для upstream-конфигов:** используйте `Table = off`, чтобы `wg-quick` не перехватывал default route — маршрутизацией управляет оркестратор.

## Диагностика

```bash
# Логи
sudo journalctl -u vpn-orchestrator -f

# Активный upstream и маршруты
ip route show table 100
ip rule list

# NAT
sudo nft list table ip vpn_orchestrator_nat

# WireGuard
sudo wg show
ip link show wg0 wg1
```
