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
- Linux x86-64 (amd64) с загруженным модулем ядра `wireguard` (на macOS собирается, но работает только на Linux)
- Для AmneziaWG: загруженный модуль ядра `amneziawg` (`awg-quick` без него не создаст интерфейс)
- Утилиты: `ip`, `ping`, `nft` (или `iptables`)
- Для upstream-ов: `wg-quick` и/или `awg-quick` и/или `xray` — в зависимости от используемых типов
- `curl` — для `[speed_test]`, HTTPS- и quality-проб в `[monitoring]`
- Поддерживается IPv4; IPv6-подсети в конфиге отклоняются

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
config_path = "/etc/amnezia/awg0.conf"
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

### Маршрутизация и NAT

| Поле | Default | Описание |
| --- | --- | --- |
| `routing.enable_ip_forward` | `true` | Включает `net.ipv4.ip_forward` при запуске. В контейнере с `--network host` включите его на хосте и задайте `false`. |
| `routing.route_table` | `100` | Таблица для клиентского трафика. Следующие таблицы используются для проб включённых upstream. Нельзя использовать 0, 253–255 или диапазон, который их затрагивает. |
| `routing.extra_prefixes` | `[]` | Дополнительные IPv4-префиксы в клиентской таблице. Они направляются в тот же активный выход. |
| `nat.masquerade` | `true` | Добавляет NAT и FORWARD-правила. При `false` оркестратор не меняет эти правила; обратная маршрутизация должна быть настроена отдельно. |
| `nat.use_nftables` | `true` | Использовать nftables. При `false` используются iptables. |

`extra_prefixes` не добавляет к policy routing новые источники: через таблицу оркестратора направляется только трафик из `server.subnet`.

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

При превышении `max_size_mb` файл обрезается тем же писателем: сохраняются целые последние строки в пределах `keep_mb` мегабайт. `keep_mb` должен быть меньше `max_size_mb`; `0` очищает файл полностью. Лимит проверяется перед записью и при сбросе буфера, поэтому временное превышение на размер записи возможно. Файл остаётся один. Ротация выполняется тем же фоновым писателем, без гонки между rename и записью. Очередь работает без намеренного сброса записей при переполнении; медленный диск может задерживать логирование. Ошибки записи выводятся отдельно в stderr (`log_write_failed`), восстановление — `log_write_restored`. При `SIGKILL`, аварии диска или питания сохранение буфера не гарантируется. Строка длиннее `keep_mb` целиком не помещается в сохраняемый хвост.

Используйте `keep_mb`; промежуточная настройка `max_files` больше не используется. `RUST_LOG`, если задан, переопределяет `[logging].level`.

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

1. При запуске поднимаются **все включённые** upstream-интерфейсы. Уже поднятые интерфейсы используются без повторного `up`.
2. Для привязанных к upstream проб настраиваются отдельные таблицы; первый прошедший health-check (ping через интерфейс) становится активным.
3. Маршрутизация и NAT настраиваются на активный интерфейс.
4. Периодически проверяется активный upstream.
5. После N (`failover_threshold`) неудач подряд — переключение на следующий здоровый upstream.
6. Переключение: `ip route replace` + смена NAT-правил. Ошибки команд передаются вызывающему коду; при ошибке NAT восстанавливаются старые правила и маршрут. При `masquerade = false` NAT/FORWARD не изменяются ни при старте, ни при failover.
7. Если все upstream-ы недоступны (в том числе при старте), оркестратор остаётся запущенным и повторяет восстановление. В клиентскую таблицу устанавливается обычный default route из `main` с его gateway и интерфейсом; NAT переключается на этот интерфейс. Клиенты получают прямой выход без VPN. После восстановления доступного VPN сервис возвращается на него. Если основного маршрута нет или настройка не удалась, сервис пишет явную ошибку и повторяет попытки.
8. При восстановлении ранее упавшего upstream-а — он снова доступен для failover.
9. Xray: при падении процесса оркестратор перезапускает его при восстановлении; в режиме мониторинга проверяет запуск перед очередным циклом проб.
10. При остановке удаляются правила оркестратора и опускаются только созданные им интерфейсы. Внешние интерфейсы остаются поднятыми. После остановки сервиса действует внешняя конфигурация firewall/routing.

## Замер скорости

Периодически оркестратор замеряет скорость каждого upstream-интерфейса, загружая тестовый файл через `curl --interface <iface>`. Сокет привязывается к конкретному устройству, а отдельная policy-таблица направляет пробу через него даже при `Table = off`. Пробы используют IPv4, игнорируют proxy-переменные окружения и пользовательский `.curlrc`. Загрузка создаёт нагрузку на канал; проверки выполняются последовательно, поэтому длительные пробы могут задерживать следующий health-check.

Результаты логируются с указанием upstream-а, интерфейса и скорости в Мбит/с.

Если задан `min_mbps > 0` и успешно измеренная скорость активного upstream ниже порога, оркестратор переключается на более быстрый из успешно протестированных после health-check. Ошибка загрузки не считается измерением скорости; недоступность обрабатывает обычный failover.

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

## Расширенный мониторинг

`[monitoring]` включает multi-target ICMP, HTTPS-пробы, EWMA и метрики. Обычный failover продолжает работать независимо от `selector.enabled`. Selector дополнительно предлагает переключения по оценке качества, с проверкой кандидата и откатом при неудачной проверке после переключения.

```toml
[monitoring]
enabled = true
health_targets = ["1.1.1.1", "8.8.8.8"]
health_interval = 15
health_timeout = 2
health_probe_count = 5
https_enabled = true
https_targets = ["https://1.1.1.1"]
https_interval = 60
https_timeout = 10
ewma_alpha = 0.2
history_size = 1000
quality_enabled = false
quality_url = "https://speed.cloudflare.com/__down?bytes=5000000"
quality_interval = 300
quality_timeout = 30
prometheus_enabled = false
prometheus_port = 9099

[monitoring.selector]
enabled = false
minimum_advantage = 0.10
consecutive_wins = 3
minimum_hold_secs = 180
cooldown_secs = 300

[monitoring.scoring]
availability_weight = 0.35
latency_weight = 0.25
loss_weight = 0.15
jitter_weight = 0.15
http_weight = 0.10
latency_max_ms = 500.0
jitter_max_ms = 20.0
healthy_threshold = 75.0
degraded_threshold = 40.0
fast_weight = 0.90
historical_weight = 0.10
```

Здесь перечислены значения по умолчанию, кроме `monitoring.enabled` (по умолчанию `false`). Интервалы и таймауты указаны в секундах, `minimum_advantage` — доля (0.10 = 10%). `consecutive_wins` — число последовательных побед кандидата. При полном отказе всех ICMP-целей состояние становится `UNHEALTHY` независимо от сглаженного score. Emergency failover не ждёт cooldown.

`quality_enabled` измеряет скорость для диагностики. Если одновременно включён `[speed_test]`, его замер используется мониторингом и отдельная quality-загрузка пропускается. Метрика скорости доступна, только когда включён `[monitoring]`. Для переключения по скорости используется `[speed_test].min_mbps`. Интервалы задают минимальные паузы между циклами: фактическая частота также зависит от длительности проб.

При `monitoring.enabled = true` и `prometheus_enabled = true` метрики доступны по `http://<host>:9099/metrics` на всех IPv4-интерфейсах. Доступ регулируется внешним firewall. Отключённые upstream в метрики не попадают. Имена включённых upstream должны быть уникальны — это метка `vpn`.

| Метрика | Смысл и применение |
| --- | --- |
| `vpn_up{vpn}` | 1, если хотя бы одна ICMP-цель ответила в последнем цикле; 0, если ни одна. Не зависит от score. До первой пробы отсутствует. Это доступность ICMP, не гарантия работы всех сайтов. |
| `vpn_selected{vpn}` | Какой upstream сейчас используется для клиентов. При прямом выходе все значения 0. |
| `vpn_direct_fallback` | 1, если клиентам настроен выход через основной интерфейс без VPN. Это состояние маршрутизации, не проверка доступности интернета у провайдера. |
| `vpn_probe_age_seconds{vpn}` | Возраст последнего завершённого ICMP-цикла. Позволяет обнаружить зависшие или чрезмерно долгие проверки; возраст растёт и между публикациями snapshot. |
| `vpn_latency_ms{vpn}` | EWMA среднего RTT **всех ответов** каждой пробы, для диагностики задержек. RTT и его разброс не экспортируются при полном отказе последнего цикла. |
| `vpn_rtt_stddev_ms{vpn}` | Сглаженный `mdev` ping — разброс RTT внутри пробы. Это не измерение IP packet delay variation. |
| `vpn_packet_loss_ratio{vpn}` | EWMA потерь в долях 0–1. Например, 0.25 означает 25% потерь. |
| `vpn_http_success_ratio{vpn}` | Доля успешных HTTPS-проб за последние 5 минут; отсутствует без измерений. Помогает отличить доступность ICMP от HTTP/TLS. |
| `vpn_download_mbps{vpn}` | Последняя измеренная скорость тестовой загрузки; при неудачном замере значение снимается. Используется существующая speed/quality-проба, дополнительного трафика ради метрики нет. |
| `vpn_score{vpn}` | Нормированная оценка 0–100 для объяснения решений selector. Экспортируется только при включённом selector; не является вероятностью доступности. При полном отказе текущего ICMP-цикла равна 0. |

Убраны `vpn_latency_p95_ms` (считался по последним ping, поэтому вводил в заблуждение), `vpn_availability_5m` (доля успешных target-проб ошибочно называлась uptime) и `vpn_consecutive_failures` (считал цели, а не последовательные циклы). `vpn_jitter_ms` переименован в `vpn_rtt_stddev_ms`, `vpn_quality_mbps` — в `vpn_download_mbps`. При обновлении скорректируйте dashboards/alerts, особенно единицу `vpn_packet_loss_ratio`: раньше это были проценты.

Полезные условия для alert: `vpn_direct_fallback == 1` — интернет без VPN; `max(vpn_up) == 0` — ни один проверенный VPN не отвечает; `sum(vpn_selected) == 0 and vpn_direct_fallback == 0` — клиентский выход не настроен. Проверяйте также возраст проб: старые измерения не доказывают текущую доступность.

### Сообщения об отказах

- `vpn_unavailable` (ERROR): ни один включённый VPN нельзя использовать. Пишется при переходе в отказ, включая запуск без VPN.
- `direct_fallback_enabled` (WARN): маршрут и NAT переключены на обычный интерфейс; указаны interface/gateway, VPN не используется.
- `direct_fallback_failed` (ERROR): не удалось настроить даже прямой выход; причина включена в сообщение.
- `vpn_still_unavailable` (WARN, раз в минуту): отказ продолжается; показано, включён ли прямой выход, и интервал восстановления.
- `vpn_restored` (INFO): VPN снова доступен, прямой выход отключён; указана длительность отказа.
- `https_probe_failed` / `https_probe_restored`: изменение доступности HTTPS, отдельно от ICMP.

Отдельные повторяющиеся ошибки target-проб доступны на уровне debug. `RUST_LOG=error` намеренно скрывает WARN/INFO, поэтому для полной картины используйте info. `--quiet` или `logging.enabled=false` отключают логи.

## Таблицы маршрутизации и имена интерфейсов

Оркестратор резервирует `routing.route_table` для клиентов и следующие N таблиц для проб N включённых upstream в порядке конфигурации. Например, для двух upstream при `route_table = 100` используются таблицы 100–102. Эти таблицы должны быть свободны от сторонних маршрутов; при остановке они очищаются. ID 0, 253–255 и диапазоны, включающие их, отклоняются.

Правила: priority 98 — локальные сокеты, привязанные к upstream; 99 — исходный IP серверного интерфейса через `main`; 100 — источники из `server.subnet` через VPN-таблицу; 101 — `unreachable` для той же подсети, если не настроен ни VPN, ни прямой fallback-маршрут. При полном отказе VPN сервис копирует обычный default route из main в клиентскую таблицу, сохраняя gateway; среди обычных маршрутов выбирается минимальная metric, серверный и все перечисленные VPN-интерфейсы (включая enabled=false) исключаются: отключённый VPN не может незаметно стать прямым выходом. ECMP/nexthop-маршруты этим простым fallback не поддерживаются. Не занимайте эти приоритеты конфликтующими правилами. `extra_prefixes` добавляет маршруты внутри клиентской таблицы; источники вне `server.subnet` этим полем не подключаются.

Для управляемых WG/AWG имя файла должно совпадать с интерфейсом: `interface = "awg0"` требует `config_path = "/etc/amnezia/awg0.conf"`. Так имя интерфейса определяют [wg-quick](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8) и awg-quick. Несовпадение отклоняется до изменения сети. Отключённые upstream не запускаются, не проверяются, не попадают в метрики и не занимают таблицы. Конфиг читается при запуске: изменение enabled требует перезапуска сервиса. При этом TOML и обязательные поля записей всё равно должны корректно разбираться. Сервер и включённые upstream должны иметь разные имена интерфейсов.

Серверный `listen_port` используется для логирования; фактический порт задаётся `ListenPort` в WG/AWG-конфиге либо внешним менеджером. NAT/FORWARD-правила не отменяют DROP-правила других firewall-цепочек; разрешения в firewall хоста настраиваются отдельно.

## Docker

Многоэтапная сборка: первый stage компилирует Rust-бинарник на Alpine, второй — минимальный Alpine со всеми upstream-инструментами (`wg-quick`, `awg-quick`, `xray`).

```bash
docker build --platform linux/amd64 -t vpn-orchestrator .
```

Контейнер управляет сетевыми интерфейсами хоста, поэтому требует `NET_ADMIN`, host-networking и доступ к `/dev/net/tun`.

**Важно:** с `--network host` Docker не разрешает менять sysctl (`net.ipv4.ip_forward`) и загружать модули ядра внутри контейнера. Эти операции нужно выполнить на хосте до запуска контейнера (см. [Подготовка хоста](#подготовка-хоста-для-docker) ниже), а в `config.toml` отключить соответствующие опции.

```bash
docker run -d \
  --name vpn-orchestrator \
  --network host \
  --cap-add NET_ADMIN \
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
- `--device /dev/net/tun` — создание TUN-интерфейсов для Xray
- Тома: конфиг оркестратора, wg-конфиги, amnezia-конфиги и xray-конфиги монтируются с хоста

> Не используйте `--sysctl net.ipv4.ip_forward=1` — с `--network host` Docker выдаст ошибку. Настройте на хосте (см. ниже).

Образ включает `wg-quick`, `awg-quick` и `xray` — все три протокола доступны из коробки. В образе установлена заглушка `resolvconf` (скрипт с `exit 0`), чтобы `wg-quick`/`awg-quick` не падали при настройке DNS в контейнере.

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
├── util.rs            — ping, проверка интерфейса, ip_forward
├── monitor.rs         — ICMP/HTTPS/speed probes, scoring, selector, Prometheus
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

Для Xray требуется конфиг с [TUN inbound](https://xtls.github.io/en/config/inbounds/tun.html), имя которого совпадает с `upstream.interface`. SOCKS/HTTP-конфига из 3x-ui недостаточно. Системный default route должен оставаться под управлением оркестратора; не включайте в Xray автоматическое перенаправление всего хостового трафика.

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

## Проверка изменений

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --locked
python3 tests/regression.py
```

Сценарные тесты требуют Python 3 и подменяют сетевые утилиты во временной директории: сеть хоста не меняется. Они проверяют failover, восстановление после старта без VPN, отключённый NAT, переключение по скорости, ошибки настройки маршрутов и откат NAT.
