# Docker

Контейнер управляет сетевыми интерфейсами хоста (`wg0`, `wgX`, `awgX`, `tunX`), поэтому запускается с `--network host` и `--cap-add NET_ADMIN`. Образ — минимальный Alpine со всеми upstream-инструментами из коробки: `wg-quick`, `awg-quick` (собран из исходников), `xray`. Конфиги монтируются извне.

## Требования

- Linux x86-64 (amd64), IPv4
- host networking и `/dev/net/tun` (TUN нужен для Xray)
- `--cap-add NET_ADMIN` — управление интерфейсами, `ip`, `nft`/`iptables`, `wg-quick`, `awg-quick`
- Модули ядра загружаются на хосте, не в контейнере: `wireguard` (обычно встроен) и `amneziawg` — только при использовании AmneziaWG

## Подготовка хоста

С `--network host` Docker не разрешает менять sysctl и загружать модули ядра внутри контейнера. Выполните на хосте до запуска:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo modprobe wireguard
sudo modprobe amneziawg  # только при использовании AmneziaWG
# Для сохранения после перезагрузки:
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-vpn-orchestrator.conf
echo 'amneziawg' | sudo tee /etc/modules-load.d/amneziawg.conf
sudo sysctl --system
```

Без модуля `amneziawg` команда `awg-quick up` падает с ошибкой `Unknown device type. Protocol not supported`.

## Запуск

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
  donakan/vpn-orchestrator:1.1.0
```

- `--network host` — доступ к интерфейсам хоста.
- `--cap-add NET_ADMIN` — `ip`, `nft`/`iptables`, `wg-quick`, `awg-quick`.
- `--device /dev/net/tun` — создание TUN-интерфейсов для Xray.
- Монтируйте только каталоги используемых конфигов: нет Xray — уберите `-v /etc/xray`.

> Не используйте `--sysctl net.ipv4.ip_forward=1` — с `--network host` Docker выдаст ошибку. Настройте на хосте и задайте `enable_ip_forward = false` в конфиге.

## docker-compose

```yaml
services:
  vpn-orchestrator:
    image: donakan/vpn-orchestrator:1.1.0
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

## Тома

| Путь | Содержимое |
| --- | --- |
| `/etc/vpn-orchestrator` | `config.toml` оркестратора |
| `/etc/wireguard` | конфиги upstream `wireguard` (`wgX.conf`) и серверного интерфейса |
| `/etc/amnezia` | конфиги upstream `amneziawg` (`awgX.conf`) |
| `/etc/xray` | конфиги upstream `xray` (`config.json`) |

Upstream-конфиги в образ не входят. Для WG/AWG имя файла обязано совпадать с именем интерфейса из конфига оркестратора, и в конфиге upstream-а нужен `Table = off` (см. [Конфигурация](configuration.md)).

## Конфиг для Docker

Копируйте [config.example.toml](https://github.com/komsikov/vpn-orchestrator/blob/main/config.example.toml) с учётом:

- `enable_ip_forward = false` — forwarding включён на хосте, контейнер не должен писать в read-only `/proc/sys`.
- `[server].config_path` — без него оркестратор не поднимает серверный интерфейс: wg0 должен быть поднят извне (например, отдельным контейнером wg-easy), иначе сервис сообщит «интерфейс недоступен». Либо укажите `config_path = "/etc/wireguard/wg0.conf"` и смонтируйте конфиг.
- **Логи**: уберите из примера `file = "/var/log/vpn-orchestrator.log"` — иначе логи уйдут в файл внутри контейнера и пропадут при пересоздании, а `docker logs` останется пустым. По умолчанию логи идут в stdout.
- **DNS**: в образе установлена заглушка `resolvconf` (`exit 0`), чтобы `wg-quick`/`awg-quick` не падали при настройке DNS. Из-за неё строки `DNS` в WG/AWG-конфигах внутри контейнера применяться не будут — DNS настраивайте на хосте.
- Путь к конфигу можно переопределить аргументами (ENTRYPOINT — сам бинарник):

  ```bash
  docker run ... donakan/vpn-orchestrator:1.1.0 -c /etc/vpn-orchestrator/custom.toml
  ```

Полное описание секций конфига — [Конфигурация](configuration.md), failover и логи — [Эксплуатация](operations.md).

## Сборка из исходников

Многоэтапная сборка: компиляция Rust-бинарника на `rust:1-alpine`, рантайм — `alpine:3.24` с сетевыми утилитами и всеми VPN-инструментами.

```bash
docker build --platform linux/amd64 -t vpn-orchestrator .
```

Образ x86_64: Xray скачивается как статический бинарь `Xray-linux-64.zip`.
