# vpn-orchestrator

VPN-оркестратор принимает WireGuard- или AmneziaWG-клиентов на серверном интерфейсе и направляет их трафик через активный upstream VPN. Поддерживаются WireGuard, AmneziaWG и Xray в TUN-режиме. При отказе текущего upstream сервис переключается на доступный; при отказе всех VPN временно использует обычный выход сервера в интернет.

## Схема работы

```
[VPN-клиенты] → серверный WG/AWG-интерфейс → vpn-orchestrator
                                                   │
                         ┌─────────────────────────┴─────────────────────────┐
                         ▼                                                   ▼
              активный upstream VPN                              все VPN недоступны
              wgX / awgX / tunX                                  direct fallback через main
                         │                                                   │
                         └──────────────────────► интернет ◄─────────────────┘
```

Клиентский трафик из `server.subnet` использует отдельную policy-таблицу. Она ведёт на активный VPN либо, если все VPN недоступны, на обычный IPv4 default route из `main`. После восстановления VPN маршрут возвращается в туннель.

## Быстрый старт

Нужен Linux x86-64 (amd64), IPv4 и права для управления маршрутизацией/NAT. Для используемых протоколов установите `wg-quick`, `awg-quick` и/или `xray`; также нужны `ip`, `ping`, `nft` или `iptables`. Модули ядра WireGuard и AmneziaWG должны быть загружены, если используются соответствующие интерфейсы.

```bash
cargo build --release
sudo install -Dm755 target/release/vpn-orchestrator /usr/local/bin/vpn-orchestrator
sudo install -d /etc/vpn-orchestrator
sudo cp config.example.toml /etc/vpn-orchestrator/config.toml
sudo vpn-orchestrator -c /etc/vpn-orchestrator/config.toml
```

Перед первым запуском настройте серверный интерфейс и хотя бы один включённый `[[upstream]]`. Полный пример находится в [config.example.toml](config.example.toml).

## Документация

- [Конфигурация и маршрутизация](docs/configuration.md) — все секции TOML, `enabled = false`, NAT, таблицы и WG/Xray-конфиги.
- [Эксплуатация](docs/operations.md) — failover, прямой fallback, логи и диагностика.
- [Мониторинг и метрики](docs/monitoring.md) — ICMP/HTTPS/speed-пробы, selector, Prometheus и alerts.
- [Развёртывание](docs/deployment.md) — systemd.
- [Docker](docs/docker.md) — образ, подготовка хоста, тома, compose и особенности конфигурации.
- [Разработка](docs/development.md) — устройство кода, добавление протокола и проверки.

## Поддерживаемые upstream-протоколы

| Тип | Бинарник | Интерфейс |
| --- | --- | --- |
| `wireguard` | `wg-quick` | `wgX` |
| `amneziawg` | `awg-quick` | `awgX` |
| `xray` | `xray` | `tunX` |

Документация описывает IPv4. IPv6-подсети конфиг отклоняет.
