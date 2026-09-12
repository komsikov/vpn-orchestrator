# Разработка

## Структура

```
src/
├── main.rs            — CLI, запуск и graceful shutdown
├── config.rs          — TOML и валидация
├── server.rs          — серверный WG/AWG-интерфейс
├── routing.rs         — policy routing
├── nat.rs             — nftables/iptables
├── util.rs            — сетевые утилиты
├── monitor.rs         — пробы, selector и Prometheus
└── upstream/
    ├── mod.rs         — UpstreamManager и failover
    ├── wireguard.rs   — WireGuard и AmneziaWG
    └── xray.rs        — Xray TUN
```

## Добавление протокола

1. Создайте адаптер в `src/upstream/<type>.rs` с методами `start`, `stop`, `health_check`, `name`, `interface`, `health_check_interval` и `failover_threshold`.
2. Добавьте вариант в `UpstreamKind` и ветки dispatch в `src/upstream/mod.rs`.
3. Добавьте вариант в `UpstreamType` и его создание в `create_upstream`.
4. Добавьте проверку конфигурации и сценарные тесты для запуска, failover и очистки.

## Проверки

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --locked
python3 tests/regression.py
```

Сценарные тесты подменяют сетевые утилиты во временной директории и не меняют сеть хоста. Они покрывают failover, запуск без доступного VPN, отключённый NAT, переключение по скорости, откат ошибок маршрутизации и исключение отключённого upstream.
