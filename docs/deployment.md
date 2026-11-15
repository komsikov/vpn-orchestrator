# Развёртывание

## Docker

Деплой в Docker — отдельная документация: [docs/docker.md](docker.md). Включает подготовку хоста, запуск, docker-compose, тома и особенности конфигурации в контейнере.

## systemd

```bash
sudo install -Dm755 target/release/vpn-orchestrator /usr/local/bin/vpn-orchestrator
```

Создайте `/etc/systemd/system/vpn-orchestrator.service`:

```ini
[Unit]
Description=VPN orchestrator
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
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-orchestrator
sudo systemctl status vpn-orchestrator
```

## Веб-панель

Для управления профилями устройств и исходящими туннелями установите панель отдельной службой systemd. Подготовка входящего WireGuard-интерфейса, настройка учётной записи и подключение через SSH описаны в руководстве. [Установка веб-панели](admin.md)
