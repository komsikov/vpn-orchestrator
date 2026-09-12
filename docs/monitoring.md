# Мониторинг и метрики

`[monitoring]` добавляет multi-target ICMP, HTTPS-пробы, EWMA, selector и Prometheus. Обычный failover работает независимо от `monitoring.selector.enabled`.

```toml
[monitoring]
enabled = true
health_targets = ["1.1.1.1", "8.8.8.8"]
health_interval = 15
health_timeout = 2
health_probe_count = 5
https_enabled = true
https_targets = [
  "https://www.youtube.com/generate_204",
  "https://chatgpt.com/",
  "https://www.instagram.com/",
  "https://web.telegram.org/",
]
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

`monitoring.enabled` по умолчанию `false`. Интервалы и таймауты выражены в секундах. `minimum_advantage` — доля, поэтому `0.10` означает 10%. При полном отказе ICMP-целей состояние `UNHEALTHY` независимо от сглаженного score. Emergency failover не ждёт cooldown.

HTTPS-пробы запускаются параллельно в фоновой задаче. Они не задерживают ICMP health-check и обычный failover; следующий HTTPS-цикл начинается только после завершения предыдущего. В debug-логе отказ содержит причину curl: таймаут, ошибку соединения/TLS либо HTTP-код.

Проба делает HTTP `HEAD` и подтверждает достижимость URL: ответы HTTP 2xx–4xx считаются успешными, поскольку 401/403 часто требуют авторизации или браузерной сессии и сами по себе не означают отказ VPN. HTTP 5xx и ошибки curl считаются отказом.

`quality_enabled` даёт диагностическую загрузочную пробу. Если включён `[speed_test]`, мониторинг использует его измерение и не запускает отдельную quality-загрузку. Загрузочные пробы выполняются последовательно, но также в фоновой задаче.

## Prometheus

При `monitoring.enabled = true` и `prometheus_enabled = true` endpoint доступен на `http://<host>:9099/metrics` на всех IPv4-интерфейсах. Ограничьте доступ внешним firewall. Отключённые upstream в метрики не попадают.

| Метрика | Значение |
| --- | --- |
| `vpn_up{vpn}` | 1, если хотя бы одна ICMP-цель ответила в последнем цикле; 0, если ни одна. До первой пробы отсутствует. |
| `vpn_selected{vpn}` | 1 для активного клиентского VPN; при direct fallback все значения 0. |
| `vpn_direct_fallback` | 1, если клиентский маршрут использует основной интерфейс без VPN. |
| `vpn_probe_age_seconds{vpn}` | Возраст последнего завершённого ICMP-цикла. |
| `vpn_latency_ms{vpn}` | EWMA среднего RTT всех ответов текущих проб. При полном отказе последнего цикла отсутствует. |
| `vpn_rtt_stddev_ms{vpn}` | EWMA `mdev` ping, то есть разброс RTT внутри пробы. |
| `vpn_packet_loss_ratio{vpn}` | EWMA потерь в долях 0–1. |
| `vpn_http_success_ratio{vpn}` | Доля успешных HTTPS-проб за последние пять минут. |
| `vpn_download_mbps{vpn}` | Последняя успешная настроенная загрузочная проба. |
| `vpn_score{vpn}` | Оценка selector 0–100; экспортируется только при включённом selector. |

Практические условия alert: `vpn_direct_fallback == 1` показывает выход без VPN; `max(vpn_up) == 0` — отсутствие ответов от всех проверенных VPN; `sum(vpn_selected) == 0 and vpn_direct_fallback == 0` — клиентский выход не настроен. Учитывайте `vpn_probe_age_seconds`: старые измерения не говорят о текущем состоянии.

Удалённые метрики при обновлении: `vpn_latency_p95_ms`, `vpn_availability_5m`, `vpn_consecutive_failures`. `vpn_jitter_ms` переименована в `vpn_rtt_stddev_ms`, `vpn_quality_mbps` — в `vpn_download_mbps`; `vpn_packet_loss_ratio` теперь доля, а не проценты.
