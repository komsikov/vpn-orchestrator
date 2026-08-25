//! Upstream-подключения: запуск, health-check, автоматический failover.
//!
//! Поддерживаемые типы:
//! - [`Wg`](UpstreamKind::Wg) — WireGuard (`wg-quick`) и AmneziaWG (`awg-quick`)
//! - [`Xray`](UpstreamKind::Xray) — через `xray run` (TUN-режим)
//!
//! ## Добавление нового протокола
//! 1. Создать структуру в `upstream/<type>.rs`
//! 2. Добавить вариант в [`UpstreamKind`]
//! 3. Добавить match-ветки в методы `UpstreamKind`
//! 4. Добавить тип в [`UpstreamType`] и в [`create_upstream`]

use std::time::Duration;

use anyhow::Result;

use tokio::time;
use tracing::{error, info, warn};

use crate::config::SpeedTestConfig;
use crate::config::{Config, UpstreamConfig, UpstreamType};
use crate::nat::NatSetup;
use crate::routing::RoutingSetup;

mod wireguard;
mod xray;

use wireguard::WgUpstream;
use xray::XrayUpstream;

/// Диспетчер upstream-подключений разных типов.
/// Добавить новый протокол:
///   1. Создать структуру в `upstream/<type>.rs`
///   2. Добавить вариант в enum `UpstreamKind`
///   3. Добавить match-ветки в методы ниже
///   4. Добавить тип в `create_upstream` и в `UpstreamType`
pub enum UpstreamKind {
    Wg(WgUpstream),
    Xray(XrayUpstream),
}

impl UpstreamKind {
    pub fn name(&self) -> &str {
        match self {
            Self::Wg(w) => w.name(),
            Self::Xray(x) => x.name(),
        }
    }

    pub fn interface(&self) -> &str {
        match self {
            Self::Wg(w) => w.interface(),
            Self::Xray(x) => x.interface(),
        }
    }

    pub fn health_check_interval(&self) -> Duration {
        match self {
            Self::Wg(w) => w.health_check_interval(),
            Self::Xray(x) => x.health_check_interval(),
        }
    }

    pub fn failover_threshold(&self) -> u32 {
        match self {
            Self::Wg(w) => w.failover_threshold(),
            Self::Xray(x) => x.failover_threshold(),
        }
    }

    pub async fn start(&self) -> Result<()> {
        match self {
            Self::Wg(w) => w.start().await,
            Self::Xray(x) => x.start().await,
        }
    }

    pub async fn stop(&self) -> Result<()> {
        match self {
            Self::Wg(w) => w.stop().await,
            Self::Xray(x) => x.stop().await,
        }
    }

    pub async fn health_check(&self) -> Result<()> {
        match self {
            Self::Wg(w) => w.health_check().await,
            Self::Xray(x) => x.health_check().await,
        }
    }
}

fn create_upstream(config: &UpstreamConfig) -> Result<UpstreamKind> {
    match config.upstream_type {
        UpstreamType::Wireguard => Ok(UpstreamKind::Wg(WgUpstream::new(config, "wg-quick")?)),
        UpstreamType::Amneziawg => Ok(UpstreamKind::Wg(WgUpstream::new(config, "awg-quick")?)),
        UpstreamType::Xray => Ok(UpstreamKind::Xray(XrayUpstream::new(config)?)),
    }
}

/// Менеджер upstream-подключений: запуск, health-check, автоматический failover.
///
/// Владеет всеми upstream-ами, routing и NAT. При падении активного upstream
/// переключается на следующий здоровый. Опционально замеряет скорость и
/// переключается на более быстрый.
pub struct UpstreamManager {
    upstreams: Vec<UpstreamKind>,
    active_index: Option<usize>,
    failure_count: u32,
    routing: Option<RoutingSetup>,
    nat: Option<NatSetup>,
    server_interface: String,
    server_subnet: String,
    use_nftables: bool,
    masquerade: bool,
    speed_test: SpeedTestConfig,
    failover_count: u32,
    active_since: Option<std::time::Instant>,
}

impl UpstreamManager {
    /// Запускает все upstream-ы, настраивает routing, выбирает первый здоровый.
    ///
    /// # Ошибки
    /// Возвращает ошибку, если нет здоровых upstream-ов при запуске.
    pub async fn start(config: &Config) -> Result<Self> {
        let upstreams: Vec<UpstreamKind> = config
            .upstream
            .iter()
            .filter(|u| u.enabled)
            .map(create_upstream)
            .collect::<Result<Vec<_>>>()?;

        // Запускаем все upstream-ы параллельно (каждый создаёт свой интерфейс).
        for upstream in &upstreams {
            if let Err(e) = upstream.start().await {
                warn!(upstream = upstream.name(), error = %e, "не удалось запустить upstream");
            }
        }

        // Policy routing (ip rule) — единожды.
        let routing = RoutingSetup::apply(config).await?;

        let mut manager = Self {
            upstreams,
            active_index: None,
            failure_count: 0,
            routing: Some(routing),
            nat: None,
            server_interface: config.server.interface.clone(),
            server_subnet: config.server.subnet.to_string(),
            use_nftables: config.nat.use_nftables,
            masquerade: config.nat.masquerade,
            speed_test: config.speed_test.clone(),
            failover_count: 0,
            active_since: None,
        };

        // Выбираем первый здоровый upstream.
        manager.select_initial().await?;

        Ok(manager)
    }

    async fn select_initial(&mut self) -> Result<()> {
        for (i, upstream) in self.upstreams.iter().enumerate() {
            match upstream.health_check().await {
                Ok(()) => {
                    self.activate(i).await?;
                    return Ok(());
                }
                Err(e) => {
                    warn!(upstream = upstream.name(), error = %e, "health check не прошёл");
                }
            }
        }
        anyhow::bail!("нет здоровых upstream при запуске");
    }

    /// Активирует upstream с индексом `index`: обновляет маршруты и NAT.
    async fn activate(&mut self, index: usize) -> Result<()> {
        let interface = self.upstreams[index].interface().to_string();
        let name = self.upstreams[index].name().to_string();

        if let Some(routing) = &self.routing {
            routing.set_default_route(&interface).await?;
        }

        let need_initial = self.nat.is_none();
        if need_initial {
            let nat = NatSetup::apply(
                &self.server_interface,
                &interface,
                &self.server_subnet,
                self.use_nftables,
                self.masquerade,
            )
            .await?;
            self.nat = Some(nat);
        } else if let Some(nat) = self.nat.as_mut() {
            nat.switch_interface(&interface).await?;
        }

        self.active_index = Some(index);
        self.failure_count = 0;
        self.active_since = Some(std::time::Instant::now());

        info!(upstream = %name, interface = %interface, "активный upstream");
        Ok(())
    }

    /// Замеряет скорость всех upstream-ов и опционально переключается на более быстрый.
    async fn run_speed_tests(&mut self) {
        info!("замер скорости upstream-ов");

        let mut results: Vec<(usize, f64)> = Vec::new();

        for (i, upstream) in self.upstreams.iter().enumerate() {
            let name = upstream.name();
            let interface = upstream.interface();

            match crate::util::speed_test(interface, &self.speed_test.url, self.speed_test.timeout)
                .await
            {
                Ok(mbps) => {
                    info!(
                        upstream = name,
                        interface = interface,
                        speed_mbps = format!("{:.2}", mbps),
                        "скорость upstream"
                    );
                    results.push((i, mbps));
                }
                Err(e) => {
                    warn!(upstream = name, error = %e, "не удалось замерить скорость");
                }
            }
        }

        // Failover по скорости: если активный upstream ниже порога и есть более быстрый.
        if self.speed_test.min_mbps > 0.0 {
            if let Some(active) = self.active_index {
                let active_speed = results.iter().find(|(i, _)| *i == active).map(|(_, s)| *s);

                if let Some(active_speed) = active_speed {
                    if active_speed < self.speed_test.min_mbps {
                        let best = results.iter().max_by(|a, b| {
                            a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal)
                        });

                        if let Some(&(best_i, best_speed)) = best {
                            if best_i != active && best_speed > active_speed {
                                let active_name = self.upstreams[active].name().to_string();
                                let best_name = self.upstreams[best_i].name().to_string();
                                info!(
                                    active = %active_name,
                                    active_speed_mbps = active_speed,
                                    better = %best_name,
                                    better_speed_mbps = best_speed,
                                    min_mbps = self.speed_test.min_mbps,
                                    "переключение на более быстрый upstream"
                                );
                                let _ = self.activate(best_i).await;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Главный цикл: health-check активного upstream, failover, speed test.
    ///
    /// Работает до тех пор, пока не будет прерван (SIGINT/SIGTERM).
    /// При отсутствии активного upstream — периодически пытается восстановить.
    pub async fn monitor_loop(&mut self) {
        let mut last_speed_test: Option<std::time::Instant> = None;

        loop {
            let (interval, threshold) = match self.active_index {
                Some(i) => (
                    self.upstreams[i].health_check_interval(),
                    self.upstreams[i].failover_threshold(),
                ),
                None => {
                    if self.try_recover().await.is_ok() {
                        continue;
                    }
                    time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };

            time::sleep(interval).await;

            // Периодический замер скорости всех upstream-ов.
            if self.speed_test.enabled {
                let due = last_speed_test
                    .map(|t| t.elapsed().as_secs() >= self.speed_test.interval)
                    .unwrap_or(true);
                if due {
                    self.run_speed_tests().await;
                    last_speed_test = Some(std::time::Instant::now());
                }
            }

            // active_index мог измениться после speed-test failover.
            let Some(active_index) = self.active_index else {
                continue;
            };
            match self.upstreams[active_index].health_check().await {
                Ok(()) => {
                    if self.failure_count > 0 {
                        info!("активный upstream восстановлен");
                    }
                    self.failure_count = 0;

                    let interface = self.upstreams[active_index].interface();
                    let name = self.upstreams[active_index].name();
                    let uptime = self
                        .active_since
                        .map(|t| t.elapsed().as_secs())
                        .unwrap_or(0);

                    let traffic = crate::util::interface_traffic(interface).ok();
                    let (rx, tx) = traffic.unwrap_or((0, 0));
                    info!(
                        upstream = name,
                        interface = interface,
                        rx_mb = format!("{:.1}", rx as f64 / 1_000_000.0),
                        tx_mb = format!("{:.1}", tx as f64 / 1_000_000.0),
                        uptime_secs = uptime,
                        "статистика upstream"
                    );
                }
                Err(e) => {
                    self.failure_count += 1;
                    warn!(
                        upstream = self.upstreams[active_index].name(),
                        error = %e,
                        failures = self.failure_count,
                        threshold,
                        "health check failed"
                    );
                    if self.failure_count >= threshold {
                        warn!(
                            upstream = self.upstreams[active_index].name(),
                            "достигнут порог failover"
                        );
                        self.failover().await;
                    }
                }
            }
        }
    }

    async fn failover(&mut self) {
        let old_index = self.active_index.unwrap();
        let uptime = self
            .active_since
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);

        self.failover_count += 1;

        match self.find_healthy_excluding(old_index).await {
            Some(i) => {
                let old_name = self.upstreams[old_index].name().to_string();
                let new_name = self.upstreams[i].name().to_string();
                info!(
                    from = %old_name,
                    to = %new_name,
                    uptime_secs = uptime,
                    failover_count = self.failover_count,
                    "переключение upstream"
                );
                if let Err(e) = self.activate(i).await {
                    error!(upstream = %new_name, error = %e, "ошибка активации");
                }
            }
            None => {
                error!(
                    upstream = self.upstreams[old_index].name(),
                    uptime_secs = uptime,
                    failover_count = self.failover_count,
                    "нет доступных upstream для переключения"
                );
                self.active_index = None;
                self.active_since = None;
            }
        }
    }

    async fn find_healthy_excluding(&self, exclude: usize) -> Option<usize> {
        for i in 0..self.upstreams.len() {
            if i == exclude {
                continue;
            }
            let upstream = &self.upstreams[i];

            if let Err(e) = upstream.start().await {
                warn!(upstream = upstream.name(), error = %e, "не удалось запустить");
                continue;
            }

            if let Err(e) = upstream.health_check().await {
                warn!(upstream = upstream.name(), error = %e, "health check failed");
                continue;
            }

            return Some(i);
        }
        None
    }

    async fn try_recover(&mut self) -> Result<()> {
        for (i, upstream) in self.upstreams.iter().enumerate() {
            if let Err(e) = upstream.start().await {
                warn!(upstream = upstream.name(), error = %e, "не удалось запустить");
                continue;
            }
            if upstream.health_check().await.is_ok() {
                self.activate(i).await?;
                return Ok(());
            }
        }
        anyhow::bail!("нет здоровых upstream")
    }

    /// Останавливает все upstream-ы, очищает NAT и routing.
    pub async fn shutdown(&mut self) {
        if let Some(nat) = self.nat.take() {
            if let Err(e) = nat.cleanup().await {
                error!(error = %e, "ошибка очистки NAT");
            }
        }
        if let Some(routing) = self.routing.take() {
            if let Err(e) = routing.cleanup().await {
                error!(error = %e, "ошибка очистки маршрутизации");
            }
        }
        for upstream in &self.upstreams {
            if let Err(e) = upstream.stop().await {
                warn!(upstream = upstream.name(), error = %e, "ошибка остановки");
            }
        }
    }
}
