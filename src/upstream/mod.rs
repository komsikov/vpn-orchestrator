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

use crate::config::{Config, UpstreamConfig, UpstreamType};
use crate::monitor::{self, Monitor, SharedMetrics, SwitchDecision, SwitchReason};
use crate::nat::NatSetup;
use crate::routing::RoutingSetup;

mod wireguard;
mod xray;

use wireguard::WgUpstream;
use xray::XrayUpstream;

pub enum UpstreamKind {
    Wg(WgUpstream),
    Xray(XrayUpstream),
}

impl UpstreamKind {
    pub fn name(&self) -> &str {
        match self { Self::Wg(w) => w.name(), Self::Xray(x) => x.name() }
    }
    pub fn interface(&self) -> &str {
        match self { Self::Wg(w) => w.interface(), Self::Xray(x) => x.interface() }
    }
    pub fn health_check_interval(&self) -> Duration {
        match self { Self::Wg(w) => w.health_check_interval(), Self::Xray(x) => x.health_check_interval() }
    }
    pub fn failover_threshold(&self) -> u32 {
        match self { Self::Wg(w) => w.failover_threshold(), Self::Xray(x) => x.failover_threshold() }
    }
    pub async fn start(&self) -> Result<()> {
        match self { Self::Wg(w) => w.start().await, Self::Xray(x) => x.start().await }
    }
    pub async fn stop(&self) -> Result<()> {
        match self { Self::Wg(w) => w.stop().await, Self::Xray(x) => x.stop().await }
    }
    pub async fn health_check(&self) -> Result<()> {
        match self { Self::Wg(w) => w.health_check().await, Self::Xray(x) => x.health_check().await }
    }
}

fn create_upstream(config: &UpstreamConfig) -> Result<UpstreamKind> {
    match config.upstream_type {
        UpstreamType::Wireguard => Ok(UpstreamKind::Wg(WgUpstream::new(config, "wg-quick")?)),
        UpstreamType::Amneziawg => Ok(UpstreamKind::Wg(WgUpstream::new(config, "awg-quick")?)),
        UpstreamType::Xray => Ok(UpstreamKind::Xray(XrayUpstream::new(config)?)),
    }
}

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
    active_since: Option<std::time::Instant>,
    monitor: Option<Monitor>,
    shared_metrics: SharedMetrics,
}

impl UpstreamManager {
    pub async fn start(config: &Config) -> Result<Self> {
        let upstreams: Vec<UpstreamKind> = config.upstream.iter().filter(|u| u.enabled)
            .map(create_upstream).collect::<Result<Vec<_>>>()?;

        for upstream in &upstreams {
            if let Err(e) = upstream.start().await {
                warn!(upstream = upstream.name(), error = %e, "не удалось запустить upstream");
            }
        }

        let routing = RoutingSetup::apply(config).await?;
        let shared_metrics: SharedMetrics = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let monitor = if config.monitoring.enabled { Some(Monitor::new(config)) } else { None };

        let mut manager = Self {
            upstreams, active_index: None, failure_count: 0,
            routing: Some(routing), nat: None,
            server_interface: config.server.interface.clone(),
            server_subnet: config.server.subnet.to_string(),
            use_nftables: config.nat.use_nftables,
            masquerade: config.nat.masquerade,
            active_since: None, monitor, shared_metrics: shared_metrics.clone(),
        };

        manager.select_initial().await?;

        if let Some(ref mut m) = manager.monitor {
            if let Some(idx) = manager.active_index { m.set_selector_active(idx); }
        }

        Ok(manager)
    }

    pub fn shared_metrics(&self) -> SharedMetrics { self.shared_metrics.clone() }
    pub fn prometheus_enabled(&self) -> bool { self.monitor.as_ref().map(|m| m.prometheus_enabled()).unwrap_or(false) }
    pub fn prometheus_port(&self) -> u16 { self.monitor.as_ref().map(|m| m.prometheus_port()).unwrap_or(9099) }

    async fn select_initial(&mut self) -> Result<()> {
        for (i, upstream) in self.upstreams.iter().enumerate() {
            match upstream.health_check().await {
                Ok(()) => { self.activate(i).await?; return Ok(()); }
                Err(e) => { warn!(upstream = upstream.name(), error = %e, "health check не прошёл"); }
            }
        }
        anyhow::bail!("нет здоровых upstream при запуске");
    }

    async fn activate(&mut self, index: usize) -> Result<()> {
        let interface = self.upstreams[index].interface().to_string();
        let name = self.upstreams[index].name().to_string();

        if let Some(routing) = &self.routing { routing.set_default_route(&interface).await?; }

        if self.nat.is_none() {
            self.nat = Some(NatSetup::apply(&self.server_interface, &interface, &self.server_subnet, self.use_nftables, self.masquerade).await?);
        } else if let Some(nat) = self.nat.as_mut() { nat.switch_interface(&interface).await?; }

        self.active_index = Some(index);
        self.failure_count = 0;
        self.active_since = Some(std::time::Instant::now());
        info!(upstream = %name, interface = %interface, "активный upstream");
        Ok(())
    }

    pub async fn monitor_loop(&mut self) {
        if self.monitor.is_some() { self.scoring_loop().await; } else { self.legacy_loop().await; }
    }

    async fn scoring_loop(&mut self) {
        let mut last_https: Option<std::time::Instant> = None;
        let mut last_quality: Option<std::time::Instant> = None;
        info!("scoring loop запущен (monitoring + selector)");

        loop {
            let interval = self.monitor.as_ref().unwrap().health_interval_secs();
            let decision = self.monitor.as_mut().unwrap().probe_cycle(&mut last_https, &mut last_quality).await;
            *self.shared_metrics.lock().unwrap() = self.monitor.as_ref().unwrap().snapshot(self.active_index);

            if let Some(d) = decision { self.handle_switch_decision(d).await; }

            if self.active_index.is_none() {
                if self.try_recover().await.is_ok() {
                    if let Some(ref mut m) = self.monitor {
                        if let Some(idx) = self.active_index { m.set_selector_active(idx); }
                    }
                    continue;
                }
            }
            time::sleep(Duration::from_secs(interval)).await;
        }
    }

    async fn handle_switch_decision(&mut self, d: SwitchDecision) {
        let to_idx = d.to;
        let from_idx = d.from;

        match &d.reason {
            SwitchReason::QualityAdvantage { consecutive_wins, advantage_pct } => {
                info!(from = %d.from_name, to = %d.to_name, from_score = format!("{:.1}", d.from_score),
                      to_score = format!("{:.1}", d.to_score), advantage_pct = format!("{:.1}%", advantage_pct),
                      consecutive_wins, reason = "quality_advantage", "vpn_switch");
            }
            SwitchReason::EmergencyFailover => {
                warn!(from = %d.from_name, to = %d.to_name, from_score = format!("{:.1}", d.from_score),
                      to_score = format!("{:.1}", d.to_score), reason = "emergency_failover", "vpn_switch");
            }
        }

        let candidate_interface = self.upstreams[to_idx].interface().to_string();
        match monitor::https_probe(&candidate_interface, "https://1.1.1.1", 5).await {
            Ok(result) if result.success => {}
            _ => {
                warn!(candidate = %d.to_name, interface = %candidate_interface, "preflight failed — переключение отменено");
                if let Some(ref mut m) = self.monitor { m.set_selector_active(from_idx); }
                return;
            }
        }

        let old_index = self.active_index;
        if let Err(e) = self.activate(to_idx).await {
            error!(upstream = %d.to_name, error = %e, "ошибка активации при switch");
            if let Some(ref mut m) = self.monitor { m.set_selector_active(from_idx); }
            return;
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        let active_interface = self.upstreams[to_idx].interface().to_string();
        match crate::util::ping_check(&active_interface, "1.1.1.1", 3).await {
            Ok(_) => { info!(to = %d.to_name, interface = %active_interface, "verify passed — переключение подтверждено"); }
            Err(e) => {
                error!(to = %d.to_name, interface = %active_interface, error = %e, "verify failed — rollback");
                if let Some(prev) = old_index {
                    if let Err(e) = self.activate(prev).await { error!(error = %e, "rollback failed"); }
                    if let Some(ref mut m) = self.monitor { m.set_selector_active(prev); }
                }
            }
        }
    }

    async fn legacy_loop(&mut self) {
        loop {
            let (interval, threshold) = match self.active_index {
                Some(i) => (self.upstreams[i].health_check_interval(), self.upstreams[i].failover_threshold()),
                None => {
                    if self.try_recover().await.is_ok() { continue; }
                    time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
            };
            time::sleep(interval).await;

            let Some(active_index) = self.active_index else { continue; };
            match self.upstreams[active_index].health_check().await {
                Ok(()) => { if self.failure_count > 0 { info!("активный upstream восстановлен"); } self.failure_count = 0; }
                Err(e) => {
                    self.failure_count += 1;
                    warn!(upstream = self.upstreams[active_index].name(), error = %e,
                          failures = self.failure_count, threshold, "health check failed");
                    if self.failure_count >= threshold {
                        warn!(upstream = self.upstreams[active_index].name(), "достигнут порог failover");
                        self.failover().await;
                    }
                }
            }
        }
    }

    async fn failover(&mut self) {
        let old_index = self.active_index.unwrap();
        match self.find_healthy_excluding(old_index).await {
            Some(i) => {
                let old_name = self.upstreams[old_index].name().to_string();
                let new_name = self.upstreams[i].name().to_string();
                info!(from = %old_name, to = %new_name, "переключение upstream");
                if let Err(e) = self.activate(i).await { error!(upstream = %new_name, error = %e, "ошибка активации"); }
            }
            None => {
                error!(upstream = self.upstreams[old_index].name(), "нет доступных upstream для переключения");
                self.active_index = None;
                self.active_since = None;
            }
        }
    }

    async fn find_healthy_excluding(&self, exclude: usize) -> Option<usize> {
        for i in 0..self.upstreams.len() {
            if i == exclude { continue; }
            let upstream = &self.upstreams[i];
            if let Err(e) = upstream.start().await { warn!(upstream = upstream.name(), error = %e, "не удалось запустить"); continue; }
            if let Err(e) = upstream.health_check().await { warn!(upstream = upstream.name(), error = %e, "health check failed"); continue; }
            return Some(i);
        }
        None
    }

    async fn try_recover(&mut self) -> Result<()> {
        for (i, upstream) in self.upstreams.iter().enumerate() {
            if let Err(e) = upstream.start().await { warn!(upstream = upstream.name(), error = %e, "не удалось запустить"); continue; }
            if upstream.health_check().await.is_ok() { self.activate(i).await?; return Ok(()); }
        }
        anyhow::bail!("нет здоровых upstream")
    }

    pub async fn shutdown(&mut self) {
        if let Some(nat) = self.nat.take() { if let Err(e) = nat.cleanup().await { error!(error = %e, "ошибка очистки NAT"); } }
        if let Some(routing) = self.routing.take() { if let Err(e) = routing.cleanup().await { error!(error = %e, "ошибка очистки маршрутизации"); } }
        for upstream in &self.upstreams { if let Err(e) = upstream.stop().await { warn!(upstream = upstream.name(), error = %e, "ошибка остановки"); } }
    }
}
