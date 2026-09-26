//! Адаптер WireGuard и AmneziaWG.
//!
//! Оба протокола используют одинаковый интерфейс командной строки
//! (`wg-quick` / `awg-quick`), отличаясь только бинарником.
//!
//! Важно: upstream-конфиги должны содержать `Table = off`, чтобы
//! `wg-quick` не перехватывал default route — маршрутизацией управляет
//! оркестратор.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{error, info};

use crate::config::UpstreamConfig;
use crate::util::{interface_is_up, ping_check};

/// Универсальный адаптер для WireGuard и AmneziaWG (оба используют wg-quick / awg-quick).
pub struct WgUpstream {
    name: String,
    interface: String,
    config_path: Option<PathBuf>,
    quick_binary: &'static str,
    health_target: String,
    health_timeout: u64,
    health_check_interval: u64,
    failover_threshold: u32,
    started: AtomicBool,
}

impl WgUpstream {
    pub fn new(config: &UpstreamConfig, quick_binary: &'static str) -> Result<Self> {
        Ok(Self {
            name: config.name.clone(),
            interface: config.interface.clone(),
            config_path: config.config_path.clone(),
            quick_binary,
            health_target: config.health_check_target.clone(),
            health_timeout: config.health_check_timeout,
            health_check_interval: config.health_check_interval,
            failover_threshold: config.failover_threshold,
            started: AtomicBool::new(false),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn health_check_interval(&self) -> Duration {
        Duration::from_secs(self.health_check_interval)
    }

    pub fn failover_threshold(&self) -> u32 {
        self.failover_threshold
    }

    pub async fn start(&self) -> Result<()> {
        if interface_is_up(&self.interface).await.is_ok() {
            return Ok(());
        }
        let Some(path) = &self.config_path else {
            anyhow::bail!(
                "интерфейс {} не поднят и config_path не указан",
                self.interface
            );
        };
        if crate::util::restore_existing_interface(&self.interface).await? {
            return Ok(());
        }
        run_wg_quick(self.quick_binary, "up", path).await?;
        self.started.store(true, Ordering::Relaxed);
        interface_is_up(&self.interface).await?;
        info!(upstream = %self.name, interface = %self.interface, "upstream поднят");
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        if !self.started.load(Ordering::Relaxed) {
            return Ok(());
        }
        let Some(path) = &self.config_path else {
            return Ok(());
        };
        run_wg_quick(self.quick_binary, "down", path).await?;
        self.started.store(false, Ordering::Relaxed);
        Ok(())
    }

    pub async fn health_check(&self) -> Result<()> {
        ping_check(&self.interface, &self.health_target, self.health_timeout)
            .await
            .map(|_| ())
    }
}

async fn run_wg_quick(binary: &str, action: &str, config_path: &Path) -> Result<()> {
    let output = Command::new(binary)
        .arg(action)
        .arg(config_path)
        .output()
        .await
        .with_context(|| format!("{binary} {action} {}", config_path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(stderr = %stderr, "{binary} ошибка");
        anyhow::bail!("{binary} {action}: {stderr}");
    }
    Ok(())
}
