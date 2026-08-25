//! Адаптер Xray / 3x-ui.
//!
//! Запускает `xray run -config <path>` как дочерний процесс.
//! Xray создаёт TUN-интерфейс, через который идёт трафик.
//! При падении процесса — оркестратор перезапускает его при следующей
//! попытке активации.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::{Child, Command};
use tokio::time;
use tracing::{info, warn};

use crate::config::UpstreamConfig;
use crate::util::ping_check;

/// Адаптер для Xray / 3x-ui: запускает xray как дочерний процесс с TUN-интерфейсом.
pub struct XrayUpstream {
    name: String,
    interface: String,
    config_path: Option<PathBuf>,
    health_target: String,
    health_timeout: u64,
    health_check_interval: u64,
    failover_threshold: u32,
    child: Mutex<Option<Child>>,
}

impl XrayUpstream {
    pub fn new(config: &UpstreamConfig) -> Result<Self> {
        Ok(Self {
            name: config.name.clone(),
            interface: config.interface.clone(),
            config_path: config.config_path.clone(),
            health_target: config.health_check_target.clone(),
            health_timeout: config.health_check_timeout,
            health_check_interval: config.health_check_interval,
            failover_threshold: config.failover_threshold,
            child: Mutex::new(None),
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
        {
            let mut guard = self.child.lock().unwrap();
            if let Some(child) = guard.as_mut() {
                match child.try_wait() {
                    Ok(None) => return Ok(()),
                    Ok(Some(status)) => {
                        tracing::warn!(status = %status, "xray process died, restarting");
                        *guard = None;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "xray process check failed, restarting");
                        *guard = None;
                    }
                }
            }
        }

        let Some(config_path) = &self.config_path else {
            return Ok(()); // предполагаем, что xray уже запущен внешне
        };

        let mut child = Command::new("xray")
            .arg("run")
            .arg("-config")
            .arg(config_path)
            .spawn()
            .context("запуск xray")?;

        // Даём xray время на поднятие TUN-интерфейса.
        time::sleep(Duration::from_secs(2)).await;

        match child.try_wait()? {
            Some(status) => anyhow::bail!("xray завершился преждевременно: {status}"),
            None => {
                *self.child.lock().unwrap() = Some(child);
                info!(upstream = %self.name, interface = %self.interface, "xray запущен");
                Ok(())
            }
        }
    }

    pub async fn stop(&self) -> Result<()> {
        let child = self.child.lock().unwrap().take();
        if let Some(mut child) = child {
            if let Err(e) = child.kill().await {
                warn!(upstream = %self.name, error = %e, "ошибка kill xray");
            }
            let _ = child.wait().await;
            info!(upstream = %self.name, "xray остановлен");
        }
        Ok(())
    }

    pub async fn health_check(&self) -> Result<()> {
        // Проверяем, что процесс ещё жив.
        {
            let mut guard = self.child.lock().unwrap();
            if let Some(child) = guard.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => anyhow::bail!("xray process exited: {status}"),
                    Ok(None) => {}
                    Err(e) => anyhow::bail!("xray process check: {e}"),
                }
            }
        }

        ping_check(&self.interface, &self.health_target, self.health_timeout)
            .await
            .map(|_| ())
    }
}
