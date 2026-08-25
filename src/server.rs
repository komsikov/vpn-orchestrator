//! Управление серверным VPN-интерфейсом.
//!
//! Серверный интерфейс (например `wg0` / `awg0`) принимает VPN-клиентов.
//! Оркестратор может поднять его через `wg-quick` / `awg-quick` (если указан
//! `config_path`) или использовать уже поднятый внешним инструментом (wg-easy и т.д.).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::process::Command;
use tokio::time;
use tracing::{error, info, warn};

use crate::config::{Config, ServerType};
use crate::util::interface_is_up;

/// Управление серверным VPN-интерфейсом (принимает клиентов).
///
/// Если `config_path` задан — поднимает/опускает интерфейс через `wg-quick` или `awg-quick`.
/// Если нет — считает, что интерфейс управляется внешне, и только проверяет
/// что он жив и мониторит пиров.
pub struct ServerInterface {
    interface: String,
    config_path: Option<PathBuf>,
    quick_binary: &'static str,
    show_binary: &'static str,
}

impl ServerInterface {
    /// Создаёт из конфига. Не поднимает интерфейс — для этого вызовите [`ServerInterface::ensure_interface`].
    pub fn new(config: &Config) -> Self {
        let (quick_binary, show_binary) = match config.server.server_type {
            ServerType::Wireguard => ("wg-quick", "wg"),
            ServerType::Amneziawg => ("awg-quick", "awg"),
        };
        Self {
            interface: config.server.interface.clone(),
            config_path: config.server.config_path.clone(),
            quick_binary,
            show_binary,
        }
    }

    /// Поднимает интерфейс через `wg-quick` / `awg-quick` (если задан `config_path`).
    pub async fn ensure_interface(&self) -> Result<()> {
        if let Some(path) = &self.config_path {
            info!(config = %path.display(), "{} up", self.quick_binary);
            run_command(self.quick_binary, "up", path).await?;
            info!(interface = %path.file_stem().and_then(|s| s.to_str()).unwrap_or("wg"), "интерфейс поднят");
        }
        Ok(())
    }

    /// Проверяет, что интерфейс существует и в состоянии UP.
    pub async fn check_interface_up(&self) -> Result<()> {
        interface_is_up(&self.interface).await.with_context(|| {
            format!(
                "интерфейс {} недоступен — поднимите wg-quick или проверьте конфиг",
                self.interface
            )
        })
    }

    /// Периодически логирует состояние пиров.
    pub async fn monitor_loop(&self, interval: Duration) {
        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.log_peers().await {
                warn!(error = %e, "не удалось получить список пиров");
            }
        }
    }

    async fn log_peers(&self) -> Result<()> {
        let peers_output = Command::new(self.show_binary)
            .args(["show", &self.interface, "peers"])
            .output()
            .await
            .context("wg/awg show peers")?;

        if !peers_output.status.success() {
            return Ok(());
        }

        let total_peers = String::from_utf8_lossy(&peers_output.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .count();

        // Считаем активные хэндшейки (last-handshake за последние 3 минуты).
        let hs_output = Command::new(self.show_binary)
            .args(["show", &self.interface, "latest-handshakes"])
            .output()
            .await
            .context("wg/awg show latest-handshakes")?;

        let mut active = 0usize;
        if hs_output.status.success() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            for line in String::from_utf8_lossy(&hs_output.stdout).lines() {
                if let Some(ts_str) = line.split_whitespace().nth(1) {
                    if let Ok(ts) = ts_str.parse::<u64>() {
                        if ts > 0 && now.saturating_sub(ts) < 180 {
                            active += 1;
                        }
                    }
                }
            }
        }

        info!(
            interface = %self.interface,
            peers = total_peers,
            active,
            "состояние серверного WireGuard"
        );
        Ok(())
    }

    /// Опускает интерфейс через `wg-quick` / `awg-quick` (если был поднят оркестратором).
    pub async fn teardown(&self) -> Result<()> {
        if let Some(path) = &self.config_path {
            info!(config = %path.display(), "{} down", self.quick_binary);
            run_command(self.quick_binary, "down", path).await?;
        }
        Ok(())
    }
}

async fn run_command(binary: &str, action: &str, config_path: &std::path::Path) -> Result<()> {
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
