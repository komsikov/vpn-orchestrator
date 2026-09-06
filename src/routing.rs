//! Policy routing: направляет трафик VPN-клиентов через активный upstream.
//!
//! Создаёт два правила `ip rule`:
//! - **priority 99**: трафик от IP самого WG-сервера → основная таблица
//!   (чтобы handshake и web UI не уходили через upstream)
//! - **priority 100**: трафик из VPN-подсети → таблица N (через upstream)
//!
//! Default route в таблице N обновляется при каждом failover.

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::Config;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    #[serde(default = "crate::config::default_true")]
    pub enable_ip_forward: bool,
    #[serde(default = "default_route_table")]
    pub route_table: u32,
    #[serde(default)]
    pub extra_prefixes: Vec<IpNetwork>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self { enable_ip_forward: true, route_table: default_route_table(), extra_prefixes: Vec::new() }
    }
}

fn default_route_table() -> u32 { 100 }

pub(crate) fn validate_route_table(table: u32) -> Result<()> {
    match table {
        0 | 253 | 254 | 255 => {
            anyhow::bail!("routing.route_table: значение {table} зарезервировано ядром Linux");
        }
        _ => Ok(()),
    }
}

/// Управляет policy routing: `ip rule` + `ip route` в отдельной таблице.
pub struct RoutingSetup {
    route_table: u32,
    server_subnet: IpNetwork,
    server_interface: String,
    extra_prefixes: Vec<IpNetwork>,
}

impl RoutingSetup {
    /// Настраивает policy routing: ip_forward + ip rule.
    /// Default route устанавливается отдельно через [`RoutingSetup::set_default_route`].
    pub async fn apply(config: &Config) -> Result<Self> {
        let routing = &config.routing;

        if routing.enable_ip_forward {
            crate::util::enable_ip_forward()?;
        }

        let setup = Self {
            route_table: routing.route_table,
            server_subnet: config.server.subnet,
            server_interface: config.server.interface.clone(),
            extra_prefixes: routing.extra_prefixes.clone(),
        };

        setup.apply_policy_rule().await?;

        info!(
            subnet = %setup.server_subnet,
            table = setup.route_table,
            "policy routing настроен"
        );

        Ok(setup)
    }

    async fn apply_policy_rule(&self) -> Result<()> {
        let table = self.route_table.to_string();
        let subnet = self.server_subnet.to_string();

        // Исключение: трафик от самого WG-сервера (handshake, web UI) не должен
        // идти через upstream. Получаем IP серверного интерфейса.
        if let Ok(server_ip) = get_interface_ip(&self.server_interface).await {
            if let Err(e) = run_ip(&[
                "rule", "add", "priority", "99", "from", &server_ip, "lookup", "main",
            ])
            .await
            {
                warn!(error = %e, "ip rule (server exception) — возможно уже существует");
            }
        }

        if let Err(e) = run_ip(&[
            "rule", "add", "priority", "100", "from", &subnet, "table", &table,
        ])
        .await
        {
            warn!(error = %e, "ip rule — возможно уже существует");
        }
        Ok(())
    }

    /// Обновляет default route (и доп. маршруты) на указанный интерфейс.
    /// Вызывается при запуске и при failover.
    pub async fn set_default_route(&self, interface: &str) -> Result<()> {
        let table = self.route_table.to_string();

        let _ = run_ip(&["route", "flush", "table", &table]).await;

        if let Err(e) =
            run_ip(&["route", "add", "default", "dev", interface, "table", &table]).await
        {
            warn!(error = %e, interface, "default route в таблице");
        }

        for prefix in &self.extra_prefixes {
            let prefix_str = prefix.to_string();
            if let Err(e) = run_ip(&[
                "route",
                "add",
                &prefix_str,
                "dev",
                interface,
                "table",
                &table,
            ])
            .await
            {
                warn!(prefix = %prefix, error = %e, "доп. маршрут");
            }
        }

        info!(interface, table = %table, "маршрут по умолчанию обновлён");
        Ok(())
    }

    /// Очищает правила и маршруты. Вызывается при остановке оркестратора.
    pub async fn cleanup(&self) -> Result<()> {
        info!("очистка правил маршрутизации");

        let table = self.route_table.to_string();
        let subnet = self.server_subnet.to_string();

        if let Ok(server_ip) = get_interface_ip(&self.server_interface).await {
            let _ = run_ip(&[
                "rule", "del", "priority", "99", "from", &server_ip, "lookup", "main",
            ])
            .await;
        }
        let _ = run_ip(&[
            "rule", "del", "priority", "100", "from", &subnet, "table", &table,
        ])
        .await;
        let _ = run_ip(&["route", "flush", "table", &table]).await;

        Ok(())
    }
}

async fn get_interface_ip(interface: &str) -> Result<String> {
    let output = Command::new("ip")
        .args(["-4", "-o", "addr", "show", interface])
        .output()
        .await
        .with_context(|| format!("ip addr show {interface}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Формат: "5: br-xxx    inet 10.42.42.42/24 brd ... scope global ..."
    for part in stdout.split_whitespace() {
        if part.contains('.') && part.contains('/') {
            let ip = part.split('/').next().unwrap_or("");
            if !ip.is_empty() {
                return Ok(ip.to_string());
            }
        }
    }
    anyhow::bail!("не удалось получить IP интерфейса {interface}")
}

async fn run_ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .with_context(|| format!("ip {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip {}: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}
