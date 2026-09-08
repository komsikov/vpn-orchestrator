//! Policy routing: направляет трафик VPN-клиентов через активный upstream.
//!
//! Правила `ip rule`:
//! - **priority 98**: привязанные к upstream сокеты → его таблица проб
//! - **priority 99**: трафик от IP самого WG-сервера → основная таблица
//!   (чтобы handshake и web UI не уходили через upstream)
//! - **priority 100**: трафик из VPN-подсети → таблица N (через upstream)
//! - **priority 101**: блокировка обхода VPN через main при пустой таблице N
//!
//! Default route в таблице N обновляется при каждом failover.

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::Deserialize;
use tokio::process::Command;
use tracing::info;

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
        Self {
            enable_ip_forward: true,
            route_table: default_route_table(),
            extra_prefixes: Vec::new(),
        }
    }
}

fn default_route_table() -> u32 {
    100
}

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
    extra_prefixes: Vec<IpNetwork>,
    server_ip: String,
    probe_tables: Vec<(String, u32)>,
    vpn_interfaces: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExitRoute {
    pub interface: String,
    pub gateway: Option<String>,
}

impl RoutingSetup {
    /// Настраивает policy routing: ip_forward + ip rule.
    /// Default route устанавливается отдельно через [`RoutingSetup::set_exit_route`].
    pub async fn apply(config: &Config) -> Result<Self> {
        let routing = &config.routing;

        if routing.enable_ip_forward {
            crate::util::enable_ip_forward()?;
        }

        let setup = Self {
            route_table: routing.route_table,
            server_subnet: config.server.subnet,
            extra_prefixes: routing.extra_prefixes.clone(),
            server_ip: get_interface_ip(&config.server.interface).await?,
            vpn_interfaces: config
                .upstream
                .iter()
                .map(|u| u.interface.clone())
                .collect(),
            probe_tables: config
                .upstream
                .iter()
                .filter(|u| u.enabled)
                .enumerate()
                .map(|(i, u)| (u.interface.clone(), routing.route_table + i as u32 + 1))
                .collect(),
        };

        if let Err(error) = setup.apply_policy_rule().await {
            let _ = setup.cleanup().await;
            return Err(error);
        }

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

        ensure_rule(&["priority", "99", "from", &self.server_ip, "lookup", "main"]).await?;
        ensure_rule(&["priority", "101", "from", &subnet, "type", "unreachable"]).await?;
        ensure_rule(&["priority", "100", "from", &subnet, "table", &table]).await?;
        Ok(())
    }

    /// Маршрут для локальных сокетов, привязанных к upstream (ping/curl).
    pub async fn prepare_probe_route(&self, interface: &str) -> Result<()> {
        let (_, table) = self
            .probe_tables
            .iter()
            .find(|(name, _)| name == interface)
            .context("не найдена таблица upstream")?;
        let table = table.to_string();
        run_ip(&[
            "route", "replace", "default", "dev", interface, "table", &table,
        ])
        .await?;
        ensure_rule(&["priority", "98", "oif", interface, "table", &table]).await
    }

    /// Обновляет default route (и доп. маршруты) на указанный интерфейс.
    /// Вызывается при запуске и при failover.
    pub async fn set_exit_route(&self, route: &ExitRoute) -> Result<()> {
        let table = self.route_table.to_string();
        for prefix in std::iter::once("default".to_string())
            .chain(self.extra_prefixes.iter().map(ToString::to_string))
        {
            let mut args = vec!["route", "replace", &prefix];
            if let Some(gateway) = &route.gateway {
                args.extend(["via", gateway.as_str(), "onlink"]);
            }
            args.extend(["dev", route.interface.as_str(), "table", &table]);
            run_ip(&args).await?;
        }
        Ok(())
    }

    pub async fn direct_route(&self, server_interface: &str) -> Result<ExitRoute> {
        let output = Command::new("ip")
            .args(["-4", "route", "show", "table", "main", "default"])
            .output()
            .await?;
        anyhow::ensure!(
            output.status.success(),
            "не удалось прочитать основной маршрут: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut excluded = vec![server_interface];
        excluded.extend(self.vpn_interfaces.iter().map(String::as_str));
        parse_direct_route(&String::from_utf8_lossy(&output.stdout), &excluded)
            .context("нет обычного IPv4 default route в main (вне VPN-интерфейсов)")
    }

    pub async fn suspend(&self) -> Result<()> {
        run_ip(&["route", "flush", "table", &self.route_table.to_string()]).await
    }

    /// Очищает правила и маршруты. Вызывается при остановке оркестратора.
    pub async fn cleanup(&self) -> Result<()> {
        info!("очистка правил маршрутизации");

        let table = self.route_table.to_string();
        let subnet = self.server_subnet.to_string();

        let _ = run_ip(&[
            "rule",
            "del",
            "priority",
            "99",
            "from",
            &self.server_ip,
            "lookup",
            "main",
        ])
        .await;
        for (interface, table) in &self.probe_tables {
            let table = table.to_string();
            let _ = run_ip(&[
                "rule", "del", "priority", "98", "oif", interface, "table", &table,
            ])
            .await;
            let _ = run_ip(&["route", "flush", "table", &table]).await;
        }
        let _ = run_ip(&[
            "rule", "del", "priority", "100", "from", &subnet, "table", &table,
        ])
        .await;
        let _ = run_ip(&["route", "flush", "table", &table]).await;
        let _ = run_ip(&[
            "rule",
            "del",
            "priority",
            "101",
            "from",
            &subnet,
            "type",
            "unreachable",
        ])
        .await;

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

async fn ensure_rule(selector: &[&str]) -> Result<()> {
    // `ip rule show` не принимает `type`, хотя add/del поддерживают его.
    let query = selector
        .strip_suffix(&["type", "unreachable"])
        .unwrap_or(selector);
    let output = Command::new("ip")
        .args(["rule", "show"])
        .args(query)
        .output()
        .await?;
    anyhow::ensure!(
        output.status.success(),
        "ip rule show: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if output.stdout.iter().all(u8::is_ascii_whitespace) {
        let mut args = vec!["rule", "add"];
        args.extend_from_slice(selector);
        run_ip(&args).await?;
    } else if query.len() != selector.len() {
        anyhow::ensure!(
            String::from_utf8_lossy(&output.stdout).contains("unreachable"),
            "priority 101 занят другим правилом"
        );
    }
    Ok(())
}

fn parse_direct_route(output: &str, excluded: &[&str]) -> Option<ExitRoute> {
    output
        .lines()
        .filter_map(|line| {
            let words: Vec<_> = line.split_whitespace().collect();
            if words.first() != Some(&"default")
                || words.contains(&"linkdown")
                || words.contains(&"nexthop")
            {
                return None;
            }
            let value = |key| words.windows(2).find(|w| w[0] == key).map(|w| w[1]);
            let interface = value("dev")?;
            if excluded.contains(&interface) {
                return None;
            }
            let gateway = value("via").map(str::to_owned);
            if gateway
                .as_ref()
                .is_some_and(|g| g.parse::<std::net::Ipv4Addr>().is_err())
            {
                return None;
            }
            let metric = value("metric")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            Some((
                metric,
                ExitRoute {
                    interface: interface.into(),
                    gateway,
                },
            ))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, route)| route)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_exit_preserves_gateway_and_selects_lowest_metric() {
        let output = "default dev wg1\ndefault via 192.0.2.2 dev eth1 metric 200\ndefault via 192.0.2.1 dev eth0 metric 100\ndefault dev eth2 linkdown";
        let route = parse_direct_route(output, &["wg0", "wg1"]).unwrap();
        assert_eq!(
            route,
            ExitRoute {
                interface: "eth0".into(),
                gateway: Some("192.0.2.1".into())
            }
        );
        assert!(parse_direct_route("default dev wg1", &["wg1"]).is_none());
        assert_eq!(
            parse_direct_route("default dev ppp0", &[]).unwrap().gateway,
            None
        );
    }
}
