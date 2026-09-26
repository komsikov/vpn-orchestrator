//! Корневой конфиг: TOML-десериализация и валидация.
//!
//! Под-секции определены в своих модулях и реэкспортированы отсюда:
//! - [`ServerConfig`] → `server`
//! - [`RoutingConfig`] → `routing`
//! - [`NatConfig`] → `nat`
//! - [`MonitoringConfig`] → `monitor`
//! - [`LoggingConfig`] и [`SpeedTestConfig`] определены здесь

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

pub use crate::monitor::MonitoringConfig;
pub use crate::nat::NatConfig;
pub use crate::routing::RoutingConfig;
pub use crate::server::ServerConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub upstream: Vec<UpstreamConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
    #[serde(default)]
    pub nat: NatConfig,
    #[serde(default)]
    pub speed_test: SpeedTestConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub monitoring: MonitoringConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub file: Option<PathBuf>,
    pub level: Option<String>,
    pub max_size_mb: u64,
    pub keep_mb: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: None,
            level: None,
            max_size_mb: 0,
            keep_mb: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub upstream_type: UpstreamType,
    pub interface: String,
    pub config_path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_health_interval")]
    pub health_check_interval: u64,
    #[serde(default = "default_health_target")]
    pub health_check_target: String,
    #[serde(default = "default_health_timeout")]
    pub health_check_timeout: u64,
    #[serde(default = "default_failover_threshold")]
    pub failover_threshold: u32,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamType {
    Wireguard,
    Amneziawg,
    Xray,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SpeedTestConfig {
    pub enabled: bool,
    pub url: String,
    pub interval: u64,
    pub timeout: u64,
    pub min_mbps: f64,
}

impl Default for SpeedTestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: "https://speed.cloudflare.com/__down?bytes=10000000".to_string(),
            interval: 300,
            timeout: 30,
            min_mbps: 0.0,
        }
    }
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("не удалось прочитать конфиг {}", path.display()))?;
        let config: Config = toml::from_str(&raw).context("ошибка разбора TOML-конфига")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        validate_interface(&self.server.interface, "server.interface")?;
        crate::routing::validate_route_table(self.routing.route_table)?;
        anyhow::ensure!(
            self.server.subnet.is_ipv4(),
            "server.subnet: поддерживается только IPv4"
        );
        anyhow::ensure!(
            self.routing.extra_prefixes.iter().all(|p| p.is_ipv4()),
            "routing.extra_prefixes: поддерживается только IPv4"
        );
        validate_quick_path(self.server.config_path.as_deref(), &self.server.interface)?;

        let enabled_count = self.upstream.iter().filter(|u| u.enabled).count();
        if enabled_count == 0 {
            anyhow::bail!("должен быть хотя бы один включённый [[upstream]] (enabled = true)");
        }

        let last_table = self
            .routing
            .route_table
            .checked_add(u32::try_from(enabled_count)?)
            .context("слишком много таблиц маршрутизации")?;
        for table in self.routing.route_table..=last_table {
            crate::routing::validate_route_table(table)?;
        }
        let mut seen = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        seen.insert(&self.server.interface);
        for (i, up) in self.upstream.iter().enumerate() {
            if !up.enabled {
                continue;
            }
            let ctx = format!("upstream[{i}] («{}»)", up.name);
            validate_interface(&up.interface, &format!("{ctx}.interface"))?;
            anyhow::ensure!(
                names.insert(&up.name),
                "{ctx}: имена включённых upstream должны быть уникальны (метка vpn)"
            );
            if up.name.is_empty() {
                anyhow::bail!("{ctx}: имя не может быть пустым");
            }
            if !seen.insert(&up.interface) {
                anyhow::bail!("{ctx}: дубликат имени интерфейса «{}»", up.interface);
            }
            anyhow::ensure!(
                up.health_check_interval > 0
                    && up.health_check_timeout > 0
                    && up.failover_threshold > 0,
                "{ctx}: интервалы, timeout и failover_threshold должны быть больше нуля"
            );
            anyhow::ensure!(
                up.health_check_target.parse::<std::net::Ipv4Addr>().is_ok(),
                "{ctx}.health_check_target: нужен IPv4-адрес"
            );
            if up.upstream_type != UpstreamType::Xray {
                validate_quick_path(up.config_path.as_deref(), &up.interface)?;
            }
        }
        if self.logging.max_size_mb > 0 {
            anyhow::ensure!(
                self.logging.keep_mb < self.logging.max_size_mb,
                "logging.keep_mb должен быть меньше max_size_mb"
            );
            self.logging
                .max_size_mb
                .checked_mul(1_000_000)
                .context("logging.max_size_mb слишком велик")?;
        }
        if self.speed_test.enabled {
            anyhow::ensure!(
                self.speed_test.interval > 0 && self.speed_test.timeout > 0,
                "speed_test: interval и timeout должны быть больше нуля"
            );
            anyhow::ensure!(
                self.speed_test.min_mbps.is_finite() && self.speed_test.min_mbps >= 0.0,
                "speed_test.min_mbps: нужно конечное неотрицательное число"
            );
            validate_url(&self.speed_test.url)?;
        }
        if self.monitoring.enabled {
            let m = &self.monitoring;
            anyhow::ensure!(m.health_interval > 0 && m.health_timeout > 0 && m.health_probe_count > 0 && m.history_size > 0,
                "monitoring: интервалы, timeout, probe_count и history_size должны быть больше нуля");
            anyhow::ensure!(
                !m.health_targets.is_empty()
                    && m.health_targets
                        .iter()
                        .all(|t| t.parse::<std::net::Ipv4Addr>().is_ok()),
                "monitoring.health_targets: нужен непустой список IPv4-адресов"
            );
            anyhow::ensure!(
                m.ewma_alpha.is_finite() && m.ewma_alpha > 0.0 && m.ewma_alpha <= 1.0,
                "monitoring.ewma_alpha: допустимо 0 < alpha <= 1"
            );
            if m.https_enabled {
                anyhow::ensure!(
                    m.https_interval > 0 && m.https_timeout > 0 && !m.https_targets.is_empty(),
                    "monitoring: нужны положительные HTTPS-интервалы и непустой https_targets"
                );
                for url in &m.https_targets {
                    validate_url(url)?;
                }
            }
            if m.quality_enabled {
                anyhow::ensure!(
                    m.quality_interval > 0 && m.quality_timeout > 0,
                    "monitoring: quality_interval и quality_timeout должны быть больше нуля"
                );
                validate_url(&m.quality_url)?;
            }
            let s = &m.scoring;
            anyhow::ensure!([s.latency_max_ms, s.jitter_max_ms].iter().all(|v| v.is_finite() && *v > 0.0), "monitoring.scoring: latency_max_ms и jitter_max_ms должны быть положительными конечными числами");
            anyhow::ensure!(
                [
                    s.availability_weight,
                    s.latency_weight,
                    s.loss_weight,
                    s.jitter_weight,
                    s.http_weight,
                    s.fast_weight,
                    s.historical_weight
                ]
                .iter()
                .all(|v| v.is_finite() && *v >= 0.0),
                "monitoring.scoring: веса должны быть конечными неотрицательными числами"
            );
            let weight = s.availability_weight
                + s.latency_weight
                + s.loss_weight
                + s.jitter_weight
                + s.http_weight;
            let final_weight = s.fast_weight + s.historical_weight;
            anyhow::ensure!(
                weight.is_finite()
                    && weight > 0.0
                    && final_weight.is_finite()
                    && final_weight > 0.0,
                "monitoring.scoring: суммы весов должны быть положительными конечными числами"
            );
            anyhow::ensure!(
                (0.0..=100.0).contains(&s.degraded_threshold)
                    && (s.degraded_threshold..=100.0).contains(&s.healthy_threshold),
                "monitoring.scoring: 0 <= degraded_threshold <= healthy_threshold <= 100"
            );
        }
        if self.monitoring.enabled || (self.speed_test.enabled && self.speed_test.min_mbps > 0.0) {
            let selector = &self.monitoring.selector;
            anyhow::ensure!(selector.minimum_advantage.is_finite() && selector.minimum_advantage >= 0.0 && selector.consecutive_wins > 0,
                "monitoring.selector: нужны неотрицательный minimum_advantage и положительный consecutive_wins");
        }
        Ok(())
    }
}

fn validate_quick_path(path: Option<&std::path::Path>, interface: &str) -> Result<()> {
    if let Some(path) = path {
        anyhow::ensure!(path.extension().and_then(|s| s.to_str()) == Some("conf") && path.file_stem().and_then(|s| s.to_str()) == Some(interface),
            "{}: wg-quick/awg-quick создаёт интерфейс по имени файла; для {interface} нужен {interface}.conf", path.display());
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<()> {
    anyhow::ensure!(
        url.starts_with("https://") || url.starts_with("http://"),
        "URL должен начинаться с http:// или https://"
    );
    Ok(())
}

pub(crate) fn validate_interface(name: &str, field: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("{field}: имя интерфейса не может быть пустым");
    }
    if name.len() > 15 {
        anyhow::bail!("{field}: имя интерфейса не длиннее 15 символов (получено {name})");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        anyhow::bail!("{field}: недопустимые символы в имени интерфейса «{name}»");
    }
    Ok(())
}

pub(crate) fn default_true() -> bool {
    true
}

fn default_health_interval() -> u64 {
    10
}
fn default_health_target() -> String {
    "8.8.8.8".to_string()
}
fn default_health_timeout() -> u64 {
    3
}
fn default_failover_threshold() -> u32 {
    3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        toml::from_str("[server]\ninterface='wg0'\nsubnet='10.8.0.0/24'\n[[upstream]]\nname='primary'\ntype='wireguard'\ninterface='wg1'").unwrap()
    }

    #[test]
    fn server_type_matches_documented_key() {
        let server: ServerConfig =
            toml::from_str("interface='awg0'\nsubnet='10.8.0.0/24'\ntype='amneziawg'").unwrap();
        assert_eq!(server.server_type, crate::server::ServerType::Amneziawg);
    }

    #[test]
    fn rejects_invalid_runtime_configuration() {
        for change in [
            |c: &mut Config| c.upstream[0].interface = "wg0".into(),
            |c: &mut Config| c.upstream[0].health_check_interval = 0,
            |c: &mut Config| c.upstream[0].config_path = Some("backup.conf".into()),
            |c: &mut Config| c.server.subnet = "fd00::/64".parse().unwrap(),
            |c: &mut Config| c.routing.route_table = 252,
            |c: &mut Config| {
                c.monitoring.enabled = true;
                c.monitoring.health_targets.clear();
            },
            |c: &mut Config| {
                c.monitoring.enabled = true;
                c.monitoring.ewma_alpha = f64::NAN;
            },
            |c: &mut Config| {
                c.monitoring.enabled = true;
                c.monitoring.history_size = 0;
            },
        ] {
            let mut config = minimal_config();
            change(&mut config);
            assert!(config.validate().is_err(), "{config:?}");
        }
    }

    #[test]
    fn speed_switch_validates_selector_without_monitoring() {
        let mut config = minimal_config();
        config.speed_test.enabled = true;
        config.speed_test.min_mbps = 5.0;
        config.monitoring.selector.consecutive_wins = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn disabled_upstream_does_not_conflict() {
        let mut config = minimal_config();
        let mut disabled = config.upstream[0].clone();
        disabled.enabled = false;
        config.upstream.push(disabled);
        config.validate().unwrap();
    }

    #[test]
    fn rejects_misspelled_upstream_enabled() {
        let config = toml::from_str::<Config>(
            "[server]\ninterface='wg0'\nsubnet='10.8.0.0/24'\n\
             [[upstream]]\nname='primary'\ntype='wireguard'\ninterface='wg1'\nenable=false",
        );
        assert!(config.is_err());
        assert!(config.unwrap_err().to_string().contains("enable"));
    }

    #[test]
    fn example_config_is_valid() {
        let config: Config = toml::from_str(include_str!("../config.example.toml")).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn validate_interface_accepts_valid_names() {
        assert!(validate_interface("wg0", "test").is_ok());
        assert!(validate_interface("eth-1", "test").is_ok());
    }

    #[test]
    fn validate_interface_rejects_invalid_names() {
        assert!(validate_interface("", "test").is_err());
        assert!(validate_interface("wg0; rm -rf /", "test").is_err());
        assert!(validate_interface("abcdefghijklmnop", "test").is_err());
    }

    #[test]
    fn config_multi_upstream() {
        let toml = r#"
[server]
interface = "wg0"
subnet = "10.8.0.0/24"

[[upstream]]
name = "primary"
type = "wireguard"
interface = "wg1"

[[upstream]]
name = "backup"
type = "xray"
interface = "tun0"

[[upstream]]
name = "amnezia"
type = "amneziawg"
interface = "awg0"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.upstream.len(), 3);
    }

    #[test]
    fn config_validate_no_upstreams() {
        let toml = r#"
[server]
interface = "wg0"
subnet = "10.8.0.0/24"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_duplicate_interfaces() {
        let toml = r#"
[server]
interface = "wg0"
subnet = "10.8.0.0/24"

[[upstream]]
name = "a"
type = "wireguard"
interface = "wg1"

[[upstream]]
name = "b"
type = "wireguard"
interface = "wg1"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_defaults_applied() {
        let toml = r#"
[server]
interface = "wg0"
subnet = "10.8.0.0/24"

[[upstream]]
name = "primary"
type = "wireguard"
interface = "wg1"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.upstream[0].health_check_interval, 10);
        assert_eq!(config.upstream[0].health_check_target, "8.8.8.8");
        assert_eq!(config.routing.route_table, 100);
        assert!(config.nat.masquerade);
    }
}
