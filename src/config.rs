//! Корневой конфиг: TOML-десериализация и валидация.
//!
//! Под-секции определены в своих модулях и реэкспортированы отсюда:
//! - [`ServerConfig`] → `server`
//! - [`RoutingConfig`] → `routing`
//! - [`NatConfig`] → `nat`
//! - [`MonitoringConfig`] → `monitor`
//! - [`LoggingConfig`] → `main`

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;

pub use crate::server::ServerConfig;
pub use crate::routing::RoutingConfig;
pub use crate::nat::NatConfig;
pub use crate::monitor::MonitoringConfig;

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
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self { enabled: true, file: None, level: None, max_size_mb: 50, max_files: 5 }
    }
}

#[derive(Debug, Clone, Deserialize)]
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
            interval: 300, timeout: 30, min_mbps: 0.0,
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

        let enabled_count = self.upstream.iter().filter(|u| u.enabled).count();
        if enabled_count == 0 {
            anyhow::bail!("должен быть хотя бы один включённый [[upstream]] (enabled = true)");
        }

        let mut seen = std::collections::HashSet::new();
        for (i, up) in self.upstream.iter().enumerate() {
            let ctx = format!("upstream[{i}] («{}»)", up.name);
            validate_interface(&up.interface, &format!("{ctx}.interface"))?;
            if up.name.is_empty() {
                anyhow::bail!("{ctx}: имя не может быть пустым");
            }
            if !seen.insert(&up.interface) {
                anyhow::bail!("{ctx}: дубликат имени интерфейса «{}»", up.interface);
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_interface(name: &str, field: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("{field}: имя интерфейса не может быть пустым");
    }
    if name.len() > 15 {
        anyhow::bail!("{field}: имя интерфейса не длиннее 15 символов (получено {name})");
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        anyhow::bail!("{field}: недопустимые символы в имени интерфейса «{name}»");
    }
    Ok(())
}

pub(crate) fn default_true() -> bool { true }

fn default_health_interval() -> u64 { 10 }
fn default_health_target() -> String { "8.8.8.8".to_string() }
fn default_health_timeout() -> u64 { 3 }
fn default_failover_threshold() -> u32 { 3 }

#[cfg(test)]
mod tests {
    use super::*;

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
