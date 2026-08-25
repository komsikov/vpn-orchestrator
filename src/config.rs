//! Парсинг и валидация TOML-конфигурации.
//!
//! Конфиг задаётся в TOML-файле (по умолчанию `/etc/vpn-orchestrator/config.toml`).
//! Содержит секции: `[server]`, `[[upstream]]`, `[routing]`, `[nat]`,
//! `[speed_test]`, `[logging]`.

use std::path::PathBuf;

use anyhow::{Context, Result};
use ipnetwork::IpNetwork;
use serde::Deserialize;

/// Корневой конфиг оркестратора. Десериализуется из TOML.
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
}

/// Серверный VPN-интерфейс (принимает клиентов).
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Имя серверного интерфейса (принимает клиентов).
    pub interface: String,
    /// Тип серверного интерфейса: `wireguard` или `amneziawg`.
    #[serde(default)]
    pub server_type: ServerType,
    /// Подсеть VPN, выдаваемая клиентам сервера.
    pub subnet: IpNetwork,
    /// Порт прослушивания сервера.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Опциональный путь к конфигу сервера (wg-quick / awg-quick).
    pub config_path: Option<PathBuf>,
}

/// Конфиг одного upstream-подключения (клиент к удалённому VPN-серверу).
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// Человекочитаемое имя upstream-а.
    pub name: String,
    /// Тип VPN-подключения.
    #[serde(rename = "type")]
    pub upstream_type: UpstreamType,
    /// Имя сетевого интерфейса upstream-а.
    pub interface: String,
    /// Путь к конфигу (wg-quick, xray, openvpn…). Если не указан —
    /// предполагается, что интерфейс уже поднят внешне.
    pub config_path: Option<PathBuf>,
    /// Включён ли upstream. Если false — игнорируется (не запускается, не участвует в failover).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Интервал health-check (секунды).
    #[serde(default = "default_health_interval")]
    pub health_check_interval: u64,
    /// IP-адрес для проверки доступности через интерфейс.
    #[serde(default = "default_health_target")]
    pub health_check_target: String,
    /// Таймаут ping (секунды).
    #[serde(default = "default_health_timeout")]
    pub health_check_timeout: u64,
    /// Число последовательных неудач до переключения.
    #[serde(default = "default_failover_threshold")]
    pub failover_threshold: u32,
}

/// Тип серверного интерфейса.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServerType {
    #[default]
    Wireguard,
    Amneziawg,
}

/// Тип VPN-протокола для upstream-подключения.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamType {
    Wireguard,
    Amneziawg,
    Xray,
}

/// Настройки policy routing: IP forwarding, номер таблицы, доп. префиксы.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    #[serde(default = "default_true")]
    pub enable_ip_forward: bool,
    /// Таблица маршрутизации для трафика клиентов.
    #[serde(default = "default_route_table")]
    pub route_table: u32,
    /// Дополнительные префиксы, маршрутизируемые через upstream.
    #[serde(default)]
    pub extra_prefixes: Vec<IpNetwork>,
}

/// Настройки NAT: маскарадинг и выбор nftables / iptables.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NatConfig {
    #[serde(default = "default_true")]
    pub masquerade: bool,
    /// Использовать nftables (true) или iptables (false).
    #[serde(default = "default_true")]
    pub use_nftables: bool,
}

impl Config {
    /// Загружает и валидирует конфиг из TOML-файла.
    ///
    /// # Ошибки
    /// - Файл не существует или недоступен для чтения
    /// - Ошибка синтаксиса TOML
    /// - Валидация не пройдена (нет upstream-ов, дубликаты интерфейсов и т.д.)
    pub fn load(path: &PathBuf) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("не удалось прочитать конфиг {}", path.display()))?;
        let config: Config = toml::from_str(&raw).context("ошибка разбора TOML-конфига")?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        validate_interface(&self.server.interface, "server.interface")?;
        validate_route_table(self.routing.route_table)?;

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

fn validate_interface(name: &str, field: &str) -> Result<()> {
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

fn validate_route_table(table: u32) -> Result<()> {
    match table {
        0 | 253 | 254 | 255 => {
            anyhow::bail!("routing.route_table: значение {table} зарезервировано ядром Linux");
        }
        _ => Ok(()),
    }
}

fn default_listen_port() -> u16 {
    51820
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

fn default_route_table() -> u32 {
    100
}

fn default_true() -> bool {
    true
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            enable_ip_forward: default_true(),
            route_table: default_route_table(),
            extra_prefixes: Vec::new(),
        }
    }
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            masquerade: default_true(),
            use_nftables: default_true(),
        }
    }
}

/// Настройки периодического замера скорости upstream-ов.
///
/// При `min_mbps > 0` — переключается на более быстрый upstream,
/// если активный ниже порога. При `min_mbps = 0` — только логирование.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SpeedTestConfig {
    /// Включить периодический замер скорости.
    pub enabled: bool,
    /// URL для загрузки тестового файла.
    pub url: String,
    /// Интервал замера (секунды).
    pub interval: u64,
    /// Таймаут загрузки (секунды).
    pub timeout: u64,
    /// Минимальная скорость (Мбит/с). При падении активного upstream ниже порога
    /// и наличии более быстрого — оркестратор переключается. 0 = только логирование.
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

/// Настройки логирования: вывод в stdout или файл, уровень, отключение.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub enabled: bool,
    pub file: Option<PathBuf>,
    pub level: Option<String>,
    /// Максимальный размер файла в МБ. При превышении — файл обрезается,
    /// последние `keep_mb` мегабайт сохраняются. 0 = без ограничения.
    pub max_size_mb: u64,
    /// Сколько МБ оставить при ротации (последние записи).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_interface_accepts_valid_names() {
        assert!(validate_interface("wg0", "test").is_ok());
        assert!(validate_interface("eth-1", "test").is_ok());
        assert!(validate_interface("wg_server", "test").is_ok());
    }

    #[test]
    fn validate_interface_rejects_invalid_names() {
        assert!(validate_interface("", "test").is_err());
        assert!(validate_interface("wg0; rm -rf /", "test").is_err());
        assert!(validate_interface("abcdefghijklmnop", "test").is_err());
        assert!(validate_interface("wg 0", "test").is_err());
    }

    #[test]
    fn validate_route_table_rejects_reserved() {
        for &t in &[0, 253, 254, 255] {
            assert!(
                validate_route_table(t).is_err(),
                "table {t} should be reserved"
            );
        }
    }

    #[test]
    fn validate_route_table_accepts_valid() {
        assert!(validate_route_table(100).is_ok());
        assert!(validate_route_table(1).is_ok());
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
config_path = "/etc/wireguard/wg1.conf"

[[upstream]]
name = "backup"
type = "xray"
interface = "tun0"
config_path = "/etc/xray/config.json"

[[upstream]]
name = "amnezia"
type = "amneziawg"
interface = "awg0"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.upstream.len(), 3);
        assert_eq!(config.upstream[0].upstream_type, UpstreamType::Wireguard);
        assert_eq!(config.upstream[1].upstream_type, UpstreamType::Xray);
        assert_eq!(config.upstream[2].upstream_type, UpstreamType::Amneziawg);
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
        assert_eq!(config.upstream[0].health_check_timeout, 3);
        assert_eq!(config.upstream[0].failover_threshold, 3);
        assert_eq!(config.routing.route_table, 100);
        assert!(config.nat.masquerade);
    }

    #[test]
    fn speed_test_config_defaults() {
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
        assert!(!config.speed_test.enabled);
        assert_eq!(config.speed_test.interval, 300);
        assert_eq!(config.speed_test.timeout, 30);
        assert_eq!(config.speed_test.min_mbps, 0.0);
    }

    #[test]
    fn speed_test_config_enabled() {
        let toml = r#"
[server]
interface = "wg0"
subnet = "10.8.0.0/24"

[[upstream]]
name = "primary"
type = "wireguard"
interface = "wg1"

[speed_test]
enabled = true
url = "http://example.com/10mb.bin"
interval = 120
timeout = 15
min_mbps = 5.0
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.speed_test.enabled);
        assert_eq!(config.speed_test.url, "http://example.com/10mb.bin");
        assert_eq!(config.speed_test.interval, 120);
        assert_eq!(config.speed_test.timeout, 15);
        assert_eq!(config.speed_test.min_mbps, 5.0);
    }

    #[test]
    fn logging_config_defaults() {
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
        assert!(config.logging.enabled);
        assert!(config.logging.file.is_none());
        assert!(config.logging.level.is_none());
    }

    #[test]
    fn logging_config_custom() {
        let toml = r#"
[server]
interface = "wg0"
subnet = "10.8.0.0/24"

[[upstream]]
name = "primary"
type = "wireguard"
interface = "wg1"

[logging]
enabled = true
file = "/var/log/vpn-orchestrator.log"
level = "debug"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(config.logging.enabled);
        assert_eq!(
            config.logging.file.as_ref().unwrap(),
            std::path::Path::new("/var/log/vpn-orchestrator.log")
        );
        assert_eq!(config.logging.level.as_deref(), Some("debug"));
    }

    #[test]
    fn logging_config_disabled() {
        let toml = r#"
[server]
interface = "wg0"
subnet = "10.8.0.0/24"

[[upstream]]
name = "primary"
type = "wireguard"
interface = "wg1"

[logging]
enabled = false
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert!(!config.logging.enabled);
    }
}
