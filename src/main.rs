//! # vpn-orchestrator
//!
//! VPN-оркестратор: принимает WireGuard-клиентов на серверном интерфейсе
//! и маршрутизирует их трафик через активный upstream VPN с автоматическим
//! failover при недоступности.
//!
//! ## Архитектура
//!
//! ```text
//! [WG-клиенты] → wg0 (сервер) → оркестратор → upstream (wg1/awg0/tun0) → интернет
//! ```
//!
//! - [`config`] — парсинг и валидация TOML-конфига
//! - [`server`] — серверный WireGuard-интерфейс
//! - [`upstream`] — upstream-подключения и failover
//! - [`routing`] — policy routing (ip rule, ip route)
//! - [`nat`] — NAT/FORWARD (nftables / iptables)
//! - [`util`] — хелперы (ping, проверка интерфейса, speed test)

mod config;
mod nat;
mod routing;
mod server;
mod upstream;
mod util;

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::config::LoggingConfig;
use crate::server::ServerInterface;
use crate::upstream::UpstreamManager;

/// CLI-аргументы, парсятся через [`clap`].
#[derive(Parser, Debug)]
#[command(
    name = "vpn-orchestrator",
    about = "VPN-оркестратор: приём WireGuard-клиентов с автоматическим failover между upstream VPN"
)]
struct Cli {
    /// Путь к TOML-конфигу.
    #[arg(short, long, default_value = "/etc/vpn-orchestrator/config.toml")]
    config: PathBuf,

    /// Интервал мониторинга пиров сервера (секунды).
    #[arg(long, default_value_t = 30)]
    monitor_interval: u64,

    /// Не поднимать серверный интерфейс через wg-quick (если уже настроен).
    #[arg(long)]
    skip_server: bool,

    /// Путь к файлу логов (переопределяет `[logging].file`).
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Отключить логирование.
    #[arg(long)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)
        .with_context(|| format!("загрузка конфига {}", cli.config.display()))?;

    let _log_guard = init_logging(&config.logging, cli.log_file.as_deref(), cli.quiet)?;

    let managed_server = !cli.skip_server;
    let server = ServerInterface::new(&config);

    if managed_server {
        server.ensure_interface().await?;
    }
    server.check_interface_up().await?;

    let startup_start = std::time::Instant::now();
    let mut upstreams = UpstreamManager::start(&config).await?;
    info!(startup_ms = startup_start.elapsed().as_millis(), "сервис запущен");

    info!(
        server = %config.server.interface,
        server_port = config.server.listen_port,
        subnet = %config.server.subnet,
        route_table = config.routing.route_table,
        upstreams = config.upstream.len(),
        "vpn-orchestrator запущен"
    );

    // Мониторинг пиров сервера — в отдельной задаче.
    let monitor_server = ServerInterface::new(&config);
    let monitor = tokio::spawn(async move {
        monitor_server
            .monitor_loop(Duration::from_secs(cli.monitor_interval))
            .await;
    });

    // Failover-цикл работает параллельно с ожиданием сигнала остановки.
    tokio::select! {
        _ = shutdown_signal() => {
            info!("получен сигнал остановки");
        }
        _ = upstreams.monitor_loop() => {
            error!("monitor loop завершился неожиданно");
        }
    }

    monitor.abort();
    info!("остановка vpn-orchestrator");
    upstreams.shutdown().await;

    if managed_server {
        if let Err(e) = server.teardown().await {
            error!(error = %e, "ошибка остановки серверного интерфейса");
        }
    } else {
        info!("серверный интерфейс не опускается (--skip-server)");
    }

    Ok(())
}

/// Ожидает SIGINT или SIGTERM для graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("не удалось подписаться на SIGINT");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("не удалось подписаться на SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("получен SIGINT"),
        _ = terminate => info!("получен SIGTERM"),
    }
}

/// Инициализирует логирование: stdout или файл, с опциональным отключением.
///
/// Возвращает [`tracing_appender::non_blocking::WorkerGuard`] для файлового вывода (нужно держать в scope
/// до завершения программы, иначе логи могут потеряться).
///
/// # Параметры
/// - `config` — секция `[logging]` из TOML-конфига
/// - `cli_log_file` — путь из `--log-file` (переопределяет конфиг)
/// - `quiet` — флаг `--quiet` (полное отключение)
fn init_logging(
    config: &LoggingConfig,
    cli_log_file: Option<&std::path::Path>,
    quiet: bool,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    if quiet || !config.enabled {
        return Ok(None);
    }

    let level = config.level.as_deref().unwrap_or("info");
    let filter = EnvFilter::from_default_env()
        .add_directive(format!("vpn_orchestrator={level}").parse()?);

    let file_path = cli_log_file.or(config.file.as_deref());

    if let Some(path) = file_path {
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        let file_name = path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("vpn-orchestrator.log"));

        let appender = tracing_appender::rolling::never(parent, file_name);
        let (writer, guard) = tracing_appender::non_blocking(appender);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .init();

        if config.max_size_mb > 0 {
            let p = path.to_path_buf();
            let max_bytes = config.max_size_mb * 1_000_000;
            let keep_bytes = config.keep_mb * 1_000_000;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    if let Err(e) = rotate_if_needed(&p, max_bytes, keep_bytes) {
                        eprintln!("log rotation error: {e}");
                    }
                }
            });
        }

        Ok(Some(guard))
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .init();

        Ok(None)
    }
}

/// Проверяет размер лог-файла и обрезает при превышении лимита.
/// Сохраняет последние `keep_bytes` байт — актуальные логи не теряются.
fn rotate_if_needed(path: &std::path::Path, max_bytes: u64, keep_bytes: u64) -> Result<()> {
    let metadata = std::fs::metadata(path)?;
    let size = metadata.len();
    if size <= max_bytes {
        return Ok(());
    }

    let content = std::fs::read(path)?;
    let start = content.len().saturating_sub(keep_bytes as usize);
    let tail = &content[start..];

    std::fs::write(path, tail)?;
    info!(file = %path.display(), old_size = size, "лог-файл ротирован");

    Ok(())
}
