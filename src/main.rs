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
//! - [`monitor`] — мониторинг VPN: multi-target probes, EWMA, состояния

mod config;
mod monitor;
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
    let server_monitor = tokio::spawn(async move {
        monitor_server
            .monitor_loop(Duration::from_secs(cli.monitor_interval))
            .await;
    });

    // Prometheus metrics endpoint (если включён в [monitoring]).
    let prometheus = if upstreams.prometheus_enabled() {
        let port = upstreams.prometheus_port();
        let shared = upstreams.shared_metrics();
        Some(tokio::spawn(async move {
            monitor::serve_prometheus(shared, port).await;
        }))
    } else {
        None
    };

    // Failover-цикл работает параллельно с ожиданием сигнала остановки.
    tokio::select! {
        _ = shutdown_signal() => {
            info!("получен сигнал остановки");
        }
        _ = upstreams.monitor_loop() => {
            error!("monitor loop завершился неожиданно");
        }
    }

    server_monitor.abort();
    if let Some(h) = prometheus {
        h.abort();
    }
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
            let max_files = config.max_files;
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    if let Err(e) = rotate_log(&p, max_bytes, max_files) {
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

fn rotate_log(path: &std::path::Path, max_bytes: u64, max_files: u32) -> Result<()> {
    if std::fs::metadata(path)?.len() <= max_bytes { return Ok(()); }

    for i in (1..=max_files).rev() {
        let src = path.with_extension(format!("{}", i));
        if !src.exists() { continue; }
        if i >= max_files {
            let _ = std::fs::remove_file(&src);
        } else {
            let _ = std::fs::rename(&src, path.with_extension(format!("{}", i + 1)));
        }
    }

    std::fs::rename(path, path.with_extension("1"))?;
    info!(file = %path.display(), "лог-файл ротирован");
    Ok(())
}
