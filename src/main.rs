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
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..))]
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
    // При сигнале во время запуска завершаем текущую инициализацию и затем
    // выполняем обычную очистку вместо выхода с оставленными интерфейсами.
    let shutdown = tokio::spawn(shutdown_signal());

    let managed_server = !cli.skip_server;
    let mut server = ServerInterface::new(&config);

    if managed_server {
        server.ensure_interface().await?;
    }
    if let Err(error) = server.check_interface_up().await {
        if managed_server {
            let _ = server.teardown().await;
        }
        return Err(error);
    }

    let startup_start = std::time::Instant::now();
    let mut upstreams = match UpstreamManager::start(&config).await {
        Ok(manager) => manager,
        Err(error) => {
            if managed_server {
                let _ = server.teardown().await;
            }
            return Err(error);
        }
    };
    info!(
        startup_ms = startup_start.elapsed().as_millis(),
        "сервис запущен"
    );

    info!(
        server = %config.server.interface,
        server_port = config.server.listen_port,
        subnet = %config.server.subnet,
        route_table = config.routing.route_table,
        upstreams_enabled = config.upstream.iter().filter(|u| u.enabled).count(),
        upstreams_disabled = config.upstream.iter().filter(|u| !u.enabled).count(),
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
        _ = shutdown => {
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
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(format!("vpn_orchestrator={level}")))?;

    let file_path = cli_log_file.or(config.file.as_deref());

    if let Some(path) = file_path {
        let appender = RotatingLog::new(path, config.max_size_mb, config.keep_mb)?;
        let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .finish(appender);

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(writer)
            .with_ansi(false)
            .init();

        Ok(Some(guard))
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();

        Ok(None)
    }
}

/// Единственный писатель принадлежит non_blocking worker: ротация и запись
/// выполняются последовательно через один дескриптор без гонок с rename.
struct RotatingLog {
    file: std::fs::File,
    max_bytes: u64,
    keep_bytes: u64,
    write_failed: bool,
}

impl RotatingLog {
    fn new(path: &std::path::Path, max_mb: u64, keep_mb: u64) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .with_context(|| format!("открытие лог-файла {}", path.display()))?;
        Ok(Self {
            file,
            max_bytes: max_mb.saturating_mul(1_000_000),
            keep_bytes: keep_mb.saturating_mul(1_000_000),
            write_failed: false,
        })
    }

    fn report_result<T>(&mut self, result: std::io::Result<T>) -> std::io::Result<T> {
        match &result {
            Err(error) if !self.write_failed => {
                eprintln!("vpn-orchestrator: log_write_failed: {error}; файловые логи теряются");
                self.write_failed = true;
            }
            Ok(_) if self.write_failed => {
                eprintln!("vpn-orchestrator: log_write_restored: запись логов восстановлена");
                self.write_failed = false;
            }
            _ => {}
        }
        result
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};
        let len = self.file.metadata()?.len();
        if self.max_bytes == 0 || len <= self.max_bytes {
            return Ok(());
        }
        let offset = len.saturating_sub(self.keep_bytes);
        // Проверяем границу строки, чтобы не оставлять обрезанный UTF-8.
        let mut tail = Vec::new();
        self.file.seek(SeekFrom::Start(offset.saturating_sub(1)))?;
        self.file.read_to_end(&mut tail)?;
        let start = if offset == 0 {
            0
        } else {
            tail.iter()
                .position(|b| *b == b'\n')
                .map(|i| i + 1)
                .unwrap_or(tail.len())
        };
        self.file.set_len(0)?;
        self.file.write_all(&tail[start..])?;
        Ok(())
    }
}

impl std::io::Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let result = self.rotate().and_then(|_| self.file.write(buf));
        self.report_result(result)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let result = self.rotate().and_then(|_| self.file.flush());
        if result.is_err() {
            self.report_result(result)
        } else {
            result
        }
    }
}

#[cfg(test)]
mod logging_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn background_rotation_preserves_last_complete_record() {
        let path = std::env::temp_dir().join(format!("vpn-log-worker-{}.log", std::process::id()));
        let mut log = RotatingLog::new(&path, 0, 0).unwrap();
        log.file.set_len(0).unwrap();
        log.max_bytes = 128;
        log.keep_bytes = 64;
        let (mut writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .buffered_lines_limit(2)
            .finish(log);
        for i in 0..100 {
            writeln!(writer, "запись {i:03}").unwrap();
        }
        drop(writer);
        drop(guard);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with("запись 099\n"), "{text}");
        assert!(text.len() <= 128);
        assert!(text.lines().all(|l| l.starts_with("запись ")));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rotation_limits_and_io_failure_state() {
        let path = std::env::temp_dir().join(format!("vpn-log-limits-{}.log", std::process::id()));
        let mut log = RotatingLog::new(&path, 0, 0).unwrap();
        log.file.set_len(0).unwrap();
        log.write_all(&[b'x'; 1000]).unwrap();
        log.flush().unwrap();
        assert_eq!(log.file.metadata().unwrap().len(), 1000);
        log.max_bytes = 10;
        log.flush().unwrap();
        assert_eq!(log.file.metadata().unwrap().len(), 0);
        log.file = std::fs::File::open(&path).unwrap();
        assert!(log.write_all(b"test").is_err());
        assert!(log.write_failed);
        log.flush().unwrap();
        assert!(log.write_failed); // flush does not prove writes have recovered
        log.file = std::fs::OpenOptions::new()
            .append(true)
            .read(true)
            .open(&path)
            .unwrap();
        log.write_all(b"ok\n").unwrap();
        assert!(!log.write_failed);
        drop(log);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn rotation_keeps_tail_and_writer_continues_in_same_file() {
        let path = std::env::temp_dir().join(format!("vpn-log-test-{}.log", std::process::id()));
        let mut log = RotatingLog::new(&path, 0, 0).unwrap();
        log.file.set_len(0).unwrap();
        log.max_bytes = 15;
        log.keep_bytes = 7;
        log.write_all("старое\nновое\n".as_bytes()).unwrap();
        log.flush().unwrap();
        // Последняя строка длиннее keep_bytes: обрезанную строку не сохраняем.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
        log.write_all(b"first\nlast\nnext\n").unwrap();
        log.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "next\n");
        log.write_all(b"more\n").unwrap();
        log.flush().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "next\nmore\n");
        drop(log);
        std::fs::remove_file(path).unwrap();
    }
}
