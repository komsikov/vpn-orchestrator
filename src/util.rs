//! Общие хелперы: проверка интерфейсов, ping, speed test, IP forwarding.

use anyhow::{Context, Result};
use tokio::process::Command;

/// Проверяет, что сетевой интерфейс существует и в состоянии UP.
pub async fn interface_is_up(name: &str) -> Result<()> {
    let output = Command::new("ip")
        .args(["link", "show", name])
        .output()
        .await
        .with_context(|| format!("ip link show {name}"))?;

    if !output.status.success() {
        anyhow::bail!("интерфейс {name} не найден");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("state UP") || stdout.contains("UP,") {
        Ok(())
    } else {
        anyhow::bail!("интерфейс {name} не в состоянии UP")
    }
}

/// Проверяет доступность target через указанный интерфейс.
/// Возвращает latency в мс.
pub async fn ping_check(interface: &str, target: &str, timeout_secs: u64) -> Result<f64> {
    let timeout_str = timeout_secs.to_string();
    let output = Command::new("ping")
        .args(["-I", interface, "-c", "1", "-W", &timeout_str, target])
        .output()
        .await
        .with_context(|| format!("ping -I {interface} -c 1 -W {timeout_str} {target}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ping {target} via {interface}: {}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for part in stdout.split_whitespace() {
        if let Some(rest) = part.strip_prefix("time=") {
            if let Some(ms_str) = rest.strip_suffix("ms") {
                return Ok(ms_str.parse().unwrap_or(0.0));
            }
            return Ok(rest.parse().unwrap_or(0.0));
        }
    }
    Ok(0.0)
}

/// Замеряет скорость загрузки через указанный интерфейс.
/// Возвращает скорость в Мбит/с.
pub async fn speed_test(interface: &str, url: &str, timeout_secs: u64) -> Result<f64> {
    let timeout_str = timeout_secs.to_string();
    let output = Command::new("curl")
        .args([
            "--interface",
            interface,
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{speed_download}",
            "--max-time",
            &timeout_str,
            url,
        ])
        .output()
        .await
        .with_context(|| format!("curl speed test via {interface}"))?;

    if !output.status.success() {
        if output.status.code() == Some(28) {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if !stdout.trim().is_empty() {
                let bytes_per_sec: f64 = stdout
                    .trim()
                    .parse()
                    .context("парсинг скорости (байт/сек) из вывода curl")?;
                let mbps = bytes_per_sec * 8.0 / 1_000_000.0;
                return Ok(mbps);
            }
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = if !stderr.is_empty() {
            stderr.trim()
        } else if !stdout.is_empty() {
            stdout.trim()
        } else {
            "неизвестная ошибка"
        };
        anyhow::bail!("speed test via {interface}: {detail}");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let bytes_per_sec: f64 = stdout
        .trim()
        .parse()
        .context("парсинг скорости (байт/сек) из вывода curl")?;

    let mbps = bytes_per_sec * 8.0 / 1_000_000.0;
    Ok(mbps)
}

/// Включает IP-форвардинг (`net.ipv4.ip_forward = 1`). Только Linux.
///
/// В Docker с `--network host` не работает — `/proc/sys` read-only.
/// В этом случае включите на хосте: `sudo sysctl -w net.ipv4.ip_forward=1`
/// и отключите в конфиге: `enable_ip_forward = false`.
#[cfg(target_os = "linux")]
pub fn enable_ip_forward() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("включение net.ipv4.ip_forward")?;
    tracing::info!("net.ipv4.ip_forward = 1");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_ip_forward() -> Result<()> {
    anyhow::bail!("IP forwarding поддерживается только на Linux");
}

/// Читает RX/TX байты для интерфейса из `/proc/net/dev`.
/// Возвращает `(rx_bytes, tx_bytes)`.
pub fn interface_traffic(interface: &str) -> Result<(u64, u64)> {
    let content = std::fs::read_to_string("/proc/net/dev").context("чтение /proc/net/dev")?;
    for line in content.lines().skip(2) {
        if line.trim().starts_with(&format!("{interface}:")) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let rx: u64 = parts[1].parse().unwrap_or(0);
                let tx: u64 = parts[9].parse().unwrap_or(0);
                return Ok((rx, tx));
            }
        }
    }
    anyhow::bail!("интерфейс {interface} не найден в /proc/net/dev")
}
