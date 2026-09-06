//! Общие хелперы: проверка интерфейсов, ping, IP forwarding.

use anyhow::{Context, Result};
use tokio::process::Command;

pub async fn interface_is_up(name: &str) -> Result<()> {
    let output = Command::new("ip").args(["link", "show", name]).output().await
        .with_context(|| format!("ip link show {name}"))?;
    if !output.status.success() { anyhow::bail!("интерфейс {name} не найден"); }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("state UP") || stdout.contains("UP,") { Ok(()) } else { anyhow::bail!("интерфейс {name} не в состоянии UP") }
}

pub async fn ping_check(interface: &str, target: &str, timeout_secs: u64) -> Result<f64> {
    let timeout_str = timeout_secs.to_string();
    let output = Command::new("ping").args(["-I", interface, "-c", "1", "-W", &timeout_str, target]).output().await
        .with_context(|| format!("ping -I {interface} -c 1 -W {timeout_str} {target}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ping {target} via {interface}: {}", stderr.trim());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for part in stdout.split_whitespace() {
        if let Some(rest) = part.strip_prefix("time=") {
            if let Some(ms_str) = rest.strip_suffix("ms") { return Ok(ms_str.parse().unwrap_or(0.0)); }
            return Ok(rest.parse().unwrap_or(0.0));
        }
    }
    Ok(0.0)
}

#[cfg(target_os = "linux")]
pub fn enable_ip_forward() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("включение net.ipv4.ip_forward")?;
    tracing::info!("net.ipv4.ip_forward = 1");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enable_ip_forward() -> Result<()> {
    anyhow::bail!("IP forwarding поддерживается только на Linux");
}
