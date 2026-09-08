//! Общие хелперы: проверка интерфейсов, ping, IP forwarding.

use anyhow::{Context, Result};
use tokio::process::Command;

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
    if link_flags_are_up(&stdout) {
        Ok(())
    } else {
        anyhow::bail!("интерфейс {name} не в состоянии UP")
    }
}

pub async fn ping_check(interface: &str, target: &str, timeout_secs: u64) -> Result<f64> {
    let timeout_str = timeout_secs.to_string();
    let output = Command::new("ping")
        .kill_on_drop(true)
        .env("LC_ALL", "C")
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
        if let Some(rest) = part
            .strip_prefix("time=")
            .or_else(|| part.strip_prefix("time<"))
        {
            if let Ok(ms) = rest.trim_end_matches("ms").parse::<f64>() {
                return Ok(ms);
            }
        }
    }
    Ok(0.0)
}

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

fn link_flags_are_up(output: &str) -> bool {
    output
        .split_once('<')
        .and_then(|(_, rest)| rest.split_once('>'))
        .is_some_and(|(flags, _)| flags.split(',').any(|flag| flag == "UP"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn recognizes_administratively_up_tunnels() {
        assert!(super::link_flags_are_up(
            "5: wg0: <POINTOPOINT,NOARP,UP> mtu 1420 state UNKNOWN"
        ));
        assert!(!super::link_flags_are_up(
            "5: wg0: <POINTOPOINT,NOARP,LOWER_UP> state UNKNOWN"
        ));
    }
}
