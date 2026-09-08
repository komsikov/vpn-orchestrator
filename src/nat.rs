//! NAT и FORWARD правила для маршрутизации трафика клиентов через upstream.
//!
//! Поддерживает два бэкенда: nftables (по умолчанию) и iptables.
//! При failover — правила пересоздаются на новый upstream-интерфейс.

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::process::Command;
use tracing::{debug, info};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NatConfig {
    #[serde(default = "crate::config::default_true")]
    pub masquerade: bool,
    #[serde(default = "crate::config::default_true")]
    pub use_nftables: bool,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            masquerade: true,
            use_nftables: true,
        }
    }
}

/// Управляет NAT (masquerade) и FORWARD правилами.
///
/// При смене активного upstream — вызывает [`NatSetup::switch_interface`] для
/// пересоздания правил на новый интерфейс.
pub struct NatSetup {
    server_interface: String,
    upstream_interface: String,
    server_subnet: String,
    use_nftables: bool,
    masquerade: bool,
}

impl NatSetup {
    /// Применяет NAT и FORWARD правила для указанной пары интерфейсов.
    ///
    /// Если `masquerade = false` — правила не применяются (no-op).
    /// Сначала удаляются старые правила, затем применяются новые.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply(
        server_interface: &str,
        upstream_interface: &str,
        server_subnet: &str,
        use_nftables: bool,
        masquerade: bool,
    ) -> Result<Self> {
        let setup = Self {
            server_interface: server_interface.to_string(),
            upstream_interface: upstream_interface.to_string(),
            server_subnet: server_subnet.to_string(),
            use_nftables,
            masquerade,
        };

        if !masquerade {
            return Ok(setup);
        }

        setup.remove_rules().await;

        if let Err(error) = setup.apply_rules().await {
            setup.remove_rules().await;
            return Err(error);
        }

        info!(
            server_if = %setup.server_interface,
            upstream_if = %setup.upstream_interface,
            subnet = %setup.server_subnet,
            "NAT и FORWARD правила применены"
        );

        Ok(setup)
    }

    /// Переключает NAT на новый upstream-интерфейс (при failover).
    pub async fn switch_interface(&mut self, new_upstream: &str) -> Result<()> {
        if !self.masquerade {
            return Ok(());
        }
        let previous = self.upstream_interface.clone();
        self.remove_rules().await;
        self.upstream_interface = new_upstream.to_string();

        if let Err(error) = self.apply_rules().await {
            self.remove_rules().await;
            self.upstream_interface = previous;
            if let Err(rollback) = self.apply_rules().await {
                return Err(
                    error.context(format!("восстановление NAT также не удалось: {rollback}"))
                );
            }
            return Err(error);
        }

        info!(upstream = new_upstream, "NAT переключён на новый upstream");
        Ok(())
    }

    async fn apply_rules(&self) -> Result<()> {
        if self.use_nftables {
            self.apply_nftables().await
        } else {
            self.apply_iptables().await
        }
    }

    async fn apply_nftables(&self) -> Result<()> {
        let script = nftables_script(
            &self.server_interface,
            &self.upstream_interface,
            &self.server_subnet,
        );
        run_nft(&script).await
    }

    async fn apply_iptables(&self) -> Result<()> {
        let rules = iptables_rules(
            &self.server_interface,
            &self.upstream_interface,
            &self.server_subnet,
            "-A",
        );

        for rule in &rules {
            run_iptables(rule).await?;
        }

        Ok(())
    }

    async fn remove_rules(&self) {
        if !self.masquerade {
            return;
        }
        if self.use_nftables {
            if let Err(e) = nft_delete_table().await {
                debug!(error = %e, "nft table не найдена (нормально при первом старте)");
            }
        } else {
            for rule in &iptables_rules(
                &self.server_interface,
                &self.upstream_interface,
                &self.server_subnet,
                "-D",
            ) {
                let _ = run_iptables(rule).await;
            }
        }
    }

    /// Удаляет NAT/FORWARD правила. Безопасно вызывает при отсутствии правил.
    pub async fn cleanup(&self) -> Result<()> {
        info!("очистка NAT/FORWARD правил");
        self.remove_rules().await;
        Ok(())
    }
}

/// Генерирует nftables-скрипт для NAT и FORWARD правил.
fn nftables_script(server: &str, upstream: &str, subnet: &str) -> String {
    format!(
        r#"
table ip vpn_orchestrator_nat {{
    chain forward {{
        type filter hook forward priority 0; policy accept;
        iifname "{server}" oifname "{upstream}" accept
        iifname "{upstream}" oifname "{server}" ct state established,related accept
    }}
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
        ip saddr {subnet} oifname "{upstream}" masquerade
    }}
}}
"#,
    )
}

/// Генерирует список iptables-правил (action: "-A" — добавить, "-D" — удалить).
fn iptables_rules(server: &str, upstream: &str, subnet: &str, action: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            action.into(),
            "FORWARD".into(),
            "-i".into(),
            server.into(),
            "-o".into(),
            upstream.into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            action.into(),
            "FORWARD".into(),
            "-i".into(),
            upstream.into(),
            "-o".into(),
            server.into(),
            "-m".into(),
            "conntrack".into(),
            "--ctstate".into(),
            "RELATED,ESTABLISHED".into(),
            "-j".into(),
            "ACCEPT".into(),
        ],
        vec![
            "-t".into(),
            "nat".into(),
            action.into(),
            "POSTROUTING".into(),
            "-s".into(),
            subnet.into(),
            "-o".into(),
            upstream.into(),
            "-j".into(),
            "MASQUERADE".into(),
        ],
    ]
}

async fn nft_delete_table() -> Result<()> {
    let output = Command::new("nft")
        .args(["delete", "table", "ip", "vpn_orchestrator_nat"])
        .output()
        .await
        .context("nft delete table")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("No such file or directory") {
            return Ok(());
        }
        anyhow::bail!("nft delete table: {}", stderr.trim());
    }
    Ok(())
}

async fn run_nft(script: &str) -> Result<()> {
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt;

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("запуск nft")?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .await
            .context("запись nft rules")?;
    }

    let status = child.wait().await.context("ожидание nft")?;
    if !status.success() {
        anyhow::bail!("nft завершился с кодом {:?}", status.code());
    }
    Ok(())
}

async fn run_iptables(args: &[String]) -> Result<()> {
    let display = args.join(" ");
    let output = Command::new("iptables")
        .args(args)
        .output()
        .await
        .with_context(|| format!("iptables {display}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("iptables {display}: {}", stderr.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_nat_stays_disabled_after_switch_and_cleanup() {
        let mut nat = NatSetup::apply("wg0", "wg1", "10.8.0.0/24", true, false)
            .await
            .unwrap();
        nat.switch_interface("wg2").await.unwrap();
        nat.cleanup().await.unwrap();
        assert!(!nat.masquerade);
    }

    #[test]
    fn nftables_script_contains_all_rules() {
        let script = nftables_script("wg0", "wg1", "10.8.0.0/24");
        assert!(script.contains("vpn_orchestrator_nat"));
        assert!(script.contains(r#"iifname "wg0" oifname "wg1" accept"#));
        assert!(
            script.contains(r#"iifname "wg1" oifname "wg0" ct state established,related accept"#)
        );
        assert!(script.contains(r#"ip saddr 10.8.0.0/24 oifname "wg1" masquerade"#));
    }

    #[test]
    fn iptables_rules_apply_has_three_rules() {
        let rules = iptables_rules("wg0", "wg1", "10.8.0.0/24", "-A");
        assert_eq!(rules.len(), 3);
        assert!(rules[0].contains(&"-A".to_string()));
        assert!(rules[0].contains(&"wg0".to_string()));
        assert!(rules[2].contains(&"MASQUERADE".to_string()));
    }

    #[test]
    fn iptables_rules_delete_uses_d_flag() {
        let rules = iptables_rules("wg0", "wg1", "10.8.0.0/24", "-D");
        assert!(rules[0].contains(&"-D".to_string()));
        assert!(rules[1].contains(&"-D".to_string()));
        assert!(rules[2].contains(&"-D".to_string()));
    }

    #[test]
    fn iptables_rules_apply_and_delete_mirror() {
        let apply = iptables_rules("wg0", "wg1", "10.8.0.0/24", "-A");
        let delete = iptables_rules("wg0", "wg1", "10.8.0.0/24", "-D");
        for (a, d) in apply.iter().zip(delete.iter()) {
            assert_eq!(a.len(), d.len());
        }
    }
}
