//! Мониторинг VPN-интерфейсов: multi-target ICMP + HTTPS пробы,
//! EWMA-сглаживание, FastScore, selector с hysteresis/cooldown.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::Config;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MonitoringConfig {
    pub enabled: bool,
    pub health_targets: Vec<String>,
    pub health_interval: u64,
    pub health_timeout: u64,
    pub health_probe_count: u8,
    pub https_enabled: bool,
    pub https_targets: Vec<String>,
    pub https_interval: u64,
    pub https_timeout: u64,
    pub ewma_alpha: f64,
    pub history_size: usize,
    #[serde(default)]
    pub scoring: ScoringConfig,
    #[serde(default)]
    pub selector: SelectorConfig,
    #[serde(default)]
    pub prometheus_enabled: bool,
    #[serde(default = "default_prometheus_port")]
    pub prometheus_port: u16,
    #[serde(default)]
    pub quality_enabled: bool,
    #[serde(default = "default_quality_url")]
    pub quality_url: String,
    #[serde(default = "default_quality_interval")]
    pub quality_interval: u64,
    #[serde(default = "default_quality_timeout")]
    pub quality_timeout: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            health_targets: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            health_interval: 15, health_timeout: 2, health_probe_count: 5,
            https_enabled: true, https_targets: vec!["https://1.1.1.1".to_string()],
            https_interval: 60, https_timeout: 10,
            ewma_alpha: 0.2, history_size: 1000,
            scoring: ScoringConfig::default(), selector: SelectorConfig::default(),
            prometheus_enabled: false, prometheus_port: default_prometheus_port(),
            quality_enabled: false, quality_url: default_quality_url(),
            quality_interval: default_quality_interval(), quality_timeout: default_quality_timeout(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ScoringConfig {
    pub availability_weight: f64,
    pub latency_weight: f64,
    pub loss_weight: f64,
    pub jitter_weight: f64,
    pub http_weight: f64,
    pub latency_max_ms: f64,
    pub jitter_max_ms: f64,
    pub healthy_threshold: f64,
    pub degraded_threshold: f64,
    pub fast_weight: f64,
    pub historical_weight: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            availability_weight: 0.35, latency_weight: 0.25, loss_weight: 0.15,
            jitter_weight: 0.15, http_weight: 0.10,
            latency_max_ms: 500.0, jitter_max_ms: 20.0,
            healthy_threshold: 75.0, degraded_threshold: 40.0,
            fast_weight: 0.90, historical_weight: 0.10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SelectorConfig {
    pub enabled: bool,
    pub minimum_advantage: f64,
    pub consecutive_wins: u32,
    pub minimum_hold_secs: u64,
    pub cooldown_secs: u64,
}

impl Default for SelectorConfig {
    fn default() -> Self {
        Self { enabled: false, minimum_advantage: 0.10, consecutive_wins: 3, minimum_hold_secs: 180, cooldown_secs: 300 }
    }
}

fn default_prometheus_port() -> u16 { 9099 }
fn default_quality_url() -> String { "https://speed.cloudflare.com/__down?bytes=5000000".to_string() }
fn default_quality_interval() -> u64 { 300 }
fn default_quality_timeout() -> u64 { 30 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VpnState {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

impl std::fmt::Display for VpnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "UNKNOWN"),
            Self::Healthy => write!(f, "HEALTHY"),
            Self::Degraded => write!(f, "DEGRADED"),
            Self::Unhealthy => write!(f, "UNHEALTHY"),
        }
    }
}

fn determine_state(total: usize, failed: usize) -> VpnState {
    if total == 0 {
        return VpnState::Unknown;
    }
    if failed == 0 || (failed == 1 && total > 1) {
        VpnState::Healthy
    } else if failed >= total {
        VpnState::Unhealthy
    } else {
        VpnState::Degraded
    }
}

#[derive(Debug, Clone)]
pub struct SwitchDecision {
    pub from: usize,
    pub to: usize,
    pub from_name: String,
    pub to_name: String,
    pub from_score: f64,
    pub to_score: f64,
    pub reason: SwitchReason,
}

#[derive(Debug, Clone)]
pub enum SwitchReason {
    QualityAdvantage { consecutive_wins: u32, advantage_pct: f64 },
    EmergencyFailover,
}

#[derive(Debug, Clone, Default)]
pub struct VpnSnapshot {
    pub name: String,
    pub state: VpnState,
    pub score: Option<f64>,
    pub ewma_rtt: Option<f64>,
    pub ewma_loss: Option<f64>,
    pub ewma_jitter: Option<f64>,
    pub availability_5m: f64,
    pub rtt_p95: Option<f64>,
    pub https_success_ratio: Option<f64>,
    pub quality_mbps: Option<f64>,
    pub consecutive_failures: u32,
    pub selected: bool,
}

pub type SharedMetrics = Arc<Mutex<Vec<VpnSnapshot>>>;

struct IcmpResult {
    success: bool,
    rtts_ms: Vec<f64>,
    loss_pct: f64,
    jitter_ms: f64,
}

pub(crate) struct HttpsResult {
    pub(crate) success: bool,
}

struct QualityResult {
    success: bool,
    mbps: f64,
}

struct HealthSample {
    timestamp: Instant,
    success: bool,
    rtt_ms: Option<f64>,
    loss_pct: Option<f64>,
    jitter_ms: Option<f64>,
}

struct HttpsSample {
    timestamp: Instant,
    success: bool,
}

pub(crate) struct VpnMetrics {
    interface: String,
    name: String,
    health_samples: VecDeque<HealthSample>,
    https_samples: VecDeque<HttpsSample>,
    ewma_rtt: Option<f64>,
    ewma_loss: Option<f64>,
    ewma_jitter: Option<f64>,
    ewma_score: Option<f64>,
    quality_mbps: Option<f64>,
    state: VpnState,
    consecutive_failures: u32,
    last_success: Option<Instant>,
    last_failure: Option<Instant>,
    prev_state: VpnState,
}

impl VpnMetrics {
    fn new(interface: &str, name: &str, history_size: usize) -> Self {
        Self {
            interface: interface.to_string(),
            name: name.to_string(),
            health_samples: VecDeque::with_capacity(history_size),
            https_samples: VecDeque::with_capacity(history_size),
            ewma_rtt: None,
            ewma_loss: None,
            ewma_jitter: None,
            ewma_score: None,
            quality_mbps: None,
            state: VpnState::Unknown,
            consecutive_failures: 0,
            last_success: None,
            last_failure: None,
            prev_state: VpnState::Unknown,
        }
    }

    fn add_health_sample(&mut self, sample: HealthSample, alpha: f64, history_size: usize) {
        if sample.success {
            if let Some(rtt) = sample.rtt_ms {
                self.ewma_rtt = Some(match self.ewma_rtt {
                    Some(prev) => rtt * alpha + prev * (1.0 - alpha),
                    None => rtt,
                });
            }
            if let Some(loss) = sample.loss_pct {
                self.ewma_loss = Some(match self.ewma_loss {
                    Some(prev) => loss * alpha + prev * (1.0 - alpha),
                    None => loss,
                });
            }
            if let Some(jitter) = sample.jitter_ms {
                self.ewma_jitter = Some(match self.ewma_jitter {
                    Some(prev) => jitter * alpha + prev * (1.0 - alpha),
                    None => jitter,
                });
            }
            self.consecutive_failures = 0;
            self.last_success = Some(sample.timestamp);
        } else {
            self.consecutive_failures += 1;
            self.last_failure = Some(sample.timestamp);
            self.ewma_loss = Some(match self.ewma_loss {
                Some(prev) => 100.0 * alpha + prev * (1.0 - alpha),
                None => 100.0,
            });
        }

        self.health_samples.push_back(sample);
        while self.health_samples.len() > history_size {
            self.health_samples.pop_front();
        }
    }

    fn add_https_sample(&mut self, sample: HttpsSample, history_size: usize) {
        self.https_samples.push_back(sample);
        while self.https_samples.len() > history_size {
            self.https_samples.pop_front();
        }
    }

    fn rtt_p95(&self) -> Option<f64> {
        let mut rtts: Vec<f64> = self
            .health_samples
            .iter()
            .filter(|s| s.success)
            .filter_map(|s| s.rtt_ms)
            .collect();
        if rtts.is_empty() {
            return None;
        }
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = rtts.len();
        let p95_idx = ((n as f64) * 0.95).ceil() as usize;
        Some(rtts[p95_idx.saturating_sub(1).min(n - 1)])
    }

    fn availability(&self, window_secs: u64) -> f64 {
        let cutoff = Instant::now() - Duration::from_secs(window_secs);
        let recent: Vec<_> = self
            .health_samples
            .iter()
            .filter(|s| s.timestamp >= cutoff)
            .collect();
        if recent.is_empty() {
            return 0.0;
        }
        let successes = recent.iter().filter(|s| s.success).count();
        successes as f64 / recent.len() as f64
    }

    fn update_state(&mut self, total_targets: usize, failed_targets: usize) {
        self.prev_state = self.state;
        if total_targets > 0 && failed_targets >= total_targets {
            self.state = VpnState::Unhealthy;
            return;
        }
        if let Some(score) = self.ewma_score {
            self.state = if score >= 75.0 {
                VpnState::Healthy
            } else if score >= 40.0 {
                VpnState::Degraded
            } else {
                VpnState::Unhealthy
            };
        } else {
            self.state = determine_state(total_targets, failed_targets);
        }
    }

    fn state_changed(&self) -> bool {
        self.state != self.prev_state
    }

    fn compute_final_score(&self, sc: &ScoringConfig) -> Option<f64> {
        let fast = self.ewma_score?;
        let avail = self.availability(1800);
        Some(fast * sc.fast_weight + (avail * 100.0) * sc.historical_weight)
    }

    fn compute_score(&self, sc: &ScoringConfig) -> Option<f64> {
        let avail_5m = self.availability(300);
        let availability_score = avail_5m * 100.0;

        let latency_score = self.ewma_rtt.map(|rtt| {
            (100.0 * (1.0 - rtt / sc.latency_max_ms)).clamp(0.0, 100.0)
        }).unwrap_or(0.0);

        let loss_score = self.ewma_loss.map(|loss| (100.0 - loss).clamp(0.0, 100.0)).unwrap_or(0.0);

        let jitter_score = self.ewma_jitter.map(|jitter| {
            (100.0 * (1.0 - jitter / sc.jitter_max_ms)).clamp(0.0, 100.0)
        }).unwrap_or(0.0);

        let http_score = {
            let cutoff = Instant::now() - Duration::from_secs(300);
            let recent: Vec<_> = self.https_samples.iter().filter(|s| s.timestamp >= cutoff).collect();
            if recent.is_empty() {
                100.0
            } else {
                let successes = recent.iter().filter(|s| s.success).count();
                successes as f64 / recent.len() as f64 * 100.0
            }
        };

        Some((availability_score * sc.availability_weight
            + latency_score * sc.latency_weight
            + loss_score * sc.loss_weight
            + jitter_score * sc.jitter_weight
            + http_score * sc.http_weight).clamp(0.0, 100.0))
    }
}

fn parse_ping_output(stdout: &str) -> IcmpResult {
    let mut rtts: Vec<f64> = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.find("time=") {
            let part = &line[rest + 5..];
            if let Some(ms_end) = part.find(" ms") {
                if let Ok(ms) = part[..ms_end].parse::<f64>() {
                    rtts.push(ms);
                }
            }
        }
    }

    let mut loss_pct = if rtts.is_empty() { 100.0 } else { 0.0 };
    for line in stdout.lines() {
        if line.contains("packet loss") {
            if let Some(pct_start) = line.rfind("received, ") {
                let rest = &line[pct_start + 10..];
                if let Some(pct_end) = rest.find('%') {
                    if let Ok(pct) = rest[..pct_end].parse::<f64>() {
                        loss_pct = pct;
                    }
                }
            }
        }
    }

    let mut jitter_ms = 0.0;
    for line in stdout.lines() {
        if line.contains("mdev") || line.contains("round-trip") {
            if let Some(eq_pos) = line.find("= ") {
                let rest = &line[eq_pos + 2..];
                if let Some(ms_pos) = rest.find(" ms") {
                    let parts: Vec<&str> = rest[..ms_pos].split('/').collect();
                    if parts.len() >= 4 {
                        if let Ok(j) = parts[3].parse::<f64>() {
                            jitter_ms = j;
                        }
                    }
                }
            }
        }
    }

    let success = !rtts.is_empty() && loss_pct < 100.0;
    IcmpResult { success, rtts_ms: rtts, loss_pct, jitter_ms }
}

async fn icmp_probe(
    interface: &str,
    target: &str,
    count: u8,
    timeout_secs: u64,
) -> Result<IcmpResult> {
    let count_str = count.to_string();
    let timeout_str = timeout_secs.to_string();
    let output = Command::new("ping")
        .args(["-I", interface, "-c", &count_str, "-i", "0.2", "-W", &timeout_str, target])
        .output()
        .await
        .with_context(|| format!("ping -I {interface} -c {count_str} {target}"))?;
    Ok(parse_ping_output(&String::from_utf8_lossy(&output.stdout)))
}

pub(crate) async fn https_probe(interface: &str, url: &str, timeout_secs: u64) -> Result<HttpsResult> {
    let timeout_str = timeout_secs.to_string();
    let output = Command::new("curl")
        .args(["--interface", interface, "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", &timeout_str, url])
        .output()
        .await
        .with_context(|| format!("curl https probe via {interface}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let success = stdout.trim().parse::<u16>().ok().map(|c| (200..400).contains(&c)).unwrap_or(false);
    Ok(HttpsResult { success })
}

async fn quality_probe(interface: &str, url: &str, timeout_secs: u64) -> Result<QualityResult> {
    let timeout_str = timeout_secs.to_string();
    let output = Command::new("curl")
        .args(["--interface", interface, "-s", "-o", "/dev/null", "-w", "%{speed_download}", "--max-time", &timeout_str, url])
        .output()
        .await
        .with_context(|| format!("quality probe via {interface}"))?;
    if !output.status.success() {
        return Ok(QualityResult { success: false, mbps: 0.0 });
    }
    let bytes_per_sec: f64 = String::from_utf8_lossy(&output.stdout)
        .trim().parse().context("парсинг скорости из quality probe")?;
    Ok(QualityResult { success: true, mbps: bytes_per_sec * 8.0 / 1_000_000.0 })
}

pub(crate) struct Selector {
    config: SelectorConfig,
    active: Option<usize>,
    active_since: Option<Instant>,
    last_switch: Option<Instant>,
    candidate: Option<usize>,
    candidate_wins: u32,
}

impl Selector {
    pub(crate) fn new(config: SelectorConfig) -> Self {
        Self { config, active: None, active_since: None, last_switch: None, candidate: None, candidate_wins: 0 }
    }

    pub(crate) fn set_active(&mut self, idx: usize) {
        self.active = Some(idx);
        self.active_since = Some(Instant::now());
    }

    pub(crate) fn evaluate(&mut self, scores: &[(usize, &str, f64, VpnState)]) -> Option<SwitchDecision> {
        if !self.config.enabled || scores.is_empty() {
            return None;
        }

        if self.active.is_none() {
            if let Some(&(best_i, best_name, best_score, _)) = scores
                .iter()
                .filter(|(_, _, _, s)| *s != VpnState::Unhealthy)
                .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
            {
                self.active = Some(best_i);
                self.active_since = Some(Instant::now());
                info!(selected = best_name, score = format!("{:.1}", best_score), "selector: начальный выбор");
            }
            return None;
        }

        let active_idx = self.active.unwrap();
        let active_entry = scores.iter().find(|(i, _, _, _)| *i == active_idx);

        if let Some((_, _, _, state)) = active_entry {
            if *state == VpnState::Unhealthy {
                if let Some(&(best_i, best_name, best_score, _)) = scores
                    .iter()
                    .filter(|(i, _, _, s)| *i != active_idx && *s != VpnState::Unhealthy)
                    .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
                {
                    let decision = SwitchDecision {
                        from: active_idx, to: best_i,
                        from_name: scores[active_idx].1.to_string(), to_name: best_name.to_string(),
                        from_score: scores[active_idx].2, to_score: best_score,
                        reason: SwitchReason::EmergencyFailover,
                    };
                    self.active = Some(best_i);
                    self.active_since = Some(Instant::now());
                    self.last_switch = Some(Instant::now());
                    self.candidate = None;
                    self.candidate_wins = 0;
                    return Some(decision);
                } else {
                    info!("selector: нет здоровых кандидатов для failover");
                    return None;
                }
            }
        }

        let active_score = active_entry.map(|(_, _, s, _)| *s).unwrap_or(0.0);
        let active_name = active_entry.map(|(_, n, _, _)| *n).unwrap_or("?");

        if let Some(last) = self.last_switch {
            if last.elapsed().as_secs() < self.config.cooldown_secs { return None; }
        }
        if let Some(since) = self.active_since {
            if since.elapsed().as_secs() < self.config.minimum_hold_secs { return None; }
        }

        let candidate = scores
            .iter()
            .filter(|(i, _, _, s)| *i != active_idx && *s != VpnState::Unhealthy)
            .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
            .copied();

        let Some((cand_i, cand_name, cand_score, _)) = candidate else {
            self.candidate = None;
            self.candidate_wins = 0;
            return None;
        };

        let required = active_score * (1.0 + self.config.minimum_advantage);
        if cand_score < required {
            self.candidate = None;
            self.candidate_wins = 0;
            return None;
        }

        if self.candidate == Some(cand_i) {
            self.candidate_wins += 1;
        } else {
            self.candidate = Some(cand_i);
            self.candidate_wins = 1;
        }

        if self.candidate_wins >= self.config.consecutive_wins {
            let advantage_pct = if active_score > 0.0 { (cand_score / active_score - 1.0) * 100.0 } else { 100.0 };
            let decision = SwitchDecision {
                from: active_idx, to: cand_i,
                from_name: active_name.to_string(), to_name: cand_name.to_string(),
                from_score: active_score, to_score: cand_score,
                reason: SwitchReason::QualityAdvantage { consecutive_wins: self.candidate_wins, advantage_pct },
            };
            self.active = Some(cand_i);
            self.active_since = Some(Instant::now());
            self.last_switch = Some(Instant::now());
            self.candidate = None;
            self.candidate_wins = 0;
            Some(decision)
        } else {
            info!(
                current = active_name, current_score = format!("{:.1}", active_score),
                candidate = cand_name, candidate_score = format!("{:.1}", cand_score),
                wins = self.candidate_wins, required_wins = self.config.consecutive_wins,
                "selector: кандидат побеждает (ожидание consecutive wins)"
            );
            None
        }
    }
}

pub(crate) struct Monitor {
    config: MonitoringConfig,
    scoring_config: ScoringConfig,
    metrics: Vec<VpnMetrics>,
    selector: Selector,
}

impl Monitor {
    pub(crate) fn new(config: &Config) -> Self {
        let metrics = config.upstream.iter().filter(|u| u.enabled)
            .map(|u| VpnMetrics::new(&u.interface, &u.name, 1000)).collect();
        Self {
            config: config.monitoring.clone(),
            scoring_config: config.monitoring.scoring.clone(),
            metrics,
            selector: Selector::new(config.monitoring.selector.clone()),
        }
    }

    pub(crate) fn set_selector_active(&mut self, idx: usize) { self.selector.set_active(idx); }
    pub(crate) fn prometheus_port(&self) -> u16 { self.config.prometheus_port }
    pub(crate) fn prometheus_enabled(&self) -> bool { self.config.prometheus_enabled }
    pub(crate) fn health_interval_secs(&self) -> u64 { self.config.health_interval }

    pub(crate) fn snapshot(&self, active_idx: Option<usize>) -> Vec<VpnSnapshot> {
        self.metrics.iter().enumerate().map(|(i, m)| VpnSnapshot {
            name: m.name.clone(), state: m.state,
            score: m.compute_final_score(&self.scoring_config),
            ewma_rtt: m.ewma_rtt, ewma_loss: m.ewma_loss, ewma_jitter: m.ewma_jitter,
            availability_5m: m.availability(300), rtt_p95: m.rtt_p95(),
            https_success_ratio: https_ratio(m), quality_mbps: m.quality_mbps,
            consecutive_failures: m.consecutive_failures, selected: Some(i) == active_idx,
        }).collect()
    }

    pub(crate) async fn probe_cycle(
        &mut self,
        last_https: &mut Option<Instant>,
        last_quality: &mut Option<Instant>,
    ) -> Option<SwitchDecision> {
        let decision = self.run_health_probes().await;

        if self.config.https_enabled {
            let due = last_https.map(|t| t.elapsed() >= Duration::from_secs(self.config.https_interval)).unwrap_or(true);
            if due { self.run_https_probes().await; *last_https = Some(Instant::now()); }
        }
        if self.config.quality_enabled {
            let due = last_quality.map(|t| t.elapsed() >= Duration::from_secs(self.config.quality_interval)).unwrap_or(true);
            if due { self.run_quality_probes().await; *last_quality = Some(Instant::now()); }
        }
        decision
    }

    async fn run_health_probes(&mut self) -> Option<SwitchDecision> {
        let targets = self.config.health_targets.clone();
        let alpha = self.config.ewma_alpha;
        let history_size = self.config.history_size;
        let probe_count = self.config.health_probe_count;
        let timeout = self.config.health_timeout;
        let sc = self.scoring_config.clone();

        for vpn in &mut self.metrics {
            let mut failed_targets = 0;
            for target in &targets {
                match icmp_probe(&vpn.interface, target, probe_count, timeout).await {
                    Ok(result) => {
                        let sample = HealthSample {
                            timestamp: Instant::now(), success: result.success,
                            rtt_ms: result.rtts_ms.last().copied(),
                            loss_pct: Some(result.loss_pct), jitter_ms: Some(result.jitter_ms),
                        };
                        if !result.success || result.loss_pct > 5.0 {
                            warn!(vpn = %vpn.name, interface = %vpn.interface, target = target,
                                  success = result.success, loss_pct = format!("{:.1}", result.loss_pct),
                                  "health probe anomaly");
                        }
                        vpn.add_health_sample(sample, alpha, history_size);
                        if !result.success { failed_targets += 1; }
                    }
                    Err(e) => {
                        warn!(vpn = %vpn.name, interface = %vpn.interface, target = target, error = %e, "health probe error");
                        failed_targets += 1;
                    }
                }
            }

            let score = vpn.compute_score(&sc);
            if let Some(s) = score {
                vpn.ewma_score = Some(match vpn.ewma_score {
                    Some(prev) => s * alpha + prev * (1.0 - alpha), None => s,
                });
            }
            vpn.update_state(targets.len(), failed_targets);

            if vpn.state_changed() {
                info!(vpn = %vpn.name, interface = %vpn.interface,
                      old_state = %vpn.prev_state, new_state = %vpn.state,
                      score = vpn.ewma_score.map(|v| format!("{:.1}", v)).unwrap_or_else(|| "n/a".to_string()),
                      consecutive_failures = vpn.consecutive_failures, "vpn state changed");
            }
            if let Some(loss) = vpn.ewma_loss {
                if loss > 10.0 {
                    warn!(vpn = %vpn.name, interface = %vpn.interface, ewma_loss_pct = format!("{:.1}", loss), "packet loss exceeded threshold");
                }
            }
        }

        let scores: Vec<(usize, &str, f64, VpnState)> = self.metrics.iter().enumerate()
            .map(|(i, m)| {
                let score = m.compute_final_score(&self.scoring_config).unwrap_or(m.ewma_score.unwrap_or(0.0));
                (i, m.name.as_str(), score, m.state)
            }).collect();
        self.selector.evaluate(&scores)
    }

    async fn run_https_probes(&mut self) {
        let targets = self.config.https_targets.clone();
        let timeout = self.config.https_timeout;
        let history_size = self.config.history_size;
        for vpn in &mut self.metrics {
            for target in &targets {
                match https_probe(&vpn.interface, target, timeout).await {
                    Ok(result) => {
                        if !result.success {
                            warn!(vpn = %vpn.name, interface = %vpn.interface, target = target, "https probe failed");
                        }
                        vpn.add_https_sample(HttpsSample { timestamp: Instant::now(), success: result.success }, history_size);
                    }
                    Err(e) => {
                        warn!(vpn = %vpn.name, interface = %vpn.interface, target = target, error = %e, "https probe error");
                    }
                }
            }
        }
    }

    async fn run_quality_probes(&mut self) {
        let url = self.config.quality_url.clone();
        let timeout = self.config.quality_timeout;
        for vpn in &mut self.metrics {
            match quality_probe(&vpn.interface, &url, timeout).await {
                Ok(result) if result.success => {
                    vpn.quality_mbps = Some(result.mbps);
                    info!(vpn = %vpn.name, interface = %vpn.interface, quality_mbps = format!("{:.2}", result.mbps), "quality probe");
                }
                Ok(_) => { warn!(vpn = %vpn.name, interface = %vpn.interface, "quality probe failed"); }
                Err(e) => { warn!(vpn = %vpn.name, interface = %vpn.interface, error = %e, "quality probe error"); }
            }
        }
    }
}

fn https_ratio(m: &VpnMetrics) -> Option<f64> {
    let cutoff = Instant::now() - Duration::from_secs(300);
    let recent: Vec<_> = m.https_samples.iter().filter(|s| s.timestamp >= cutoff).collect();
    if recent.is_empty() { return None; }
    Some(recent.iter().filter(|s| s.success).count() as f64 / recent.len() as f64)
}

pub async fn serve_prometheus(shared: SharedMetrics, port: u16) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    let listener = match TcpListener::bind(format!("0.0.0.0:{port}")).await {
        Ok(l) => l,
        Err(e) => { tracing::error!(error = %e, port, "не удалось запустить Prometheus server"); return; }
    };
    tracing::info!(port, "Prometheus metrics server запущен");
    loop {
        let (mut socket, _) = match listener.accept().await { Ok(c) => c, Err(_) => continue };
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let body = format_prometheus(&shared);
            let _ = socket.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                body.len(), body
            ).as_bytes()).await;
        });
    }
}

fn format_prometheus(shared: &SharedMetrics) -> String {
    let snapshots = shared.lock().unwrap();
    let mut out = String::new();
    for (name, help, mtype, fmt) in METRIC_DEFS {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {mtype}\n"));
        for s in snapshots.iter() {
            if let Some(val) = fmt(s) {
                out.push_str(&format!("{name}{{vpn=\"{}\"}} {val}\n", s.name));
            }
        }
        out.push('\n');
    }
    out
}

type MetricFmt = fn(&VpnSnapshot) -> Option<String>;

const METRIC_DEFS: &[(&str, &str, &str, MetricFmt)] = &[
    ("vpn_up", "VPN interface is up (1) or down (0)", "gauge", |s| {
        Some(if s.state == VpnState::Unhealthy { "0".into() } else { "1".into() })
    }),
    ("vpn_score", "FastScore (0-100)", "gauge", |s| s.score.map(|v| format!("{:.1}", v))),
    ("vpn_latency_ms", "EWMA latency in ms", "gauge", |s| s.ewma_rtt.map(|v| format!("{:.1}", v))),
    ("vpn_latency_p95_ms", "p95 latency in ms", "gauge", |s| s.rtt_p95.map(|v| format!("{:.1}", v))),
    ("vpn_jitter_ms", "EWMA jitter in ms", "gauge", |s| s.ewma_jitter.map(|v| format!("{:.2}", v))),
    ("vpn_packet_loss_ratio", "EWMA packet loss ratio (0-100)", "gauge", |s| s.ewma_loss.map(|v| format!("{:.1}", v))),
    ("vpn_availability_5m", "Availability ratio last 5 min (0-1)", "gauge", |s| Some(format!("{:.3}", s.availability_5m))),
    ("vpn_http_success_ratio", "HTTPS success ratio last 5 min (0-1)", "gauge", |s| s.https_success_ratio.map(|v| format!("{:.3}", v))),
    ("vpn_quality_mbps", "Quality probe throughput in Mbps", "gauge", |s| s.quality_mbps.map(|v| format!("{:.2}", v))),
    ("vpn_selected", "Currently selected VPN (1) or not (0)", "gauge", |s| Some(if s.selected { "1".into() } else { "0".into() })),
    ("vpn_consecutive_failures", "Consecutive health check failures", "gauge", |s| Some(s.consecutive_failures.to_string())),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ping_success() {
        let output = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n\
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=15.2 ms\n\
64 bytes from 1.1.1.1: icmp_seq=2 ttl=58 time=14.8 ms\n\
64 bytes from 1.1.1.1: icmp_seq=3 ttl=58 time=15.5 ms\n\
64 bytes from 1.1.1.1: icmp_seq=4 ttl=58 time=15.1 ms\n\
64 bytes from 1.1.1.1: icmp_seq=5 ttl=58 time=14.9 ms\n\n\
--- 1.1.1.1 ping statistics ---\n\
5 packets transmitted, 5 received, 0% packet loss\n\
rtt min/avg/max/mdev = 14.8/15.1/15.5/0.243 ms\n";
        let r = parse_ping_output(output);
        assert!(r.success);
        assert_eq!(r.rtts_ms.len(), 5);
        assert!((r.loss_pct - 0.0).abs() < 0.01);
        assert!((r.jitter_ms - 0.243).abs() < 0.001);
    }

    #[test]
    fn parse_ping_all_failed() {
        let output = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n\n\
--- 1.1.1.1 ping statistics ---\n\
5 packets transmitted, 0 received, 100% packet loss\n";
        let r = parse_ping_output(output);
        assert!(!r.success);
        assert!(r.rtts_ms.is_empty());
        assert!((r.loss_pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn parse_ping_partial_loss() {
        let output = "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n\
64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=15.2 ms\n\
64 bytes from 1.1.1.1: icmp_seq=3 ttl=58 time=15.5 ms\n\n\
--- 1.1.1.1 ping statistics ---\n\
5 packets transmitted, 2 received, 60% packet loss\n\
rtt min/avg/max/mdev = 15.2/15.35/15.5/0.150 ms\n";
        let r = parse_ping_output(output);
        assert!(r.success);
        assert_eq!(r.rtts_ms.len(), 2);
        assert!((r.loss_pct - 60.0).abs() < 0.01);
    }

    #[test]
    fn state_determination() {
        assert_eq!(determine_state(3, 0), VpnState::Healthy);
        assert_eq!(determine_state(3, 1), VpnState::Healthy);
        assert_eq!(determine_state(3, 2), VpnState::Degraded);
        assert_eq!(determine_state(3, 3), VpnState::Unhealthy);
        assert_eq!(determine_state(0, 0), VpnState::Unknown);
    }

    #[test]
    fn ewma_smoothing() {
        let mut m = VpnMetrics::new("wg0", "test", 100);
        let alpha = 0.2;
        m.add_health_sample(HealthSample {
            timestamp: Instant::now(), success: true, rtt_ms: Some(10.0),
            loss_pct: Some(0.0), jitter_ms: Some(1.0),
        }, alpha, 100);
        assert!((m.ewma_rtt.unwrap() - 10.0).abs() < 0.01);
        m.add_health_sample(HealthSample {
            timestamp: Instant::now(), success: true, rtt_ms: Some(20.0),
            loss_pct: Some(0.0), jitter_ms: Some(2.0),
        }, alpha, 100);
        assert!((m.ewma_rtt.unwrap() - 12.0).abs() < 0.01);
    }

    #[test]
    fn rtt_p95_test() {
        let mut m = VpnMetrics::new("wg0", "test", 100);
        for i in 0..20 {
            m.add_health_sample(HealthSample {
                timestamp: Instant::now(), success: true, rtt_ms: Some((i + 1) as f64),
                loss_pct: Some(0.0), jitter_ms: Some(0.5),
            }, 0.2, 100);
        }
        let p95 = m.rtt_p95().unwrap();
        assert!(p95 >= 19.0 && p95 <= 20.0, "p95={p95}");
    }

    #[test]
    fn score_healthy_vpn() {
        let mut m = VpnMetrics::new("wg0", "test", 100);
        for _ in 0..10 {
            m.add_health_sample(HealthSample {
                timestamp: Instant::now(), success: true, rtt_ms: Some(15.0),
                loss_pct: Some(0.0), jitter_ms: Some(1.0),
            }, 0.2, 100);
        }
        let sc = ScoringConfig::default();
        let score = m.compute_score(&sc).unwrap();
        assert!(score > 95.0, "expected score > 95, got {score}");
    }

    #[test]
    fn score_degraded_vpn() {
        let mut m = VpnMetrics::new("wg1", "test", 100);
        for _ in 0..10 {
            m.add_health_sample(HealthSample {
                timestamp: Instant::now(), success: true, rtt_ms: Some(300.0),
                loss_pct: Some(20.0), jitter_ms: Some(10.0),
            }, 0.2, 100);
        }
        let sc = ScoringConfig::default();
        let score = m.compute_score(&sc).unwrap();
        assert!(score < 80.0, "got {score}");
        assert!(score > 60.0, "got {score}");
    }

    #[test]
    fn score_unhealthy_vpn() {
        let mut m = VpnMetrics::new("wg2", "test", 100);
        for _ in 0..10 {
            m.add_health_sample(HealthSample {
                timestamp: Instant::now(), success: false, rtt_ms: None,
                loss_pct: Some(100.0), jitter_ms: None,
            }, 0.2, 100);
        }
        let sc = ScoringConfig::default();
        let score = m.compute_score(&sc).unwrap();
        assert!(score < 20.0, "got {score}");
    }

    #[test]
    fn selector_initial_pick() {
        let mut sel = Selector::new(SelectorConfig {
            enabled: true, minimum_advantage: 0.10, consecutive_wins: 3,
            minimum_hold_secs: 0, cooldown_secs: 0,
        });
        let scores = vec![(0usize, "wg0", 70.0, VpnState::Healthy), (1usize, "wg1", 90.0, VpnState::Healthy)];
        assert!(sel.evaluate(&scores).is_none());
        assert_eq!(sel.active, Some(1));
    }

    #[test]
    fn selector_hysteresis() {
        let mut sel = Selector::new(SelectorConfig {
            enabled: true, minimum_advantage: 0.10, consecutive_wins: 1,
            minimum_hold_secs: 0, cooldown_secs: 0,
        });
        sel.evaluate(&[(0, "wg0", 91.0, VpnState::Healthy), (1, "wg1", 88.0, VpnState::Healthy)]);
        assert_eq!(sel.active, Some(0));
        assert!(sel.evaluate(&[(0, "wg0", 91.0, VpnState::Healthy), (1, "wg1", 93.0, VpnState::Healthy)]).is_none());
        assert_eq!(sel.active, Some(0));
    }

    #[test]
    fn selector_consecutive_wins() {
        let mut sel = Selector::new(SelectorConfig {
            enabled: true, minimum_advantage: 0.10, consecutive_wins: 3,
            minimum_hold_secs: 0, cooldown_secs: 0,
        });
        sel.evaluate(&[(0, "wg0", 70.0, VpnState::Healthy), (1, "wg1", 90.0, VpnState::Healthy)]);
        assert_eq!(sel.active, Some(1));
        let scores = [(0, "wg0", 95.0, VpnState::Healthy), (1, "wg1", 70.0, VpnState::Healthy)];
        assert!(sel.evaluate(&scores).is_none());
        assert!(sel.evaluate(&scores).is_none());
        assert!(sel.evaluate(&scores).is_some());
        assert_eq!(sel.active, Some(0));
    }

    #[test]
    fn selector_failover_on_unhealthy() {
        let mut sel = Selector::new(SelectorConfig {
            enabled: true, minimum_advantage: 0.10, consecutive_wins: 3,
            minimum_hold_secs: 0, cooldown_secs: 60,
        });
        sel.evaluate(&[(0, "wg0", 90.0, VpnState::Healthy), (1, "wg1", 70.0, VpnState::Healthy)]);
        assert_eq!(sel.active, Some(0));
        let d = sel.evaluate(&[(0, "wg0", 0.0, VpnState::Unhealthy), (1, "wg1", 70.0, VpnState::Healthy)]);
        assert!(d.is_some());
        assert_eq!(sel.active, Some(1));
        assert!(matches!(d.unwrap().reason, SwitchReason::EmergencyFailover));
    }
}
