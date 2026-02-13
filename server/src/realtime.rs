use chrono::{DateTime, Utc};
use percepta_server::alerts::Alert;
use percepta_server::percepta::Event;
use percepta_server::time_utils;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize)]
pub struct BaselineSnapshot {
    pub now_unix: i64,
    pub tau_secs: u64,
    pub agent_id: Option<String>,

    pub top_users: Vec<(String, f64)>,
    pub top_processes: Vec<(String, f64)>,
    pub top_sources: Vec<(String, f64)>,
    pub top_event_ids: Vec<(String, f64)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertRtEnvelope {
    pub seq: u64,
    pub at: DateTime<Utc>,
    pub alert: Alert,
}

#[derive(Debug)]
pub struct AlertJournal {
    next_seq: u64,
    entries: VecDeque<AlertRtEnvelope>,
    max_keep: usize,
}

impl AlertJournal {
    pub fn new(max_keep: usize) -> Self {
        Self {
            next_seq: 1,
            entries: VecDeque::new(),
            max_keep: max_keep.max(100),
        }
    }

    pub fn push(&mut self, alert: Alert) -> AlertRtEnvelope {
        let env = AlertRtEnvelope {
            seq: self.next_seq,
            at: Utc::now(),
            alert,
        };
        self.next_seq = self.next_seq.saturating_add(1);
        self.entries.push_back(env.clone());
        while self.entries.len() > self.max_keep {
            self.entries.pop_front();
        }
        env
    }

    #[allow(dead_code)]
    pub fn latest_seq(&self) -> u64 {
        self.entries.back().map(|e| e.seq).unwrap_or(0)
    }

    pub fn since(&self, seq_exclusive: u64) -> Vec<AlertRtEnvelope> {
        // The journal is already bounded, so this is cheap.
        self.entries
            .iter()
            .filter(|e| e.seq > seq_exclusive)
            .cloned()
            .collect()
    }

    pub fn tail(&self, max: usize) -> Vec<AlertRtEnvelope> {
        let take = max.min(self.entries.len());
        self.entries
            .iter()
            .skip(self.entries.len().saturating_sub(take))
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EventHeader {
    pub hash: String,
    pub ingest_unix: i64,
    pub severity: i32,
    pub category: String,
    pub summary: String,
    pub agent_id: String,
    pub agent_display_name: String,
    pub agent_hostname: String,
    pub agent_ip: String,
    pub user_name: String,
    pub user_domain: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub sensor_kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TelemetrySnapshot {
    pub version: u64,
    pub now_unix: i64,

    // One-second resolution over the ring window.
    pub window_secs: usize,
    pub series_total: Vec<u32>,
    pub series_high: Vec<u32>,
    pub series_critical: Vec<u32>,
    pub series_alerts: Vec<u32>,

    // Top-K boards.
    pub top_agents: Vec<(String, u32)>,
    pub top_sources: Vec<(String, u32)>,
    pub top_signatures: Vec<(String, u32)>,

    // Recent samples (bounded).
    pub recent: Vec<EventHeader>,
}

#[derive(Debug)]
struct BoundedCounter {
    max_keys: usize,
    // key -> (count, last_seen_unix)
    map: HashMap<String, (u32, i64)>,
}

#[derive(Debug, Clone)]
struct EwmaEntry {
    value: f64,
    last_unix: i64,
}

#[derive(Debug)]
struct BaselineStore {
    tau_secs: f64,
    max_keys: usize,
    // key -> decayed count since last update
    map: HashMap<String, EwmaEntry>,
}

impl BaselineStore {
    fn new(max_keys: usize, tau_secs: u64) -> Self {
        let tau_secs = (tau_secs as f64).clamp(60.0, 24.0 * 60.0 * 60.0);
        Self {
            tau_secs,
            max_keys: max_keys.max(500),
            map: HashMap::new(),
        }
    }

    fn decayed_value_at_tau(tau_secs: f64, entry: &EwmaEntry, now_unix: i64) -> f64 {
        let dt = (now_unix - entry.last_unix).max(0) as f64;
        if dt <= 0.0 {
            return entry.value;
        }
        let decay = (-dt / tau_secs).exp();
        entry.value * decay
    }

    fn decayed_value_at(&self, entry: &EwmaEntry, now_unix: i64) -> f64 {
        Self::decayed_value_at_tau(self.tau_secs, entry, now_unix)
    }

    fn bump(&mut self, key: &str, now_unix: i64, n: u32) {
        let key = key.trim();
        if key.is_empty() || n == 0 {
            return;
        }

        let tau_secs = self.tau_secs;
        let entry = self.map.entry(key.to_string()).or_insert(EwmaEntry {
            value: 0.0,
            last_unix: now_unix,
        });

        // Apply decay from last update to now (avoid borrowing self while entry is mutably borrowed).
        entry.value = Self::decayed_value_at_tau(tau_secs, entry, now_unix) + (n as f64);
        entry.last_unix = now_unix;

        if self.map.len() > self.max_keys {
            self.prune(now_unix);
        }
    }

    fn prune(&mut self, now_unix: i64) {
        if self.map.len() <= self.max_keys {
            return;
        }

        // Drop very stale, near-zero entries first.
        let tau_secs = self.tau_secs;
        let stale_cutoff = now_unix.saturating_sub((tau_secs * 10.0) as i64);
        self.map.retain(|_, v| {
            if v.last_unix < stale_cutoff {
                return BaselineStore::decayed_value_at_tau(tau_secs, v, now_unix) >= 0.01;
            }
            true
        });

        if self.map.len() <= self.max_keys {
            return;
        }

        // Evict lowest-decayed-value keys first; break ties by oldest last_seen.
        let mut items: Vec<(String, f64, i64)> = self
            .map
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    BaselineStore::decayed_value_at_tau(tau_secs, v, now_unix),
                    v.last_unix,
                )
            })
            .collect();

        items.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.2.cmp(&b.2))
        });
        let over = self.map.len().saturating_sub(self.max_keys);
        for (k, _, _) in items.into_iter().take(over) {
            self.map.remove(&k);
        }
    }

    fn top_k_by_prefix(&self, prefix: &str, now_unix: i64, k: usize) -> Vec<(String, f64)> {
        let mut v: Vec<(String, f64)> = self
            .map
            .iter()
            .filter_map(|(key, entry)| {
                if key.starts_with(prefix) {
                    let dv = self.decayed_value_at(entry, now_unix);
                    if dv.is_finite() && dv > 0.0 {
                        // Trim the prefix for display.
                        if let Some(stripped) = key.strip_prefix(prefix) {
                            return Some((stripped.to_string(), dv));
                        }
                    }
                }
                None
            })
            .collect();

        v.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        v.truncate(k);
        v
    }
}

impl BoundedCounter {
    fn new(max_keys: usize) -> Self {
        Self {
            max_keys: max_keys.max(100),
            map: HashMap::new(),
        }
    }

    fn bump(&mut self, key: &str, now_unix: i64, n: u32) {
        if key.is_empty() {
            return;
        }
        let entry = self.map.entry(key.to_string()).or_insert((0, now_unix));
        entry.0 = entry.0.saturating_add(n);
        entry.1 = now_unix;

        if self.map.len() > self.max_keys {
            self.prune();
        }
    }

    fn prune(&mut self) {
        if self.map.len() <= self.max_keys {
            return;
        }

        // Evict lowest-count keys first; break ties by oldest last_seen.
        let mut items: Vec<(String, u32, i64)> = self
            .map
            .iter()
            .map(|(k, (c, t))| (k.clone(), *c, *t))
            .collect();

        items.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.2.cmp(&b.2)));
        let over = self.map.len().saturating_sub(self.max_keys);
        for (k, _, _) in items.into_iter().take(over) {
            self.map.remove(&k);
        }
    }

    fn top_k(&self, k: usize) -> Vec<(String, u32)> {
        let mut v: Vec<(String, u32)> =
            self.map.iter().map(|(k, (c, _))| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(k);
        v
    }
}

#[derive(Debug)]
pub struct RealtimeAnalytics {
    version: u64,
    window_secs: usize,
    // The ring is aligned to epoch seconds. We store the start second.
    start_unix: i64,
    total: Vec<u32>,
    high: Vec<u32>,
    critical: Vec<u32>,
    alerts: Vec<u32>,

    top_agents: BoundedCounter,
    top_sources: BoundedCounter,
    top_signatures: BoundedCounter,

    recent: VecDeque<EventHeader>,
    recent_max: usize,

    baseline: BaselineStore,
}

impl RealtimeAnalytics {
    pub fn new(window_secs: usize, recent_max: usize) -> Self {
        let window_secs = window_secs.clamp(30, 600);
        let now = Utc::now().timestamp();
        Self {
            version: 1,
            window_secs,
            start_unix: now - window_secs as i64 + 1,
            total: vec![0; window_secs],
            high: vec![0; window_secs],
            critical: vec![0; window_secs],
            alerts: vec![0; window_secs],
            top_agents: BoundedCounter::new(5000),
            top_sources: BoundedCounter::new(5000),
            top_signatures: BoundedCounter::new(5000),
            recent: VecDeque::new(),
            recent_max: recent_max.clamp(50, 500),

            // Baseline is intentionally more permissive in size but still bounded.
            // Tau controls how quickly "normal" adapts; 30 minutes is a practical default.
            baseline: BaselineStore::new(50_000, 30 * 60),
        }
    }

    fn bump_version(&mut self) {
        self.version = self.version.saturating_add(1);
    }

    fn rotate_to(&mut self, now_unix: i64) {
        let desired_start = now_unix - self.window_secs as i64 + 1;
        if desired_start <= self.start_unix {
            return;
        }

        let shift = (desired_start - self.start_unix) as usize;
        if shift >= self.window_secs {
            self.total.fill(0);
            self.high.fill(0);
            self.critical.fill(0);
            self.alerts.fill(0);
            self.start_unix = desired_start;
            return;
        }

        // Slide ring left by shift.
        self.total.rotate_left(shift);
        self.high.rotate_left(shift);
        self.critical.rotate_left(shift);
        self.alerts.rotate_left(shift);

        for i in (self.window_secs - shift)..self.window_secs {
            self.total[i] = 0;
            self.high[i] = 0;
            self.critical[i] = 0;
            self.alerts[i] = 0;
        }

        self.start_unix = desired_start;
    }

    fn idx(&self, unix: i64) -> Option<usize> {
        if unix < self.start_unix {
            return None;
        }
        let i = (unix - self.start_unix) as usize;
        if i >= self.window_secs {
            return None;
        }
        Some(i)
    }

    pub fn observe_event(&mut self, event: &Event) {
        let now_unix = time_utils::now_unix();
        self.rotate_to(now_unix);

        // Clamp event timestamp to at most 60 seconds in the future to
        // prevent a malicious/skewed event from wiping the ring buffer.
        // Use centralized validation to ensure consistency across all components.
        let raw_t = event
            .ingest_time
            .as_ref()
            .map(|ts| ts.seconds)
            .unwrap_or(now_unix);
        let t = time_utils::validate_and_clamp_event_time(Some(raw_t));
        if t > now_unix {
            // Guard against clock skew by using canonical server time.
            self.rotate_to(t);
        }

        if let Some(i) = self.idx(t) {
            self.total[i] = self.total[i].saturating_add(1);

            let sev = event.event.as_ref().map(|e| e.severity).unwrap_or(0);
            if sev >= 3 {
                self.high[i] = self.high[i].saturating_add(1);
            }
            if sev >= 4 {
                self.critical[i] = self.critical[i].saturating_add(1);
            }
        }

        let agent_id = event
            .agent
            .as_ref()
            .map(|a| a.id.clone())
            .unwrap_or_default();
        let src_ip = event
            .network
            .as_ref()
            .map(|n| n.src_ip.clone())
            .unwrap_or_default();

        self.top_agents.bump(&agent_id, now_unix, 1);
        self.top_sources.bump(&src_ip, now_unix, 1);

        let sig = event
            .metadata
            .get("ids.signature")
            .or_else(|| event.metadata.get("suricata.signature"))
            .cloned()
            .unwrap_or_default();
        if !sig.is_empty() {
            self.top_signatures.bump(&sig, now_unix, 1);
        }

        // --- Adaptive baselines (decayed counts) ---
        // These are used only for operator/allowlist tuning and should remain cheap & bounded.
        let agent_scope = if agent_id.trim().is_empty() {
            "agent:<unknown>".to_string()
        } else {
            format!("agent:{}", agent_id.trim())
        };

        let user_name = event
            .user
            .as_ref()
            .map(|u| u.name.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                event
                    .metadata
                    .get("norm.user")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_default();

        let proc_name = event
            .process
            .as_ref()
            .map(|p| p.name.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_default();

        let eid = event
            .event
            .as_ref()
            .map(|e| e.event_id)
            .filter(|x| *x != 0)
            .or_else(|| {
                event
                    .metadata
                    .get("winlog.event_id")
                    .and_then(|s| s.trim().parse::<u64>().ok())
            })
            .unwrap_or(0);

        if !user_name.is_empty() {
            self.baseline
                .bump(&format!("{}|user:{}", agent_scope, user_name), now_unix, 1);
        }
        if !proc_name.is_empty() {
            self.baseline.bump(
                &format!("{}|process:{}", agent_scope, proc_name),
                now_unix,
                1,
            );
        }
        if !src_ip.trim().is_empty() {
            self.baseline.bump(
                &format!("{}|src_ip:{}", agent_scope, src_ip.trim()),
                now_unix,
                1,
            );
        }
        if eid != 0 {
            self.baseline
                .bump(&format!("{}|event_id:{}", agent_scope, eid), now_unix, 1);
        }

        // Recent sample header.
        let hash = event.hash.clone();
        if !hash.is_empty() {
            let (category, summary, severity) = match event.event.as_ref() {
                Some(ed) => {
                    let cat =
                        percepta_server::percepta::event::EventCategory::try_from(ed.category)
                            .ok()
                            .map(|c| c.as_str_name().to_string())
                            .unwrap_or_default();
                    let sum = ed.summary.clone();
                    (cat, sum, ed.severity)
                }
                None => (String::new(), String::new(), 0),
            };

            let agent_ip = event
                .agent
                .as_ref()
                .map(|a| a.ip.clone())
                .unwrap_or_default();
            let dst_ip = event
                .network
                .as_ref()
                .map(|n| n.dst_ip.clone())
                .unwrap_or_default();
            let sensor_kind = event
                .metadata
                .get("sensor.kind")
                .cloned()
                .unwrap_or_default();

            let agent_hostname = event
                .agent
                .as_ref()
                .map(|a| a.hostname.clone())
                .unwrap_or_default();
            let agent_display_name = event
                .metadata
                .get("agent.display_name")
                .cloned()
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    event
                        .metadata
                        .get("host.hostname")
                        .cloned()
                        .filter(|s| !s.trim().is_empty())
                })
                .or_else(|| {
                    if !agent_hostname.trim().is_empty() {
                        Some(agent_hostname.clone())
                    } else if !agent_id.trim().is_empty() {
                        Some(agent_id.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_default();

            let (mut user_name, mut user_domain) = event
                .user
                .as_ref()
                .map(|u| (u.name.clone(), u.domain.clone()))
                .unwrap_or_default();
            if user_name.trim().is_empty() {
                user_name = event.metadata.get("norm.user").cloned().unwrap_or_default();
            }
            if user_domain.trim().is_empty() {
                user_domain = event
                    .metadata
                    .get("norm.user_domain")
                    .cloned()
                    .unwrap_or_default();
            }
            let user_name = user_name.trim().to_string();
            let user_domain = user_domain.trim().to_string();

            self.recent.push_front(EventHeader {
                hash,
                ingest_unix: t,
                severity,
                category,
                summary,
                agent_id,
                agent_display_name,
                agent_hostname,
                agent_ip,
                user_name,
                user_domain,
                src_ip,
                dst_ip,
                sensor_kind,
            });
            while self.recent.len() > self.recent_max {
                self.recent.pop_back();
            }
        }

        self.bump_version();
    }

    pub fn baseline_snapshot(&mut self, agent_id: Option<&str>, top_k: usize) -> BaselineSnapshot {
        let now_unix = Utc::now().timestamp();
        let top_k = top_k.clamp(1, 200);

        let agent_prefix = agent_id
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|aid| format!("agent:{}|", aid));

        let prefix = agent_prefix.as_deref().unwrap_or("");

        BaselineSnapshot {
            now_unix,
            tau_secs: self.baseline.tau_secs.round() as u64,
            agent_id: agent_id.map(|s| s.to_string()),
            top_users: self
                .baseline
                .top_k_by_prefix(&format!("{}user:", prefix), now_unix, top_k),
            top_processes: self.baseline.top_k_by_prefix(
                &format!("{}process:", prefix),
                now_unix,
                top_k,
            ),
            top_sources: self.baseline.top_k_by_prefix(
                &format!("{}src_ip:", prefix),
                now_unix,
                top_k,
            ),
            top_event_ids: self.baseline.top_k_by_prefix(
                &format!("{}event_id:", prefix),
                now_unix,
                top_k,
            ),
        }
    }

    pub fn observe_alert(&mut self) {
        let now_unix = Utc::now().timestamp();
        self.rotate_to(now_unix);
        if let Some(i) = self.idx(now_unix) {
            self.alerts[i] = self.alerts[i].saturating_add(1);
        }
        self.bump_version();
    }

    pub fn snapshot(&mut self, top_k: usize) -> TelemetrySnapshot {
        let now_unix = Utc::now().timestamp();
        self.rotate_to(now_unix);

        TelemetrySnapshot {
            version: self.version,
            now_unix,
            window_secs: self.window_secs,
            series_total: self.total.clone(),
            series_high: self.high.clone(),
            series_critical: self.critical.clone(),
            series_alerts: self.alerts.clone(),
            top_agents: self.top_agents.top_k(top_k),
            top_sources: self.top_sources.top_k(top_k),
            top_signatures: self.top_signatures.top_k(top_k),
            recent: self.recent.iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_store_is_bounded() {
        let now = 1_700_000_000i64;
        let mut s = BaselineStore::new(500, 60);
        for i in 0..10_000u32 {
            s.bump(&format!("agent:a|user:u{}", i), now, 1);
        }
        assert!(s.map.len() <= 500);
    }

    #[test]
    fn baseline_decay_reduces_value_over_time() {
        let mut s = BaselineStore::new(1000, 60);
        let t0 = 1_700_000_000i64;
        s.bump("agent:a|user:alice", t0, 10);
        let v0 = s
            .map
            .get("agent:a|user:alice")
            .map(|e| s.decayed_value_at(e, t0))
            .unwrap_or(0.0);
        let v1 = s
            .map
            .get("agent:a|user:alice")
            .map(|e| s.decayed_value_at(e, t0 + 60))
            .unwrap_or(0.0);
        assert!(v0 > v1);
        assert!(v1 > 0.0);
    }
}
