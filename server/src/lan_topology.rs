use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use percepta_server::percepta::Event;

#[derive(Clone, Debug, Serialize)]
pub struct LanAgentNode {
    pub agent_id: String,
    pub hostname: String,
    pub ip: String,
    pub mac: String,
    #[serde(default)]
    pub last_user: String,
    pub last_seen_unix: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct LanDeviceNode {
    pub ip: String,
    pub mac: String,
    pub last_seen_unix: i64,
    pub seen_by_agents: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LanTopologySnapshot {
    pub server_host: String,
    pub server_ip: String,
    pub gateway_ip: String,
    pub agents: Vec<LanAgentNode>,
    pub devices: Vec<LanDeviceNode>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LanPersistenceStatus {
    pub enabled: bool,
    pub path: Option<String>,
    pub persist_interval_secs: i64,
    pub last_persist_unix: Option<i64>,
    pub last_restore_unix: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
struct LanSnapshotPayload {
    #[serde(default)]
    entries: Vec<LanNeighbor>,
}

#[derive(Debug, Clone, Deserialize)]
struct LanNeighbor {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    mac: String,
}

#[derive(Debug, Clone)]
struct AgentState {
    hostname: String,
    ip: String,
    mac: String,
    last_user: String,
    last_seen: DateTime<Utc>,
}

fn is_system_or_service_principal(name: &str) -> bool {
    let n = name.trim().to_lowercase();
    if n.is_empty() {
        return false;
    }
    n == "system"
        || n == "local system"
        || n == "nt authority\\system"
        || n == "nt authority\\local service"
        || n == "local service"
        || n == "nt authority\\network service"
        || n == "network service"
}

fn is_machine_account(name: &str) -> bool {
    let raw = name.trim();
    if raw.is_empty() {
        return false;
    }
    let user = raw
        .split('\\')
        .next_back()
        .unwrap_or(raw)
        .split('/')
        .next_back()
        .unwrap_or(raw)
        .trim();
    user.ends_with('$')
}

fn looks_like_hostname_token(name: &str) -> bool {
    let n = name.trim();
    if n.is_empty() {
        return false;
    }
    let u = n.to_uppercase();
    u.starts_with("DESKTOP-") || u.starts_with("LAPTOP-")
}

fn best_interactive_user_from_event(event: &Event) -> String {
    // Prefer explicit hint
    let cu = event
        .metadata
        .get("current_user")
        .map(|s| s.trim())
        .unwrap_or("");
    if !cu.is_empty()
        && !is_system_or_service_principal(cu)
        && !is_machine_account(cu)
        && !looks_like_hostname_token(cu)
        && !cu.eq_ignore_ascii_case("unknown")
    {
        return cu.to_string();
    }

    // Then structured user fields
    if let Some(u) = event.user.as_ref() {
        let name = u.name.trim();
        if !name.is_empty()
            && !is_system_or_service_principal(name)
            && !is_machine_account(name)
            && !looks_like_hostname_token(name)
            && !name.eq_ignore_ascii_case("unknown")
        {
            if !u.domain.trim().is_empty() {
                return format!("{}\\{}", u.domain.trim(), name);
            }
            return name.to_string();
        }
    }

    String::new()
}

#[derive(Debug, Clone)]
struct DeviceState {
    ip: String,
    mac: String,
    last_seen: DateTime<Utc>,
    seen_by: HashSet<String>,
}

#[derive(Clone)]
pub struct LanTopologyStore {
    inner: Arc<RwLock<LanTopologyInner>>,
    persist_path: Option<PathBuf>,
    persist_interval_secs: i64,
}

#[derive(Debug, Default)]
struct LanTopologyInner {
    agents: HashMap<String, AgentState>,
    devices: HashMap<String, DeviceState>,
    last_server_scan: Option<DateTime<Utc>>,
    last_gateway_ip: String,
    last_persist: Option<DateTime<Utc>>,
    last_restore: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedLanTopology {
    #[serde(default)]
    agents: Vec<PersistedAgentState>,
    #[serde(default)]
    devices: Vec<PersistedDeviceState>,
    #[serde(default)]
    last_gateway_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAgentState {
    agent_id: String,
    hostname: String,
    ip: String,
    mac: String,
    last_user: String,
    last_seen_unix: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDeviceState {
    ip: String,
    mac: String,
    last_seen_unix: i64,
    #[serde(default)]
    seen_by: Vec<String>,
}

fn key_for_device(ip: &str, mac: &str) -> String {
    let m = mac.trim().to_lowercase();
    if !m.is_empty() && m != "unknown" {
        return format!("mac:{}", m);
    }
    format!("ip:{}", ip.trim())
}

fn is_private_ip(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            match o {
                [10, ..] => true,
                [127, ..] => true,
                [0, ..] => true,
                [169, 254, ..] => true,
                [192, 168, ..] => true,
                [172, b, ..] if (16..=31).contains(&b) => true,
                _ => false,
            }
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || is_unique_local_v6(v6) || is_unicast_link_local_v6(v6)
        }
    }
}

fn is_unique_local_v6(v6: Ipv6Addr) -> bool {
    // fc00::/7
    let o = v6.octets();
    (o[0] & 0xfe) == 0xfc
}

fn is_unicast_link_local_v6(v6: Ipv6Addr) -> bool {
    // fe80::/10
    let o = v6.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

impl LanTopologyStore {
    pub fn new() -> Self {
        let persist_enabled = std::env::var("PERCEPTA_LAN_TOPOLOGY_PERSIST")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true);
        let persist_path = if persist_enabled {
            Some(
                std::env::var("PERCEPTA_LAN_TOPOLOGY_FILE")
                    .ok()
                    .map(PathBuf::from)
                    .unwrap_or_else(default_lan_topology_path),
            )
        } else {
            None
        };
        let persist_interval_secs = std::env::var("PERCEPTA_LAN_PERSIST_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(15)
            .clamp(5, 3600);

        let mut inner = LanTopologyInner::default();
        if let Some(path) = persist_path.as_ref() {
            if let Ok(raw) = std::fs::read_to_string(path) {
                match serde_json::from_str::<PersistedLanTopology>(&raw) {
                    Ok(saved) => {
                        restore_from_persisted(&mut inner, saved);
                        inner.last_restore = Some(Utc::now());
                        info!(
                            "Loaded LAN topology snapshot: agents={} devices={} path={}",
                            inner.agents.len(),
                            inner.devices.len(),
                            path.display()
                        );
                    }
                    Err(e) => {
                        warn!("Failed to parse LAN topology snapshot {}: {}", path.display(), e);
                    }
                }
            }
        }

        Self {
            inner: Arc::new(RwLock::new(inner)),
            persist_path,
            persist_interval_secs,
        }
    }

    pub async fn observe_event(&self, event: &Event) {
        let now = Utc::now();

        // Always update agent last-seen (helps keep agents visible even when no lan snapshots).
        if let Some(agent) = event.agent.as_ref() {
            let agent_id = agent.id.clone();
            if !agent_id.trim().is_empty() {
                let last_user = best_interactive_user_from_event(event);
                let mut w = self.inner.write().await;
                let prev_user = w
                    .agents
                    .get(&agent_id)
                    .map(|s| s.last_user.clone())
                    .unwrap_or_default();
                w.agents.insert(
                    agent_id,
                    AgentState {
                        hostname: agent.hostname.clone(),
                        ip: agent.ip.clone(),
                        mac: agent.mac.clone(),
                        last_user: if !last_user.is_empty() {
                            last_user
                        } else {
                            prev_user
                        },
                        last_seen: now,
                    },
                );
            }
        }

        self.maybe_persist(now).await;

        // Only parse lan snapshots.
        let Some(ev) = event.event.as_ref() else {
            return;
        };
        if ev.provider != "percepta.lan" {
            return;
        }
        if ev.action != "arp_snapshot" {
            return;
        }

        let agent_id = event
            .agent
            .as_ref()
            .map(|a| a.id.clone())
            .unwrap_or_default();

        let payload: LanSnapshotPayload = match serde_json::from_str(&ev.original_message) {
            Ok(v) => v,
            Err(_) => return,
        };

        if payload.entries.is_empty() {
            return;
        }

        let mut w = self.inner.write().await;
        for n in payload.entries {
            let ip = n.ip.trim().to_string();
            let mac = n.mac.trim().to_string();
            if ip.is_empty() {
                continue;
            }
            // We only visualize private LAN devices.
            if !is_private_ip(&ip) {
                continue;
            }

            let key = key_for_device(&ip, &mac);
            let entry = w.devices.entry(key).or_insert(DeviceState {
                ip: ip.clone(),
                mac: mac.clone(),
                last_seen: now,
                seen_by: HashSet::new(),
            });
            entry.ip = ip;
            if !mac.is_empty() {
                entry.mac = mac;
            }
            entry.last_seen = now;
            if !agent_id.is_empty() {
                entry.seen_by.insert(agent_id.clone());
            }
        }

        self.maybe_persist(now).await;
    }

    pub async fn observe_server_neighbors(&self, gateway_ip: &str, entries: &[(String, String)]) {
        let now = Utc::now();
        let mut w = self.inner.write().await;

        if !gateway_ip.trim().is_empty() {
            w.last_gateway_ip = gateway_ip.trim().to_string();
        }

        for (ip_raw, mac_raw) in entries {
            let ip = ip_raw.trim().to_string();
            let mac = mac_raw.trim().to_string();
            if ip.is_empty() {
                continue;
            }
            if !is_private_ip(&ip) {
                continue;
            }
            let key = key_for_device(&ip, &mac);
            let entry = w.devices.entry(key).or_insert(DeviceState {
                ip: ip.clone(),
                mac: mac.clone(),
                last_seen: now,
                seen_by: HashSet::new(),
            });
            entry.ip = ip;
            if !mac.is_empty() {
                entry.mac = mac;
            }
            entry.last_seen = now;
            entry.seen_by.insert("server".to_string());
        }

        self.maybe_persist(now).await;
    }

    pub async fn should_run_server_scan(&self, min_interval_seconds: i64) -> bool {
        let now = Utc::now();
        let mut w = self.inner.write().await;
        let ok = w
            .last_server_scan
            .map(|t| (now - t).num_seconds() >= min_interval_seconds)
            .unwrap_or(true);
        if ok {
            w.last_server_scan = Some(now);
        }
        ok
    }

    pub async fn agents_snapshot(&self) -> Vec<LanAgentNode> {
        let r = self.inner.read().await;
        let mut agents: Vec<LanAgentNode> = r
            .agents
            .iter()
            .map(|(id, a)| LanAgentNode {
                agent_id: id.clone(),
                hostname: a.hostname.clone(),
                ip: a.ip.clone(),
                mac: a.mac.clone(),
                last_user: a.last_user.clone(),
                last_seen_unix: a.last_seen.timestamp(),
            })
            .collect();
        agents.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        agents
    }

    pub async fn snapshot(&self, host_hint: &str) -> Result<LanTopologySnapshot> {
        let host = host_hint.trim().to_string();
        let server_host = if host.is_empty() {
            "server".to_string()
        } else {
            host
        };

        // Best-effort: if PERCEPTA_PUBLIC_HOST is an IP, use it.
        let server_ip = std::env::var("PERCEPTA_PUBLIC_HOST")
            .ok()
            .filter(|s| s.parse::<IpAddr>().is_ok())
            .unwrap_or_default();

        let r = self.inner.read().await;
        let gateway_ip = r.last_gateway_ip.clone();

        let mut agents: Vec<LanAgentNode> = r
            .agents
            .iter()
            .map(|(id, a)| LanAgentNode {
                agent_id: id.clone(),
                hostname: a.hostname.clone(),
                ip: a.ip.clone(),
                mac: a.mac.clone(),
                last_user: a.last_user.clone(),
                last_seen_unix: a.last_seen.timestamp(),
            })
            .collect();
        agents.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));

        let mut devices: Vec<LanDeviceNode> = r
            .devices
            .values()
            .map(|d| LanDeviceNode {
                ip: d.ip.clone(),
                mac: d.mac.clone(),
                last_seen_unix: d.last_seen.timestamp(),
                seen_by_agents: {
                    let mut v: Vec<String> = d.seen_by.iter().cloned().collect();
                    v.sort();
                    v
                },
            })
            .collect();
        devices.sort_by(|a, b| a.ip.cmp(&b.ip));

        Ok(LanTopologySnapshot {
            server_host,
            server_ip,
            gateway_ip,
            agents,
            devices,
        })
    }

    pub async fn persistence_status(&self) -> LanPersistenceStatus {
        let r = self.inner.read().await;
        LanPersistenceStatus {
            enabled: self.persist_path.is_some(),
            path: self
                .persist_path
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            persist_interval_secs: self.persist_interval_secs,
            last_persist_unix: r.last_persist.map(|t| t.timestamp()),
            last_restore_unix: r.last_restore.map(|t| t.timestamp()),
        }
    }

    async fn maybe_persist(&self, now: DateTime<Utc>) {
        let Some(path) = self.persist_path.as_ref() else {
            return;
        };

        let snapshot = {
            let mut w = self.inner.write().await;
            if let Some(last) = w.last_persist {
                if (now - last).num_seconds() < self.persist_interval_secs {
                    return;
                }
            }
            w.last_persist = Some(now);
            snapshot_from_inner(&w)
        };

        if let Err(e) = persist_snapshot(path, &snapshot).await {
            warn!("Failed to persist LAN topology snapshot {}: {}", path.display(), e);
        }
    }
}

fn default_lan_topology_path() -> PathBuf {
    if let Ok(d) = std::env::var("PERCEPTA_BASE_DIR") {
        let p = PathBuf::from(&d);
        if p.is_dir() {
            return p.join("lan_topology_snapshot.json");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(format!(
        "{}/.local/share/percepta-siem/lan_topology_snapshot.json",
        home
    ))
}

fn snapshot_from_inner(inner: &LanTopologyInner) -> PersistedLanTopology {
    PersistedLanTopology {
        agents: inner
            .agents
            .iter()
            .map(|(agent_id, a)| PersistedAgentState {
                agent_id: agent_id.clone(),
                hostname: a.hostname.clone(),
                ip: a.ip.clone(),
                mac: a.mac.clone(),
                last_user: a.last_user.clone(),
                last_seen_unix: a.last_seen.timestamp(),
            })
            .collect(),
        devices: inner
            .devices
            .values()
            .map(|d| PersistedDeviceState {
                ip: d.ip.clone(),
                mac: d.mac.clone(),
                last_seen_unix: d.last_seen.timestamp(),
                seen_by: d.seen_by.iter().cloned().collect(),
            })
            .collect(),
        last_gateway_ip: inner.last_gateway_ip.clone(),
    }
}

fn restore_from_persisted(inner: &mut LanTopologyInner, saved: PersistedLanTopology) {
    let mut agents = HashMap::new();
    for a in saved.agents {
        let Some(last_seen) = DateTime::from_timestamp(a.last_seen_unix, 0) else {
            continue;
        };
        if a.agent_id.trim().is_empty() {
            continue;
        }
        agents.insert(
            a.agent_id,
            AgentState {
                hostname: a.hostname,
                ip: a.ip,
                mac: a.mac,
                last_user: a.last_user,
                last_seen,
            },
        );
    }

    let mut devices = HashMap::new();
    for d in saved.devices {
        let Some(last_seen) = DateTime::from_timestamp(d.last_seen_unix, 0) else {
            continue;
        };
        let key = key_for_device(&d.ip, &d.mac);
        devices.insert(
            key,
            DeviceState {
                ip: d.ip,
                mac: d.mac,
                last_seen,
                seen_by: d.seen_by.into_iter().collect(),
            },
        );
    }

    inner.agents = agents;
    inner.devices = devices;
    inner.last_gateway_ip = saved.last_gateway_ip;
}

async fn persist_snapshot(path: &PathBuf, snapshot: &PersistedLanTopology) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let body = serde_json::to_vec_pretty(snapshot)?;
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, body).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn topology_persists_and_restores_across_store_recreate() {
        let _guard = ENV_LOCK.lock().expect("lock env test mutex");
        let temp = tempfile::tempdir().expect("create temp dir");
        let snapshot_path = temp.path().join("lan_topology_snapshot.json");

        std::env::set_var("PERCEPTA_LAN_TOPOLOGY_PERSIST", "1");
        std::env::set_var(
            "PERCEPTA_LAN_TOPOLOGY_FILE",
            snapshot_path.to_string_lossy().to_string(),
        );
        std::env::set_var("PERCEPTA_LAN_PERSIST_INTERVAL_SECS", "5");

        let store = LanTopologyStore::new();
        let event = Event {
            agent: Some(percepta_server::percepta::event::Agent {
                id: "persist-agent-1".to_string(),
                hostname: "persist-host".to_string(),
                ip: "10.10.1.7".to_string(),
                mac: "AA:BB:CC:DD:EE:FF".to_string(),
                version: "test".to_string(),
                os: None,
            }),
            metadata: HashMap::new(),
            ..Default::default()
        };

        store.observe_event(&event).await;
        assert!(snapshot_path.exists());

        let restored = LanTopologyStore::new();
        let agents = restored.agents_snapshot().await;
        let found = agents.into_iter().find(|a| a.agent_id == "persist-agent-1");
        assert!(found.is_some(), "restored topology should contain persisted agent");

        std::env::remove_var("PERCEPTA_LAN_TOPOLOGY_PERSIST");
        std::env::remove_var("PERCEPTA_LAN_TOPOLOGY_FILE");
        std::env::remove_var("PERCEPTA_LAN_PERSIST_INTERVAL_SECS");
    }
}
