use anyhow::Result;
use openssl::sha::sha256;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tracing::{debug, warn};

use crate::percepta::event::{EventCategory, EventDetails};
use crate::percepta::Event;
use crate::system_info;

#[cfg(target_os = "windows")]
trait CommandExtNoWindow {
    fn no_window(&mut self) -> &mut Self;
}

#[cfg(target_os = "windows")]
impl CommandExtNoWindow for std::process::Command {
    fn no_window(&mut self) -> &mut Self {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LanNeighbor {
    pub ip: String,
    pub mac: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct LanSnapshotPayload {
    entries: Vec<LanNeighbor>,
}

#[cfg(target_os = "linux")]
fn read_neighbors_ip_neigh() -> Vec<LanNeighbor> {
    let output = match std::process::Command::new("ip").args(["neigh", "show"]).output() {
        Ok(o) if o.status.success() => o,
        _ => {
            warn!("'ip neigh show' also failed — LAN discovery fully disabled.");
            return Vec::new();
        }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out: Vec<LanNeighbor> = Vec::new();
    for line in text.lines() {
        // Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
        let parts: Vec<&str> = line.split_whitespace().collect();
        let lladdr_pos = parts.iter().position(|&p| p == "lladdr");
        let Some(pos) = lladdr_pos else { continue };
        if pos + 1 >= parts.len() { continue; }
        let ip = parts[0];
        let mac = parts[pos + 1];
        if mac == "00:00:00:00:00:00" { continue; }
        out.push(LanNeighbor { ip: ip.to_string(), mac: mac.to_string() });
    }
    out.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.mac.cmp(&b.mac)));
    out.dedup();
    out
}

#[cfg(target_os = "linux")]
fn read_neighbors_best_effort() -> Vec<LanNeighbor> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static ARP_WARNED: AtomicBool = AtomicBool::new(false);

    let content = match std::fs::read_to_string("/proc/net/arp") {
        Ok(c) => c,
        Err(_) => {
            // ISS-023: Log a clear warning on first failure (common in containers).
            if !ARP_WARNED.swap(true, Ordering::Relaxed) {
                warn!("Cannot read /proc/net/arp -- LAN discovery disabled (common in containers). \
                       Trying 'ip neigh' fallback.");
            }
            // Fallback: try `ip neigh show` for environments without procfs.
            return read_neighbors_ip_neigh();
        }
    };
    let mut out: Vec<LanNeighbor> = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        // Skip header
        if idx == 0 {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: IP address HW type Flags HW address Mask Device
        if parts.len() < 6 {
            continue;
        }
        let ip = parts[0].trim();
        let flags = parts[2].trim();
        let mac = parts[3].trim();

        // Only accept complete entries (0x2) with a MAC.
        if flags != "0x2" {
            continue;
        }
        if mac.is_empty() || mac == "00:00:00:00:00:00" {
            continue;
        }

        out.push(LanNeighbor {
            ip: ip.to_string(),
            mac: mac.to_string(),
        });
    }

    out.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.mac.cmp(&b.mac)));
    out.dedup();
    out
}

#[cfg(all(windows, target_os = "windows"))]
fn read_neighbors_best_effort() -> Vec<LanNeighbor> {
    use std::process::Command;

    let output = std::process::Command::new("arp").no_window().arg("-a").output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut out: Vec<LanNeighbor> = Vec::new();

    for line in text.lines() {
        // Typical: "  192.168.1.1           00-11-22-33-44-55     dynamic"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let ip = parts[0];
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let mac_raw = parts[1];
        let mac = mac_raw.replace('-', ":");
        if mac.is_empty() {
            continue;
        }
        out.push(LanNeighbor {
            ip: ip.to_string(),
            mac,
        });
    }

    out.sort_by(|a, b| a.ip.cmp(&b.ip).then(a.mac.cmp(&b.mac)));
    out.dedup();
    out
}

#[cfg(not(any(target_os = "linux", all(windows, target_os = "windows"))))]
fn read_neighbors_best_effort() -> Vec<LanNeighbor> {
    Vec::new()
}

fn fingerprint(entries: &[LanNeighbor]) -> String {
    let payload = LanSnapshotPayload {
        entries: entries.to_vec(),
    };
    let json = serde_json::to_vec(&payload).unwrap_or_default();
    hex::encode(sha256(&json))
}

fn build_snapshot_event(agent_id: &str, entries: Vec<LanNeighbor>) -> Result<Event> {
    use chrono::Utc;
    use prost_types::Timestamp;

    let now = Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    };

    let agent = system_info::build_agent(agent_id);
    let host = system_info::build_host(&agent);

    let payload = LanSnapshotPayload { entries };
    let original_message = serde_json::to_string(&payload)?;

    Ok(Event {
        event_time: Some(ts.clone()),
        ingest_time: Some(ts),
        agent: Some(agent.clone()),
        host: Some(host),
        event: Some(EventDetails {
            summary: "LAN neighbor snapshot".to_string(),
            original_message,
            category: EventCategory::Network as i32,
            action: "arp_snapshot".to_string(),
            outcome: 0,
            level: "Info".to_string(),
            severity: 1,
            provider: "percepta.lan".to_string(),
            event_id: 0,
            record_id: 0,
        }),
        // Server will ensure hash if missing, but sending a stable UUID keeps dedupe behavior sane.
        hash: format!("{}-{}", agent_id, uuid::Uuid::new_v4()),
        ..Default::default()
    })
}

pub async fn lan_snapshot_loop(agent_id: String, event_sender: Sender<Vec<Event>>) {
    // Default 5s, allow tuning; keep min 2s (dashboard refresh target) and max 60s.
    let interval_ms = std::env::var("PERCEPTA_LAN_SNAPSHOT_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5000)
        .clamp(2000, 60_000);

    let mut interval = tokio::time::interval(Duration::from_millis(interval_ms));
    let mut last_fp: Option<String> = None;

    loop {
        interval.tick().await;

        let entries = read_neighbors_best_effort();
        if entries.is_empty() {
            continue;
        }

        let fp = fingerprint(&entries);
        if last_fp.as_deref() == Some(fp.as_str()) {
            continue;
        }
        last_fp = Some(fp);

        let evt = match build_snapshot_event(&agent_id, entries) {
            Ok(v) => v,
            Err(e) => {
                warn!("LAN snapshot event build failed: {:#}", e);
                continue;
            }
        };

        debug!("Emitting LAN neighbor snapshot event");
        let _ = event_sender.send(vec![evt]);
    }
}
