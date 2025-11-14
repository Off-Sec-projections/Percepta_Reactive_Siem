//! Sensor integrations (IDS/IPS, honeypot, FIM)
//!
//! This module adds practical event sources beyond OS logs:
//! - Suricata `eve.json` (IDS/IPS signals)
//! - Cowrie JSON logs (honeypot signals)
//! - Filesystem watching (FIM)
//!
//! All sources emit Percepta `Event`s with:
//! - `metadata["sensor.kind"]` set to one of: `ids`, `ips`, `honeypot`, `fim`
//! - a corresponding tag (`ids`, `ips`, `honeypot`, `fim`) plus source tags

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use notify::Watcher;
use openssl::sha::sha256;
use prost_types::Timestamp;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::fs;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::percepta::{
    event::{
        EventCategory, EventDetails, EventOutcome, File, FileOperation, Host, Network,
        NetworkDirection, User,
    },
    Event,
};

#[derive(Debug, Clone)]
pub struct SensorConfig {
    pub suricata_eve_path: Option<PathBuf>,
    pub cowrie_json_path: Option<PathBuf>,
    pub fim_paths: Vec<PathBuf>,
    pub fim_recursive: bool,
    pub fim_debounce: Duration,
}

impl SensorConfig {
    pub fn load() -> Self {
        let suricata_eve_path = std::env::var("PERCEPTA_SURICATA_EVE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(crate::ids_suricata::detect_eve_json_path);

        let cowrie_json_path = std::env::var("PERCEPTA_COWRIE_JSON")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);

        let fim_paths = std::env::var("PERCEPTA_FIM_PATHS")
            .ok()
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect::<Vec<_>>();

        let fim_recursive = std::env::var("PERCEPTA_FIM_RECURSIVE")
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            .map(|v| v != 0)
            .unwrap_or(true);

        let fim_debounce = std::env::var("PERCEPTA_FIM_DEBOUNCE_MS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|ms| ms.clamp(50, 10_000))
            .unwrap_or(250);

        Self {
            suricata_eve_path,
            cowrie_json_path,
            fim_paths,
            fim_recursive,
            fim_debounce: Duration::from_millis(fim_debounce),
        }
    }

    pub fn enabled(&self) -> bool {
        self.suricata_eve_path.is_some()
            || self.cowrie_json_path.is_some()
            || !self.fim_paths.is_empty()
    }
}

#[derive(Debug)]
pub struct SensorManager {
    suricata: Option<NdjsonCursorCollector>,
    cowrie: Option<NdjsonCursorCollector>,
    fim: Option<FimWatcher>,
}

impl SensorManager {
    pub async fn initialize(
        agent_id: String,
        agent: crate::percepta::event::Agent,
        host: Host,
        cert_dir: PathBuf,
        cfg: SensorConfig,
    ) -> Result<Self> {
        let cursor_path = cert_dir.join("sensor_log_cursor.json");

        let suricata = if let Some(path) = cfg.suricata_eve_path.clone() {
            Some(
                NdjsonCursorCollector::new(
                    agent_id.clone(),
                    agent.clone(),
                    host.clone(),
                    cursor_path.clone(),
                    "suricata".to_string(),
                    path,
                    parse_suricata_eve_line,
                )
                .await?,
            )
        } else {
            None
        };

        let cowrie = if let Some(path) = cfg.cowrie_json_path.clone() {
            Some(
                NdjsonCursorCollector::new(
                    agent_id.clone(),
                    agent.clone(),
                    host.clone(),
                    cursor_path.clone(),
                    "cowrie".to_string(),
                    path,
                    parse_cowrie_json_line,
                )
                .await?,
            )
        } else {
            None
        };

        let fim = if !cfg.fim_paths.is_empty() {
            Some(FimWatcher::start(
                agent_id,
                agent,
                host,
                cfg.fim_paths,
                cfg.fim_recursive,
                cfg.fim_debounce,
            )?)
        } else {
            None
        };

        Ok(Self {
            suricata,
            cowrie,
            fim,
        })
    }

    pub async fn collect_once(&mut self, max_events: usize) -> Vec<Event> {
        let mut out = Vec::new();

        if let Some(c) = &mut self.suricata {
            match c.collect(max_events.saturating_sub(out.len())).await {
                Ok(mut v) => out.append(&mut v),
                Err(e) => warn!("suricata collector failed: {:#}", e),
            }
        }

        if out.len() < max_events {
            if let Some(c) = &mut self.cowrie {
                match c.collect(max_events.saturating_sub(out.len())).await {
                    Ok(mut v) => out.append(&mut v),
                    Err(e) => warn!("cowrie collector failed: {:#}", e),
                }
            }
        }

        if out.len() < max_events {
            if let Some(f) = &mut self.fim {
                let mut v = f.drain(max_events.saturating_sub(out.len())).await;
                out.append(&mut v);
            }
        }

        out
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct CursorState {
    sources: std::collections::HashMap<String, u64>,
    /// Inode numbers keyed by source name; used to detect log rotation.
    #[serde(default)]
    inodes: std::collections::HashMap<String, u64>,
}

#[derive(Debug)]
struct NdjsonCursorCollector {
    agent_id: String,
    agent: crate::percepta::event::Agent,
    host: Host,
    cursor_path: PathBuf,
    cursor_key: String,
    log_path: PathBuf,
    pos: u64,
    last_inode: u64,
    parser: fn(&str, &crate::percepta::event::Agent, &Host, &str) -> Option<Event>,
}

impl NdjsonCursorCollector {
    async fn new(
        agent_id: String,
        agent: crate::percepta::event::Agent,
        host: Host,
        cursor_path: PathBuf,
        cursor_key: String,
        log_path: PathBuf,
        parser: fn(&str, &crate::percepta::event::Agent, &Host, &str) -> Option<Event>,
    ) -> Result<Self> {
        let mut state = load_cursor_state(&cursor_path).await.unwrap_or_default();
        let mut pos = state.sources.get(&cursor_key).copied().unwrap_or(0);

        let last_inode = state.inodes.get(&cursor_key).copied().unwrap_or(0);

        // If first-run, start from end to avoid historical spam.
        if pos == 0 {
            if let Ok(meta) = fs::metadata(&log_path).await {
                pos = meta.len();
                state.sources.insert(cursor_key.clone(), pos);
                let _ = save_cursor_state(&cursor_path, &state).await;
            }
        }

        Ok(Self {
            agent_id,
            agent,
            host,
            cursor_path,
            cursor_key,
            log_path,
            pos,
            last_inode,
            parser,
        })
    }

    async fn collect(&mut self, max_events: usize) -> Result<Vec<Event>> {
        if max_events == 0 {
            return Ok(Vec::new());
        }

        let meta = match fs::metadata(&self.log_path).await {
            Ok(m) => m,
            Err(_) => return Ok(Vec::new()),
        };

        // Handle truncation/rotation.
        #[cfg(target_os = "linux")]
        {
            let cur_inode = meta.ino();
            if self.last_inode != 0 && cur_inode != self.last_inode {
                // File was rotated — different inode means a new file.
                debug!("{}: log rotated (inode {} -> {}), resetting cursor",
                       self.cursor_key, self.last_inode, cur_inode);
                self.pos = 0;
            }
            self.last_inode = cur_inode;
        }
        if meta.len() < self.pos {
            self.pos = 0;
        }

        let mut file = fs::File::open(&self.log_path)
            .await
            .with_context(|| format!("failed to open {}", self.log_path.display()))?;
        file.seek(std::io::SeekFrom::Start(self.pos)).await?;

        let mut reader = BufReader::new(file);
        let mut events = Vec::new();
        let mut line_buf = Vec::<u8>::new();

        while events.len() < max_events {
            line_buf.clear();
            let n = reader.read_until(b'\n', &mut line_buf).await?;
            if n == 0 {
                break;
            }
            // If the file ends mid-record (no trailing newline yet), keep cursor unchanged
            // so the complete JSON line can be parsed on the next poll.
            if !line_buf.ends_with(b"\n") {
                break;
            }
            self.pos = self.pos.saturating_add(n as u64);
            let line_lossy = String::from_utf8_lossy(&line_buf);
            let l = line_lossy.trim_end();
            if l.is_empty() {
                continue;
            }
            if let Some(ev) = (self.parser)(l, &self.agent, &self.host, &self.agent_id) {
                events.push(ev);
            }
        }

        if !events.is_empty() {
            debug!("{} collected {} events", self.cursor_key, events.len());
        }

        // Persist cursor even if no events: avoids re-reading if parser ignores lines.
        let mut state = load_cursor_state(&self.cursor_path)
            .await
            .unwrap_or_default();
        state.sources.insert(self.cursor_key.clone(), self.pos);
        if self.last_inode != 0 {
            state.inodes.insert(self.cursor_key.clone(), self.last_inode);
        }
        save_cursor_state(&self.cursor_path, &state).await?;

        Ok(events)
    }
}

async fn load_cursor_state(path: &Path) -> Result<CursorState> {
    if !path.exists() {
        return Ok(CursorState::default());
    }
    let s = fs::read_to_string(path).await?;
    Ok(serde_json::from_str(&s).unwrap_or_default())
}

async fn save_cursor_state(path: &Path, state: &CursorState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    let tmp = path.with_extension("json.tmp");
    let s = serde_json::to_string_pretty(state)?;
    fs::write(&tmp, s).await?;
    fs::rename(&tmp, path).await?;
    Ok(())
}

fn mk_hash(agent_id: &str, stable: &str) -> String {
    hex::encode(sha256(format!("{}:{}", agent_id, stable).as_bytes()))
}

fn mk_now_ts() -> Timestamp {
    let now = Utc::now();
    Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    }
}

fn parse_rfc3339_ts(s: &str) -> Option<Timestamp> {
    let dt = DateTime::parse_from_rfc3339(s).ok()?;
    let utc = dt.with_timezone(&Utc);
    Some(Timestamp {
        seconds: utc.timestamp(),
        nanos: utc.timestamp_subsec_nanos() as i32,
    })
}

fn parse_suricata_eve_line(
    line: &str,
    agent: &crate::percepta::event::Agent,
    host: &Host,
    agent_id: &str,
) -> Option<Event> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let event_type = v.get("event_type")?.as_str()?.to_string();

    match event_type.as_str() {
        "alert" => parse_suricata_alert(&v, agent, host, agent_id, line),
        "dns" => parse_suricata_dns(&v, agent, host, agent_id, line),
        "http" => parse_suricata_http(&v, agent, host, agent_id, line),
        "tls" => parse_suricata_tls(&v, agent, host, agent_id, line),
        "flow" => parse_suricata_flow(&v, agent, host, agent_id, line),
        _ => None,
    }
}

fn parse_suricata_alert(
    v: &serde_json::Value,
    agent: &crate::percepta::event::Agent,
    host: &Host,
    agent_id: &str,
    line: &str,
) -> Option<Event> {
    let alert = v.get("alert")?;
    let signature = alert
        .get("signature")
        .and_then(|x| x.as_str())
        .unwrap_or("suricata alert");
    let sid = alert
        .get("signature_id")
        .and_then(|x| x.as_i64())
        .unwrap_or(0);
    let category = alert.get("category").and_then(|x| x.as_str()).unwrap_or("");
    let severity = alert.get("severity").and_then(|x| x.as_i64()).unwrap_or(3);
    let alert_action = alert
        .get("action")
        .and_then(|x| x.as_str())
        .unwrap_or("alert");

    let src_ip = v.get("src_ip").and_then(|x| x.as_str()).unwrap_or("");
    let dst_ip = v.get("dest_ip").and_then(|x| x.as_str()).unwrap_or("");
    let src_port = v.get("src_port").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let dst_port = v.get("dest_port").and_then(|x| x.as_u64()).unwrap_or(0) as u32;

    let ts = v
        .get("timestamp")
        .and_then(|x| x.as_str())
        .and_then(parse_rfc3339_ts)
        .unwrap_or_else(mk_now_ts);

    let direction = v.get("direction").and_then(|x| x.as_str()).or_else(|| {
        v.get("flow")
            .and_then(|f| f.get("direction").and_then(|x| x.as_str()))
    });
    let direction = match direction.map(|d| d.to_lowercase()) {
        Some(d) if d == "to_server" || d == "inbound" || d == "in" => NetworkDirection::Inbound,
        Some(d) if d == "to_client" || d == "outbound" || d == "out" => NetworkDirection::Outbound,
        _ => NetworkDirection::DirUnknown,
    };

    // Map Suricata alert severity (commonly 1=high .. 5=low) -> Percepta severity (0..4).
    let percepta_sev = match severity {
        1 => 4,
        2 => 3,
        3 => 2,
        4 => 1,
        _ => 1,
    };

    let mut ev = Event {
        event_time: Some(ts.clone()),
        ingest_time: Some(ts),
        agent: Some(agent.clone()),
        host: Some(host.clone()),
        event: Some(EventDetails {
            summary: format!("Suricata alert: {}", signature),
            original_message: line.to_string(),
            category: EventCategory::Network as i32,
            action: if alert_action.trim().is_empty() {
                "alert".to_string()
            } else {
                alert_action.to_string()
            },
            outcome: match alert_action.to_lowercase().as_str() {
                "blocked" | "block" | "drop" | "deny" => EventOutcome::Blocked as i32,
                "allowed" | "allow" | "pass" => EventOutcome::Success as i32,
                _ => EventOutcome::Success as i32,
            },
            level: "Warning".to_string(),
            severity: percepta_sev,
            provider: "suricata".to_string(),
            event_id: sid as u64,
            record_id: 0,
        }),
        network: Some(Network {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            src_port,
            dst_port,
            protocol: v
                .get("proto")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            direction: direction as i32,
            ..Default::default()
        }),
        hash: mk_hash(
            agent_id,
            &format!("suricata:{}:{}:{}:{}", sid, src_ip, dst_ip, dst_port),
        ),
        ..Default::default()
    };

    ev.tags.push("suricata".to_string());
    ev.tags.push("ids".to_string());
    ev.metadata
        .insert("sensor.kind".to_string(), "ids".to_string());
    ev.metadata
        .insert("suricata.signature".to_string(), signature.to_string());
    ev.metadata
        .insert("suricata.sid".to_string(), sid.to_string());
    ev.metadata
        .insert("suricata.action".to_string(), alert_action.to_string());
    if !category.is_empty() {
        ev.metadata
            .insert("suricata.category".to_string(), category.to_string());
    }
    ev.metadata
        .insert("suricata.severity".to_string(), severity.to_string());
    ev.metadata
        .insert("ids.engine".to_string(), "suricata".to_string());
    ev.metadata
        .insert("ids.signature".to_string(), signature.to_string());
    ev.metadata.insert("ids.sid".to_string(), sid.to_string());
    if !category.is_empty() {
        ev.metadata
            .insert("ids.category".to_string(), category.to_string());
    }
    ev.metadata
        .insert("ids.severity".to_string(), severity.to_string());
    ev.metadata
        .insert("ids.action".to_string(), alert_action.to_string());
    ev.metadata
        .insert("signature".to_string(), signature.to_string());
    ev.metadata.insert("sid".to_string(), sid.to_string());

    Some(ev)
}

/// Helper: extract common network fields + timestamp from a Suricata eve record.
fn suricata_common(
    v: &serde_json::Value,
    agent: &crate::percepta::event::Agent,
    host: &Host,
) -> (String, String, u32, u32, String, i32, Timestamp) {
    let src_ip = v.get("src_ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let dst_ip = v.get("dest_ip").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let src_port = v.get("src_port").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let dst_port = v.get("dest_port").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let proto = v.get("proto").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let direction = v.get("direction").and_then(|x| x.as_str()).or_else(|| {
        v.get("flow").and_then(|f| f.get("direction").and_then(|x| x.as_str()))
    });
    let dir = match direction.map(|d| d.to_lowercase()).as_deref() {
        Some("to_server") | Some("inbound") | Some("in") => NetworkDirection::Inbound as i32,
        Some("to_client") | Some("outbound") | Some("out") => NetworkDirection::Outbound as i32,
        _ => NetworkDirection::DirUnknown as i32,
    };
    let ts = v.get("timestamp").and_then(|x| x.as_str()).and_then(parse_rfc3339_ts).unwrap_or_else(mk_now_ts);
    let _ = (agent, host); // used by caller
    (src_ip, dst_ip, src_port, dst_port, proto, dir, ts)
}

fn parse_suricata_dns(
    v: &serde_json::Value,
    agent: &crate::percepta::event::Agent,
    host: &Host,
    agent_id: &str,
    line: &str,
) -> Option<Event> {
    let dns = v.get("dns")?;
    let (src_ip, dst_ip, src_port, dst_port, proto, dir, ts) = suricata_common(v, agent, host);

    let dns_type = dns.get("type").and_then(|x| x.as_str()).unwrap_or("query");
    let rrname = dns.get("rrname").and_then(|x| x.as_str()).unwrap_or("");
    let rrtype = dns.get("rrtype").and_then(|x| x.as_str()).unwrap_or("");
    let rcode = dns.get("rcode").and_then(|x| x.as_str()).unwrap_or("");
    let rdata = dns.get("rdata").and_then(|x| x.as_str()).unwrap_or("");

    let summary = if dns_type == "answer" {
        format!("DNS {} {} {} -> {}", rrtype, rrname, rcode, rdata)
    } else {
        format!("DNS query {} {}", rrtype, rrname)
    };

    let mut ev = Event {
        event_time: Some(ts.clone()),
        ingest_time: Some(ts),
        agent: Some(agent.clone()),
        host: Some(host.clone()),
        event: Some(EventDetails {
            summary,
            original_message: line.to_string(),
            category: EventCategory::Network as i32,
            action: format!("dns_{}", dns_type),
            outcome: if rcode == "NOERROR" || rcode.is_empty() { EventOutcome::Success as i32 } else { EventOutcome::Failure as i32 },
            level: "Informational".to_string(),
            severity: 0,
            provider: "suricata".to_string(),
            event_id: 0,
            record_id: 0,
        }),
        network: Some(Network {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: proto,
            direction: dir,
            ..Default::default()
        }),
        hash: mk_hash(agent_id, &format!("suricata:dns:{}:{}:{}:{}", rrname, rrtype, src_ip, dst_ip)),
        ..Default::default()
    };
    ev.tags.extend(["suricata".into(), "ids".into(), "dns".into()]);
    ev.metadata.insert("sensor.kind".into(), "ids".into());
    ev.metadata.insert("ids.engine".into(), "suricata".into());
    ev.metadata.insert("dns.type".into(), dns_type.into());
    ev.metadata.insert("dns.rrname".into(), rrname.into());
    ev.metadata.insert("dns.rrtype".into(), rrtype.into());
    if !rcode.is_empty() { ev.metadata.insert("dns.rcode".into(), rcode.into()); }
    if !rdata.is_empty() { ev.metadata.insert("dns.rdata".into(), rdata.into()); }
    Some(ev)
}

fn parse_suricata_http(
    v: &serde_json::Value,
    agent: &crate::percepta::event::Agent,
    host: &Host,
    agent_id: &str,
    line: &str,
) -> Option<Event> {
    let http = v.get("http")?;
    let (src_ip, dst_ip, src_port, dst_port, proto, dir, ts) = suricata_common(v, agent, host);

    let hostname = http.get("hostname").and_then(|x| x.as_str()).unwrap_or("");
    let url = http.get("url").and_then(|x| x.as_str()).unwrap_or("");
    let method = http.get("http_method").and_then(|x| x.as_str()).unwrap_or("GET");
    let status = http.get("status").and_then(|x| x.as_u64()).unwrap_or(0);
    let user_agent = http.get("http_user_agent").and_then(|x| x.as_str()).unwrap_or("");
    let content_type = http.get("http_content_type").and_then(|x| x.as_str()).unwrap_or("");
    let length = http.get("length").and_then(|x| x.as_u64()).unwrap_or(0);

    let summary = format!("HTTP {} {}{} -> {}", method, hostname, url, status);

    let mut ev = Event {
        event_time: Some(ts.clone()),
        ingest_time: Some(ts),
        agent: Some(agent.clone()),
        host: Some(host.clone()),
        event: Some(EventDetails {
            summary,
            original_message: line.to_string(),
            category: EventCategory::Network as i32,
            action: format!("http_{}", method.to_lowercase()),
            outcome: if status >= 400 { EventOutcome::Failure as i32 } else { EventOutcome::Success as i32 },
            level: "Informational".to_string(),
            severity: 0,
            provider: "suricata".to_string(),
            event_id: 0,
            record_id: 0,
        }),
        network: Some(Network {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: proto,
            direction: dir,
            ..Default::default()
        }),
        hash: mk_hash(agent_id, &format!("suricata:http:{}:{}:{}:{}", method, hostname, url, src_ip)),
        ..Default::default()
    };
    ev.tags.extend(["suricata".into(), "ids".into(), "http".into()]);
    ev.metadata.insert("sensor.kind".into(), "ids".into());
    ev.metadata.insert("ids.engine".into(), "suricata".into());
    ev.metadata.insert("http.method".into(), method.into());
    ev.metadata.insert("http.hostname".into(), hostname.into());
    ev.metadata.insert("http.url".into(), url.into());
    if status > 0 { ev.metadata.insert("http.status".into(), status.to_string()); }
    if !user_agent.is_empty() { ev.metadata.insert("http.user_agent".into(), user_agent.into()); }
    if !content_type.is_empty() { ev.metadata.insert("http.content_type".into(), content_type.into()); }
    if length > 0 { ev.metadata.insert("http.length".into(), length.to_string()); }
    Some(ev)
}

fn parse_suricata_tls(
    v: &serde_json::Value,
    agent: &crate::percepta::event::Agent,
    host: &Host,
    agent_id: &str,
    line: &str,
) -> Option<Event> {
    let tls = v.get("tls")?;
    let (src_ip, dst_ip, src_port, dst_port, proto, dir, ts) = suricata_common(v, agent, host);

    let sni = tls.get("sni").and_then(|x| x.as_str()).unwrap_or("");
    let subject = tls.get("subject").and_then(|x| x.as_str()).unwrap_or("");
    let issuer = tls.get("issuerdn").and_then(|x| x.as_str()).unwrap_or("");
    let version = tls.get("version").and_then(|x| x.as_str()).unwrap_or("");
    let ja3_hash = tls.get("ja3").and_then(|j| j.get("hash")).and_then(|x| x.as_str()).unwrap_or("");
    let ja3s_hash = tls.get("ja3s").and_then(|j| j.get("hash")).and_then(|x| x.as_str()).unwrap_or("");
    let fingerprint = tls.get("fingerprint").and_then(|x| x.as_str()).unwrap_or("");
    let not_after = tls.get("notafter").and_then(|x| x.as_str()).unwrap_or("");

    let display_name = if !sni.is_empty() { sni } else if !subject.is_empty() { subject } else { "unknown" };
    let summary = format!("TLS {} {}", version, display_name);

    let mut ev = Event {
        event_time: Some(ts.clone()),
        ingest_time: Some(ts),
        agent: Some(agent.clone()),
        host: Some(host.clone()),
        event: Some(EventDetails {
            summary,
            original_message: line.to_string(),
            category: EventCategory::Network as i32,
            action: "tls_handshake".to_string(),
            outcome: EventOutcome::Success as i32,
            level: "Informational".to_string(),
            severity: 0,
            provider: "suricata".to_string(),
            event_id: 0,
            record_id: 0,
        }),
        network: Some(Network {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: proto,
            direction: dir,
            ..Default::default()
        }),
        hash: mk_hash(agent_id, &format!("suricata:tls:{}:{}:{}:{}", sni, src_ip, dst_ip, dst_port)),
        ..Default::default()
    };
    ev.tags.extend(["suricata".into(), "ids".into(), "tls".into()]);
    ev.metadata.insert("sensor.kind".into(), "ids".into());
    ev.metadata.insert("ids.engine".into(), "suricata".into());
    if !sni.is_empty() { ev.metadata.insert("tls.sni".into(), sni.into()); }
    if !subject.is_empty() { ev.metadata.insert("tls.subject".into(), subject.into()); }
    if !issuer.is_empty() { ev.metadata.insert("tls.issuer".into(), issuer.into()); }
    if !version.is_empty() { ev.metadata.insert("tls.version".into(), version.into()); }
    if !ja3_hash.is_empty() { ev.metadata.insert("tls.ja3".into(), ja3_hash.into()); }
    if !ja3s_hash.is_empty() { ev.metadata.insert("tls.ja3s".into(), ja3s_hash.into()); }
    if !fingerprint.is_empty() { ev.metadata.insert("tls.fingerprint".into(), fingerprint.into()); }
    if !not_after.is_empty() { ev.metadata.insert("tls.not_after".into(), not_after.into()); }
    Some(ev)
}

fn parse_suricata_flow(
    v: &serde_json::Value,
    agent: &crate::percepta::event::Agent,
    host: &Host,
    agent_id: &str,
    line: &str,
) -> Option<Event> {
    let (src_ip, dst_ip, src_port, dst_port, proto, dir, ts) = suricata_common(v, agent, host);

    let app_proto = v.get("app_proto").and_then(|x| x.as_str()).unwrap_or("unknown");
    let flow = v.get("flow");
    let bytes_toserver = flow.and_then(|f| f.get("bytes_toserver")).and_then(|x| x.as_u64()).unwrap_or(0);
    let bytes_toclient = flow.and_then(|f| f.get("bytes_toclient")).and_then(|x| x.as_u64()).unwrap_or(0);
    let pkts_toserver = flow.and_then(|f| f.get("pkts_toserver")).and_then(|x| x.as_u64()).unwrap_or(0);
    let pkts_toclient = flow.and_then(|f| f.get("pkts_toclient")).and_then(|x| x.as_u64()).unwrap_or(0);
    let state = flow.and_then(|f| f.get("state")).and_then(|x| x.as_str()).unwrap_or("");
    let reason = flow.and_then(|f| f.get("reason")).and_then(|x| x.as_str()).unwrap_or("");

    let total_bytes = bytes_toserver + bytes_toclient;
    let summary = format!("Flow {} {}:{} -> {}:{} ({} bytes)", app_proto, src_ip, src_port, dst_ip, dst_port, total_bytes);

    let mut ev = Event {
        event_time: Some(ts.clone()),
        ingest_time: Some(ts),
        agent: Some(agent.clone()),
        host: Some(host.clone()),
        event: Some(EventDetails {
            summary,
            original_message: line.to_string(),
            category: EventCategory::Network as i32,
            action: "flow_end".to_string(),
            outcome: EventOutcome::Success as i32,
            level: "Informational".to_string(),
            severity: 0,
            provider: "suricata".to_string(),
            event_id: 0,
            record_id: 0,
        }),
        network: Some(Network {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: proto,
            direction: dir,
            bytes_in: bytes_toclient,
            bytes_out: bytes_toserver,
            ..Default::default()
        }),
        hash: mk_hash(agent_id, &format!("suricata:flow:{}:{}:{}:{}:{}:{}", app_proto, src_ip, src_port, dst_ip, dst_port, total_bytes)),
        ..Default::default()
    };
    ev.tags.extend(["suricata".into(), "ids".into(), "flow".into()]);
    ev.metadata.insert("sensor.kind".into(), "ids".into());
    ev.metadata.insert("ids.engine".into(), "suricata".into());
    ev.metadata.insert("flow.app_proto".into(), app_proto.into());
    ev.metadata.insert("flow.bytes_toserver".into(), bytes_toserver.to_string());
    ev.metadata.insert("flow.bytes_toclient".into(), bytes_toclient.to_string());
    ev.metadata.insert("flow.pkts_toserver".into(), pkts_toserver.to_string());
    ev.metadata.insert("flow.pkts_toclient".into(), pkts_toclient.to_string());
    if !state.is_empty() { ev.metadata.insert("flow.state".into(), state.into()); }
    if !reason.is_empty() { ev.metadata.insert("flow.reason".into(), reason.into()); }
    Some(ev)
}

fn parse_cowrie_json_line(
    line: &str,
    agent: &crate::percepta::event::Agent,
    host: &Host,
    agent_id: &str,
) -> Option<Event> {
    static COWRIE_MAX_LINE_BYTES: OnceLock<usize> = OnceLock::new();
    let max_line = *COWRIE_MAX_LINE_BYTES.get_or_init(|| {
        std::env::var("PERCEPTA_COWRIE_MAX_LINE_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .map(|n| n.clamp(512, 256 * 1024))
            .unwrap_or(16 * 1024)
    });
    if line.len() > max_line {
        return None;
    }

    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    let eventid = v
        .get("eventid")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if eventid.is_empty() {
        return None;
    }

    // Production default: accept Cowrie namespace events, optional explicit allowlist via env.
    // PERCEPTA_COWRIE_EVENT_ALLOWLIST="cowrie.login.failed,cowrie.command.input"
    // PERCEPTA_COWRIE_EVENT_ALLOWLIST="*" to accept all cowrie.* events.
    static COWRIE_ALLOWLIST: OnceLock<Option<HashSet<String>>> = OnceLock::new();
    let allowlist = COWRIE_ALLOWLIST.get_or_init(|| {
        let raw = std::env::var("PERCEPTA_COWRIE_EVENT_ALLOWLIST").ok()?;
        let items = raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<HashSet<_>>();
        if items.is_empty() {
            None
        } else {
            Some(items)
        }
    });

    if !eventid.starts_with("cowrie.") {
        return None;
    }
    if let Some(set) = allowlist {
        if !set.contains("*") && !set.contains(&eventid) {
            return None;
        }
    }

    let src_ip = v.get("src_ip").and_then(|x| x.as_str()).unwrap_or("");
    let src_port = v.get("src_port").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let dst_port = v.get("dst_port").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
    let protocol = v
        .get("protocol")
        .or_else(|| v.get("proto"))
        .and_then(|x| x.as_str())
        .unwrap_or("tcp")
        .to_string();

    let mut dst_ip = v
        .get("dst_ip")
        .or_else(|| v.get("dest_ip"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let mut dst_ip_source = "cowrie".to_string();
    if dst_ip.trim().is_empty() {
        let host_ip = host.ip.first().map(|s| s.trim()).unwrap_or("");
        if !host_ip.is_empty() {
            dst_ip = host_ip.to_string();
            dst_ip_source = "host.ip".to_string();
        }
    }

    let session = v
        .get("session")
        .or_else(|| v.get("sessionid"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    let username = v
        .get("username")
        .or_else(|| v.get("user"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    let command = v
        .get("input")
        .or_else(|| v.get("command"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    let url = v
        .get("url")
        .or_else(|| v.get("outfile"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    let client_version = v
        .get("version")
        .or_else(|| v.get("client"))
        .or_else(|| v.get("client_version"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .trim()
        .to_string();

    let (category, outcome, severity, level) = if eventid.contains("login.failed") {
        (EventCategory::Auth, EventOutcome::Failure, 3, "Warning")
    } else if eventid.contains("login.success") {
        (EventCategory::Auth, EventOutcome::Success, 2, "Info")
    } else if eventid.contains("command.input") {
        (EventCategory::Process, EventOutcome::Success, 3, "Warning")
    } else if eventid.contains("file_download") || eventid.contains("download") {
        (EventCategory::File, EventOutcome::Success, 4, "High")
    } else if eventid.contains("session.connect") {
        (EventCategory::Network, EventOutcome::Success, 2, "Info")
    } else if eventid.contains("session.closed") || eventid.contains("session.disconnect") {
        (EventCategory::Network, EventOutcome::Success, 1, "Info")
    } else {
        (EventCategory::Other, EventOutcome::Success, 2, "Info")
    };

    let ts = v
        .get("timestamp")
        .or_else(|| v.get("time"))
        .and_then(|x| x.as_str())
        .and_then(parse_rfc3339_ts)
        .unwrap_or_else(mk_now_ts);

    let summary = if eventid.contains("login.failed") {
        format!(
            "Cowrie login failed: user={} src={} dst_port={}",
            if username.is_empty() {
                "(unknown)"
            } else {
                username.as_str()
            },
            if src_ip.is_empty() {
                "(unknown)"
            } else {
                src_ip
            },
            dst_port
        )
    } else if eventid.contains("login.success") {
        format!(
            "Cowrie login success: user={} src={} dst_port={}",
            if username.is_empty() {
                "(unknown)"
            } else {
                username.as_str()
            },
            if src_ip.is_empty() {
                "(unknown)"
            } else {
                src_ip
            },
            dst_port
        )
    } else if eventid.contains("command.input") {
        let c = if command.is_empty() {
            "(empty)"
        } else {
            command.as_str()
        };
        format!(
            "Cowrie command input: src={} cmd={}",
            if src_ip.is_empty() {
                "(unknown)"
            } else {
                src_ip
            },
            c
        )
    } else if !url.is_empty() {
        format!(
            "Cowrie file/download activity: src={} url={}",
            if src_ip.is_empty() {
                "(unknown)"
            } else {
                src_ip
            },
            url
        )
    } else {
        format!("Cowrie event: {}", eventid)
    };

    let stable = format!(
        "cowrie:{}:{}:{}:{}:{}:{}:{}:{}",
        eventid,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        session,
        command,
        v.get("timestamp").and_then(|x| x.as_str()).unwrap_or("")
    );

    let mut ev = Event {
        event_time: Some(ts.clone()),
        ingest_time: Some(ts),
        agent: Some(agent.clone()),
        host: Some(host.clone()),
        event: Some(EventDetails {
            summary,
            original_message: line.to_string(),
            category: category as i32,
            action: eventid.clone(),
            outcome: outcome as i32,
            level: level.to_string(),
            severity,
            provider: "cowrie".to_string(),
            event_id: 0,
            record_id: 0,
        }),
        network: Some(Network {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol,
            direction: NetworkDirection::Inbound as i32,
            ..Default::default()
        }),
        hash: mk_hash(agent_id, &stable),
        ..Default::default()
    };

    ev.tags.push("cowrie".to_string());
    ev.tags.push("honeypot".to_string());
    ev.metadata
        .insert("sensor.kind".to_string(), "honeypot".to_string());
    ev.metadata.insert("cowrie.eventid".to_string(), eventid);
    ev.metadata
        .insert("honeypot.engine".to_string(), "cowrie".to_string());
    ev.metadata
        .insert("honeypot.provider".to_string(), "cowrie".to_string());
    ev.metadata
        .insert("honeypot.session".to_string(), session.clone());
    ev.metadata
        .insert("honeypot.src_ip".to_string(), src_ip.to_string());
    ev.metadata
        .insert("honeypot.src_port".to_string(), src_port.to_string());
    ev.metadata
        .insert("honeypot.dst_port".to_string(), dst_port.to_string());

    if !session.is_empty() {
        ev.metadata.insert("cowrie.session".to_string(), session);
    }

    if !username.is_empty() {
        ev.metadata
            .insert("cowrie.username".to_string(), username.clone());
        ev.metadata
            .insert("metadata.user".to_string(), username.clone());
        if ev.user.is_none() {
            ev.user = Some(User {
                id: String::new(),
                name: username,
                domain: String::new(),
                privileges: Vec::new(),
            });
        }
    }
    if !command.is_empty() {
        ev.metadata
            .insert("cowrie.command".to_string(), command.clone());
        ev.metadata.insert("command".to_string(), command.clone());
        ev.metadata.insert("activity".to_string(), command);
    }
    if !url.is_empty() {
        ev.metadata.insert("cowrie.url".to_string(), url.clone());
        ev.metadata.insert("request".to_string(), url);
    }
    if !client_version.is_empty() {
        ev.metadata
            .insert("cowrie.client_version".to_string(), client_version);
    }

    if let Some(s) = v.get("sensor").and_then(|x| x.as_str()) {
        if !s.trim().is_empty() {
            ev.metadata
                .insert("cowrie.sensor".to_string(), s.to_string());
        }
    }
    if let Some(raw_ts) = v.get("timestamp").and_then(|x| x.as_str()) {
        if !raw_ts.trim().is_empty() {
            ev.metadata
                .insert("cowrie.timestamp".to_string(), raw_ts.to_string());
        }
    }
    if !dst_ip.is_empty() {
        ev.metadata
            .insert("network.dst_ip_source".to_string(), dst_ip_source);
    }

    Some(ev)
}

#[derive(Debug)]
struct FimWatcher {
    rx: mpsc::Receiver<FimChange>,
    _watcher: notify::RecommendedWatcher,
    agent_id: String,
    agent: crate::percepta::event::Agent,
    host: Host,
    recent_changes: HashMap<String, Instant>,
    dedup_window: Duration,
    baseline_hashes: HashMap<String, String>,
    enable_hash_baseline: bool,
    max_hash_file_bytes: u64,
}

#[derive(Debug, Clone)]
struct FimChange {
    op: FileOperation,
    path: String,
    old_path: Option<String>,
}

impl FimWatcher {
    fn dedup_window_from_env() -> Duration {
        let ms = std::env::var("PERCEPTA_FIM_DEDUP_WINDOW_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|v| v.clamp(100, 30_000))
            .unwrap_or(1500);
        Duration::from_millis(ms)
    }

    fn hash_baseline_enabled() -> bool {
        std::env::var("PERCEPTA_FIM_HASH_BASELINE")
            .ok()
            .map(|v| {
                let t = v.trim().to_ascii_lowercase();
                t == "1" || t == "true" || t == "yes" || t == "on"
            })
            .unwrap_or(true)
    }

    fn max_hash_file_bytes() -> u64 {
        std::env::var("PERCEPTA_FIM_MAX_HASH_FILE_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|v| v.clamp(4 * 1024, 64 * 1024 * 1024))
            .unwrap_or(2 * 1024 * 1024)
    }

    fn change_key(ch: &FimChange) -> String {
        format!(
            "{:?}|{}|{}",
            ch.op,
            ch.path,
            ch.old_path.as_deref().unwrap_or("")
        )
    }

    fn should_emit(&mut self, ch: &FimChange) -> bool {
        let now = Instant::now();
        self.recent_changes
            .retain(|_, ts| now.saturating_duration_since(*ts) <= self.dedup_window);

        let key = Self::change_key(ch);
        if let Some(last) = self.recent_changes.get(&key) {
            if now.saturating_duration_since(*last) <= self.dedup_window {
                return false;
            }
        }

        self.recent_changes.insert(key, now);
        true
    }

    fn start(
        agent_id: String,
        agent: crate::percepta::event::Agent,
        host: Host,
        paths: Vec<PathBuf>,
        recursive: bool,
        debounce: Duration,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel::<FimChange>(5000);

        let mode = if recursive {
            notify::RecursiveMode::Recursive
        } else {
            notify::RecursiveMode::NonRecursive
        };

        let mut watcher = notify::recommended_watcher(
            move |res: Result<notify::Event, notify::Error>| match res {
                Ok(ev) => {
                    if let Some(change) = map_notify_event(&ev) {
                        let _ = tx.send(change);
                    }
                }
                Err(e) => {
                    tracing::warn!("FIM notify error: {}", e);
                }
            },
        )
        .context("failed to start filesystem watcher")?;

        let _ = debounce; // notify does its own coalescing; we additionally bound drains per tick.

        // ISS-026/027: Validate FIM paths and detect symlink loops before watching.
        let mut canonical_set = std::collections::HashSet::new();
        for p in paths {
            if !p.exists() {
                tracing::warn!("FIM path '{}' does not exist -- skipping", p.display());
                continue;
            }
            // ISS-027: Resolve symlinks and skip duplicate canonical paths to prevent loops.
            match std::fs::canonicalize(&p) {
                Ok(canonical) => {
                    if !canonical_set.insert(canonical.clone()) {
                        tracing::warn!("FIM path '{}' resolves to already-watched '{}' -- skipping duplicate", p.display(), canonical.display());
                        continue;
                    }
                    watcher
                        .watch(&canonical, mode)
                        .with_context(|| format!("failed to watch path {}", p.display()))?;
                }
                Err(e) => {
                    tracing::warn!("FIM path '{}' cannot be resolved: {} -- skipping", p.display(), e);
                    continue;
                }
            }
        }

        Ok(Self {
            rx,
            _watcher: watcher,
            agent_id,
            agent,
            host,
            recent_changes: HashMap::new(),
            dedup_window: Self::dedup_window_from_env(),
            baseline_hashes: HashMap::new(),
            enable_hash_baseline: Self::hash_baseline_enabled(),
            max_hash_file_bytes: Self::max_hash_file_bytes(),
        })
    }

    async fn drain(&mut self, max_events: usize) -> Vec<Event> {
        let mut out = Vec::new();
        for _ in 0..max_events {
            match self.rx.try_recv() {
                Ok(ch) => {
                    if self.should_emit(&ch) {
                        out.push(self.build_event(ch).await);
                    }
                }
                Err(_) => break,
            }
        }
        out
    }

    async fn compute_sha256_if_small(&self, path: &str) -> Option<String> {
        let meta = fs::metadata(path).await.ok()?;
        if !meta.is_file() || meta.len() > self.max_hash_file_bytes {
            return None;
        }
        let bytes = fs::read(path).await.ok()?;
        Some(hex::encode(sha256(&bytes)))
    }

    async fn build_event(&mut self, ch: FimChange) -> Event {
        let ts = mk_now_ts();

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("sensor.kind".to_string(), "fim".to_string());
        if let Some(old) = ch.old_path.clone() {
            metadata.insert("file.old_path".to_string(), old);
        }

        if self.enable_hash_baseline {
            match ch.op {
                FileOperation::Created | FileOperation::Modified => {
                    if let Some(new_hash) = self.compute_sha256_if_small(&ch.path).await {
                        let old_hash = self
                            .baseline_hashes
                            .insert(ch.path.clone(), new_hash.clone());
                        metadata.insert("fim.hash_sha256".to_string(), new_hash.clone());
                        if let Some(prev) = old_hash {
                            if prev != new_hash {
                                metadata.insert("fim.hash_changed".to_string(), "true".to_string());
                                metadata.insert("fim.hash_old".to_string(), prev);
                                metadata.insert("fim.hash_new".to_string(), new_hash);
                            }
                        }
                    }
                }
                FileOperation::Deleted => {
                    if let Some(prev) = self.baseline_hashes.remove(&ch.path) {
                        metadata.insert("fim.hash_deleted_previous".to_string(), prev);
                    }
                }
                _ => {}
            }
        }

        let ev = Event {
            event_time: Some(ts.clone()),
            ingest_time: Some(ts),
            agent: Some(self.agent.clone()),
            host: Some(self.host.clone()),
            event: Some(EventDetails {
                summary: format!("FIM: {:?} {}", ch.op, ch.path),
                original_message: "".to_string(),
                category: EventCategory::File as i32,
                action: "fim".to_string(),
                outcome: EventOutcome::Success as i32,
                level: "Info".to_string(),
                severity: if metadata.contains_key("fim.hash_changed") {
                    3
                } else {
                    2
                },
                provider: "fim".to_string(),
                event_id: 0,
                record_id: 0,
            }),
            file: Some(File {
                path: ch.path.clone(),
                hash: std::collections::HashMap::new(),
                permissions: String::new(),
                operation: ch.op as i32,
            }),
            hash: mk_hash(&self.agent_id, &format!("fim:{:?}:{}", ch.op, ch.path)),
            tags: vec!["fim".to_string()],
            metadata,
            ..Default::default()
        };

        // If an IPS-like workflow blocks file operations on endpoint, set outcome=Blocked.
        // (We keep default Success here; downstream can choose.)
        ev
    }
}

fn map_notify_event(ev: &notify::Event) -> Option<FimChange> {
    use notify::event::{CreateKind, ModifyKind, RemoveKind, RenameMode};

    let kind = &ev.kind;
    let paths = &ev.paths;

    let (op, path, old_path) = match kind {
        // Handle rename before generic Modify.
        notify::EventKind::Modify(ModifyKind::Name(RenameMode::Both))
        | notify::EventKind::Modify(ModifyKind::Name(RenameMode::Any))
        | notify::EventKind::Modify(ModifyKind::Name(_)) => {
            let old = paths.first()?.to_string_lossy().to_string();
            let newp = paths
                .get(1)
                .unwrap_or(paths.first()?)
                .to_string_lossy()
                .to_string();
            // Proto does not have RENAMED; represent as MODIFIED with old path in metadata.
            (FileOperation::Modified, newp, Some(old))
        }

        notify::EventKind::Create(CreateKind::Any) | notify::EventKind::Create(_) => {
            let p = paths.first()?.to_string_lossy().to_string();
            (FileOperation::Created, p, None)
        }

        notify::EventKind::Modify(ModifyKind::Any)
        | notify::EventKind::Modify(ModifyKind::Data(_))
        | notify::EventKind::Modify(ModifyKind::Metadata(_))
        | notify::EventKind::Modify(ModifyKind::Other) => {
            let p = paths.first()?.to_string_lossy().to_string();
            (FileOperation::Modified, p, None)
        }

        notify::EventKind::Remove(RemoveKind::Any) | notify::EventKind::Remove(_) => {
            let p = paths.first()?.to_string_lossy().to_string();
            (FileOperation::Deleted, p, None)
        }

        _ => return None,
    };

    Some(FimChange { op, path, old_path })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_agent() -> crate::percepta::event::Agent {
        crate::percepta::event::Agent {
            id: "a1".to_string(),
            hostname: "h".to_string(),
            ip: "10.0.0.1".to_string(),
            ..Default::default()
        }
    }

    fn mk_host() -> Host {
        Host {
            ip: vec!["10.0.0.1".to_string()],
            mac: vec![],
        }
    }

    #[test]
    fn parses_suricata_alert() {
        let line = r#"{"event_type":"alert","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","dest_port":80,"proto":"TCP","alert":{"signature":"ET TEST","signature_id":2100001,"category":"Attempted","severity":2}}"#;
        let ev = parse_suricata_eve_line(line, &mk_agent(), &mk_host(), "a1").expect("event");
        assert!(ev.tags.iter().any(|t| t == "ids"));
        assert_eq!(
            ev.metadata.get("sensor.kind").map(|s| s.as_str()),
            Some("ids")
        );
        assert_eq!(
            ev.metadata.get("suricata.sid").map(|s| s.as_str()),
            Some("2100001")
        );
    }

    #[test]
    fn parses_cowrie_login_failed() {
        let line = r#"{"eventid":"cowrie.login.failed","src_ip":"3.3.3.3","dst_port":2222,"username":"root"}"#;
        let ev = parse_cowrie_json_line(line, &mk_agent(), &mk_host(), "a1").expect("event");
        assert!(ev.tags.iter().any(|t| t == "honeypot"));
        assert_eq!(
            ev.metadata.get("sensor.kind").map(|s| s.as_str()),
            Some("honeypot")
        );
        assert_eq!(
            ev.metadata.get("cowrie.username").map(|s| s.as_str()),
            Some("root")
        );
        assert_eq!(ev.event.as_ref().map(|e| e.severity), Some(3));
    }

    #[test]
    fn parses_cowrie_command_input_context() {
        let line = r#"{"eventid":"cowrie.command.input","src_ip":"4.4.4.4","src_port":54321,"dst_port":2222,"input":"uname -a","session":"s-1"}"#;
        let ev = parse_cowrie_json_line(line, &mk_agent(), &mk_host(), "a1").expect("event");
        assert_eq!(
            ev.metadata.get("cowrie.command").map(|s| s.as_str()),
            Some("uname -a")
        );
        assert_eq!(
            ev.metadata.get("activity").map(|s| s.as_str()),
            Some("uname -a")
        );
        assert_eq!(
            ev.metadata.get("cowrie.session").map(|s| s.as_str()),
            Some("s-1")
        );
        assert_eq!(
            ev.event.as_ref().map(|e| e.category),
            Some(EventCategory::Process as i32)
        );
    }
}
