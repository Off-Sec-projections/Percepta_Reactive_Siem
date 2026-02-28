//! Syslog Receiver Module
//!
//! Accepts syslog messages over UDP and TCP (RFC 3164 / RFC 5424),
//! parses them into SIEM Events, and feeds into the collector pipeline.

use anyhow::{Context, Result};
use chrono::Utc;
use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, warn};

use percepta_server::percepta::{
    event::{EventCategory, EventDetails, EventOutcome},
    Event,
};

/// Configuration for the syslog receiver.
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    pub udp_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    /// Maximum message size in bytes (RFC 5424 recommends 2048 for UDP).
    pub max_message_size: usize,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            udp_addr: "0.0.0.0:1514".parse().unwrap(),
            tcp_addr: "0.0.0.0:1514".parse().unwrap(),
            max_message_size: 8192,
        }
    }
}

/// Parsed syslog message fields.
struct SyslogMessage {
    facility: u8,
    severity: u8,
    timestamp: Option<String>,
    hostname: String,
    app_name: String,
    pid: Option<String>,
    message: String,
}

/// Start the syslog receivers (UDP + TCP). Returns a channel of parsed Events.
pub async fn start_syslog_receiver(config: SyslogConfig) -> Result<mpsc::Receiver<Event>> {
    let (tx, rx) = mpsc::channel::<Event>(4096);
    let send_timeout = Duration::from_millis(
        std::env::var("SYSLOG_QUEUE_SEND_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10_000),
    );

    // Start UDP listener
    let udp_tx = tx.clone();
    let udp_config = config.clone();
    percepta_server::spawn_monitored("syslog-udp", async move {
        if let Err(e) = run_udp_receiver(udp_config, udp_tx, send_timeout).await {
            error!("Syslog UDP receiver failed: {:#}", e);
        }
    });

    // Start TCP listener
    let tcp_tx = tx;
    percepta_server::spawn_monitored("syslog-tcp", async move {
        if let Err(e) = run_tcp_receiver(config, tcp_tx, send_timeout).await {
            error!("Syslog TCP receiver failed: {:#}", e);
        }
    });

    Ok(rx)
}

async fn run_udp_receiver(
    config: SyslogConfig,
    tx: mpsc::Sender<Event>,
    send_timeout: Duration,
) -> Result<()> {
    let socket = UdpSocket::bind(config.udp_addr)
        .await
        .with_context(|| format!("Failed to bind UDP syslog on {}", config.udp_addr))?;

    info!("Syslog UDP receiver listening on {}", config.udp_addr);

    let mut buf = vec![0u8; config.max_message_size];

    loop {
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!("Syslog UDP recv error: {}", e);
                continue;
            }
        };

        let raw = match std::str::from_utf8(&buf[..len]) {
            Ok(s) => s.trim(),
            Err(_) => continue,
        };

        if raw.is_empty() {
            continue;
        }

        if let Some(event) = parse_syslog_to_event(raw, src) {
            match timeout(send_timeout, tx.send(event)).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    debug!("Syslog event channel closed");
                    return Ok(());
                }
                Err(_) => {
                    warn!(
                        "Syslog UDP ingest backpressure: dropping message from {} after {}ms",
                        src,
                        send_timeout.as_millis()
                    );
                }
            }
        }
    }
}

async fn run_tcp_receiver(
    config: SyslogConfig,
    tx: mpsc::Sender<Event>,
    send_timeout: Duration,
) -> Result<()> {
    let listener = TcpListener::bind(config.tcp_addr)
        .await
        .with_context(|| format!("Failed to bind TCP syslog on {}", config.tcp_addr))?;

    info!("Syslog TCP receiver listening on {}", config.tcp_addr);

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Syslog TCP accept error: {}", e);
                continue;
            }
        };

        let tx = tx.clone();
        let max_line_bytes = config.max_message_size;
        tokio::spawn(async move {
            // Bound the BufReader capacity to prevent a single connection from
            // consuming unbounded memory with a never-terminated line.
            let reader = BufReader::with_capacity(max_line_bytes.min(64 * 1024), stream);
            let mut lines = reader.lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        if line.len() > max_line_bytes {
                            warn!(
                                "Syslog TCP line from {} exceeds max_message_size ({} > {}), dropping",
                                src, line.len(), max_line_bytes,
                            );
                            continue;
                        }
                        let raw = line.trim();
                        if raw.is_empty() {
                            continue;
                        }
                        if let Some(event) = parse_syslog_to_event(raw, src) {
                            match timeout(send_timeout, tx.send(event)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => return,
                                Err(_) => {
                                    warn!(
                                        "Syslog TCP ingest backpressure: closing connection {} after {}ms",
                                        src,
                                        send_timeout.as_millis()
                                    );
                                    return;
                                }
                            }
                        }
                    }
                    Ok(None) => return, // Connection closed cleanly
                    Err(e) => {
                        debug!("Syslog TCP read error from {}: {}", src, e);
                        return;
                    }
                }
            }
        });
    }
}


/// Parse a raw syslog line into a SIEM Event.
fn parse_syslog_to_event(raw: &str, src: SocketAddr) -> Option<Event> {
    // Try CEF format first
    if raw.contains("CEF:") {
        if let Some(ev) = parse_cef_to_event(raw, src) {
            return Some(ev);
        }
    }
    // Try LEEF format
    if raw.contains("LEEF:") {
        if let Some(ev) = parse_leef_to_event(raw, src) {
            return Some(ev);
        }
    }
    // Standard syslog
    let msg = parse_syslog_message(raw)?;

    let now = prost_types::Timestamp {
        seconds: Utc::now().timestamp(),
        nanos: 0,
    };

    let severity_val = match msg.severity {
        0..=2 => 4, // emergency/alert/critical → SIEM critical
        3 => 3,     // error → high
        4 => 2,     // warning → medium
        5 => 1,     // notice → low
        _ => 0,     // info/debug → info
    };

    let facility_name = match msg.facility {
        0 => "kern",
        1 => "user",
        2 => "mail",
        3 => "daemon",
        4 | 10 => "auth",
        5 => "syslog",
        6 => "lpr",
        7 => "news",
        9 => "cron",
        16..=23 => "local",
        _ => "unknown",
    };

    let category = match msg.facility {
        4 | 10 => EventCategory::Auth as i32,
        0 => EventCategory::System as i32,
        _ => EventCategory::Other as i32,
    };

    let hash_input = format!("syslog:{}:{}:{}", src, msg.hostname, raw);
    let hash = hex::encode(openssl::sha::sha256(hash_input.as_bytes()));

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("syslog.facility".to_string(), facility_name.to_string());
    metadata.insert("syslog.facility_code".to_string(), msg.facility.to_string());
    metadata.insert("syslog.severity_code".to_string(), msg.severity.to_string());
    metadata.insert("syslog.source_ip".to_string(), src.ip().to_string());
    metadata.insert("syslog.source_port".to_string(), src.port().to_string());
    if let Some(ref ts) = msg.timestamp {
        metadata.insert("syslog.timestamp".to_string(), ts.clone());
    }
    if let Some(ref pid) = msg.pid {
        metadata.insert("syslog.pid".to_string(), pid.clone());
    }
    metadata.insert("syslog.app_name".to_string(), msg.app_name.clone());

    let mut event = Event {
        event_time: Some(now.clone()),
        ingest_time: Some(now),
        event: Some(EventDetails {
            summary: format!(
                "[syslog] {} {}: {}",
                msg.hostname,
                msg.app_name,
                &msg.message[..msg.message.len().min(120)]
            ),
            original_message: raw.to_string(),
            category,
            action: "syslog_message".to_string(),
            outcome: EventOutcome::OutcomeUnknown as i32,
            level: syslog_severity_label(msg.severity).to_string(),
            severity: severity_val,
            provider: format!("syslog/{}", facility_name),
            event_id: 0,
            record_id: 0,
        }),
        hash,
        metadata,
        tags: vec!["syslog".to_string()],
        ..Default::default()
    };

    // Set network src_ip from the sending host
    event.network = Some(percepta_server::percepta::event::Network {
        src_ip: src.ip().to_string(),
        src_port: src.port() as u32,
        ..Default::default()
    });

    // Populate agent so syslog events appear in per-agent tracking and the Events tab
    event.agent = Some(percepta_server::percepta::event::Agent {
        id: src.ip().to_string(),
        hostname: msg.hostname.clone(),
        ip: src.ip().to_string(),
        ..Default::default()
    });

    // Set process info if we got app_name/pid
    if !msg.app_name.is_empty() {
        event.process = Some(percepta_server::percepta::event::Process {
            name: msg.app_name.clone(),
            pid: msg.pid.and_then(|p| p.parse().ok()).unwrap_or(0),
            ..Default::default()
        });
    }

    Some(event)
}

/// Parse RFC 3164 / RFC 5424 syslog message.
fn parse_syslog_message(raw: &str) -> Option<SyslogMessage> {
    // Both formats start with <PRI>
    if !raw.starts_with('<') {
        // Non-standard — treat as plain message
        return Some(SyslogMessage {
            facility: 1,
            severity: 6,
            timestamp: None,
            hostname: String::new(),
            app_name: String::new(),
            pid: None,
            message: raw.to_string(),
        });
    }

    let pri_end = raw.find('>')?;
    let pri: u16 = raw[1..pri_end].parse().ok()?;
    let facility = (pri / 8) as u8;
    let severity = (pri % 8) as u8;

    let rest = &raw[pri_end + 1..];

    // Try RFC 5424 first: VERSION SP TIMESTAMP SP HOSTNAME SP APP SP PROCID SP MSGID SP MSG
    if rest.starts_with('1') && rest.len() > 2 && rest.as_bytes()[1] == b' ' {
        return parse_rfc5424(facility, severity, &rest[2..]);
    }

    // RFC 3164: TIMESTAMP HOSTNAME APP[PID]: MSG
    parse_rfc3164(facility, severity, rest)
}

fn parse_rfc5424(facility: u8, severity: u8, rest: &str) -> Option<SyslogMessage> {
    let parts: Vec<&str> = rest.splitn(6, ' ').collect();
    if parts.len() < 6 {
        return Some(SyslogMessage {
            facility,
            severity,
            timestamp: None,
            hostname: String::new(),
            app_name: String::new(),
            pid: None,
            message: rest.to_string(),
        });
    }

    let timestamp = if parts[0] == "-" {
        None
    } else {
        Some(parts[0].to_string())
    };
    let hostname = if parts[1] == "-" {
        String::new()
    } else {
        parts[1].to_string()
    };
    let app_name = if parts[2] == "-" {
        String::new()
    } else {
        parts[2].to_string()
    };
    let pid = if parts[3] == "-" {
        None
    } else {
        Some(parts[3].to_string())
    };
    // parts[4] is MSGID, skip it
    let message = parts[5].to_string();

    Some(SyslogMessage {
        facility,
        severity,
        timestamp,
        hostname,
        app_name,
        pid,
        message,
    })
}

fn parse_rfc3164(facility: u8, severity: u8, rest: &str) -> Option<SyslogMessage> {
    // Typical: "Jan  1 00:00:00 hostname app[pid]: message"
    // Timestamp is first 15 chars for BSD format
    if rest.len() < 16 {
        return Some(SyslogMessage {
            facility,
            severity,
            timestamp: None,
            hostname: String::new(),
            app_name: String::new(),
            pid: None,
            message: rest.to_string(),
        });
    }

    let timestamp = Some(rest[..15].to_string());
    let after_ts = rest[16..].trim_start();

    let mut parts = after_ts.splitn(2, ' ');
    let hostname = parts.next().unwrap_or("").to_string();
    let remainder = parts.next().unwrap_or("");

    // Extract app[pid]: message
    let (app_name, pid, message) = if let Some(colon_pos) = remainder.find(':') {
        let tag = &remainder[..colon_pos];
        let msg = remainder[colon_pos + 1..].trim_start().to_string();

        if let Some(bracket_start) = tag.find('[') {
            let app = tag[..bracket_start].to_string();
            let pid_str = tag[bracket_start + 1..].trim_end_matches(']').to_string();
            (app, Some(pid_str), msg)
        } else {
            (tag.to_string(), None, msg)
        }
    } else {
        (String::new(), None, remainder.to_string())
    };

    Some(SyslogMessage {
        facility,
        severity,
        timestamp,
        hostname,
        app_name,
        pid,
        message,
    })
}

fn syslog_severity_label(severity: u8) -> &'static str {
    match severity {
        0 => "Emergency",
        1 => "Alert",
        2 => "Critical",
        3 => "Error",
        4 => "Warning",
        5 => "Notice",
        6 => "Info",
        7 => "Debug",
        _ => "Unknown",
    }
}

// ── CEF Parser (ArcSight Common Event Format) ──────────────────────────────

/// Parse a CEF-formatted syslog message.
/// Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
fn parse_cef_to_event(raw: &str, src: SocketAddr) -> Option<Event> {
    // Find CEF header start
    let cef_start = raw.find("CEF:")?;
    let cef_body = &raw[cef_start + 4..];

    let parts: Vec<&str> = cef_body.splitn(8, '|').collect();
    if parts.len() < 8 {
        return None;
    }

    let _version = parts[0];
    let vendor = parts[1];
    let product = parts[2];
    let _device_version = parts[3];
    let sig_id = parts[4];
    let name = parts[5];
    let severity_str = parts[6];
    let extension = parts[7];

    let severity_val: i32 = match severity_str.parse::<i32>() {
        Ok(n) if n >= 8 => 4, // critical
        Ok(n) if n >= 6 => 3, // high
        Ok(n) if n >= 4 => 2, // medium
        Ok(n) if n >= 1 => 1, // low
        _ => 0,               // info
    };

    let now = prost_types::Timestamp {
        seconds: Utc::now().timestamp(),
        nanos: 0,
    };

    let hash_input = format!("cef:{}:{}:{}", src, sig_id, raw);
    let hash = hex::encode(openssl::sha::sha256(hash_input.as_bytes()));

    // Parse CEF extension key=value pairs
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("cef.vendor".to_string(), vendor.to_string());
    metadata.insert("cef.product".to_string(), product.to_string());
    metadata.insert("cef.signature_id".to_string(), sig_id.to_string());
    metadata.insert("cef.name".to_string(), name.to_string());
    metadata.insert("cef.severity".to_string(), severity_str.to_string());
    metadata.insert("sensor.kind".to_string(), "cef".to_string());

    let mut src_ip = String::new();
    let mut dst_ip = String::new();
    let mut src_port: u32 = 0;
    let mut dst_port: u32 = 0;

    for pair in extension.split_whitespace() {
        if let Some(eq) = pair.find('=') {
            let k = &pair[..eq];
            let v = &pair[eq + 1..];
            metadata.insert(format!("cef.{}", k), v.to_string());
            match k {
                "src" | "sourceAddress" => src_ip = v.to_string(),
                "dst" | "destinationAddress" => dst_ip = v.to_string(),
                "spt" | "sourcePort" => src_port = v.parse().unwrap_or(0),
                "dpt" | "destinationPort" => dst_port = v.parse().unwrap_or(0),
                "duser" => {
                    metadata.insert("user.name".to_string(), v.to_string());
                }
                _ => {}
            }
        }
    }

    let mut event = Event {
        event_time: Some(now.clone()),
        ingest_time: Some(now),
        event: Some(percepta_server::percepta::event::EventDetails {
            summary: format!("[CEF] {} {} — {}", vendor, product, name),
            original_message: raw.to_string(),
            category: percepta_server::percepta::event::EventCategory::Other as i32,
            action: "cef_event".to_string(),
            outcome: percepta_server::percepta::event::EventOutcome::OutcomeUnknown as i32,
            level: match severity_val {
                4 => "Critical",
                3 => "Error",
                2 => "Warning",
                1 => "Info",
                _ => "Info",
            }
            .to_string(),
            severity: severity_val,
            provider: format!("{}/{}", vendor, product),
            event_id: 0,
            record_id: 0,
        }),
        hash,
        metadata,
        tags: vec!["cef".to_string(), "syslog".to_string()],
        ..Default::default()
    };

    if !src_ip.is_empty() || !dst_ip.is_empty() {
        event.network = Some(percepta_server::percepta::event::Network {
            src_ip: if src_ip.is_empty() {
                src.ip().to_string()
            } else {
                src_ip
            },
            dst_ip,
            src_port,
            dst_port,
            ..Default::default()
        });
    }

    Some(event)
}

// ── LEEF Parser (IBM QRadar Log Event Extended Format) ─────────────────────

/// Parse a LEEF-formatted syslog message.
/// Format: LEEF:Version|Vendor|Product|Version|EventID|delimiter?|key=value pairs
fn parse_leef_to_event(raw: &str, src: SocketAddr) -> Option<Event> {
    let leef_start = raw.find("LEEF:")?;
    let leef_body = &raw[leef_start + 5..];

    let parts: Vec<&str> = leef_body.splitn(6, '|').collect();
    if parts.len() < 6 {
        return None;
    }

    let _version = parts[0];
    let vendor = parts[1];
    let product = parts[2];
    let _prod_version = parts[3];
    let event_id = parts[4];
    let attrs = parts[5];

    // LEEF 2.0 allows custom delimiter as first char; default is tab
    let delimiter = if attrs.starts_with('\t') || attrs.starts_with(char::is_alphanumeric) {
        '\t'
    } else {
        let d = attrs.chars().next().unwrap_or('\t');
        d
    };

    let now = prost_types::Timestamp {
        seconds: Utc::now().timestamp(),
        nanos: 0,
    };

    let hash_input = format!("leef:{}:{}:{}", src, event_id, raw);
    let hash = hex::encode(openssl::sha::sha256(hash_input.as_bytes()));

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("leef.vendor".to_string(), vendor.to_string());
    metadata.insert("leef.product".to_string(), product.to_string());
    metadata.insert("leef.event_id".to_string(), event_id.to_string());
    metadata.insert("sensor.kind".to_string(), "leef".to_string());

    let mut src_ip = String::new();
    let mut dst_ip = String::new();

    for pair in attrs.split(delimiter) {
        if let Some(eq) = pair.find('=') {
            let k = pair[..eq].trim();
            let v = pair[eq + 1..].trim();
            if !k.is_empty() {
                metadata.insert(format!("leef.{}", k), v.to_string());
                match k {
                    "src" | "srcIP" => src_ip = v.to_string(),
                    "dst" | "dstIP" => dst_ip = v.to_string(),
                    "usrName" => {
                        metadata.insert("user.name".to_string(), v.to_string());
                    }
                    _ => {}
                }
            }
        }
    }

    let severity_val = 1; // LEEF doesn't standardise severity; default to low

    let mut event = Event {
        event_time: Some(now.clone()),
        ingest_time: Some(now),
        event: Some(percepta_server::percepta::event::EventDetails {
            summary: format!("[LEEF] {} {} — {}", vendor, product, event_id),
            original_message: raw.to_string(),
            category: percepta_server::percepta::event::EventCategory::Other as i32,
            action: "leef_event".to_string(),
            outcome: percepta_server::percepta::event::EventOutcome::OutcomeUnknown as i32,
            level: "Info".to_string(),
            severity: severity_val,
            provider: format!("{}/{}", vendor, product),
            event_id: 0,
            record_id: 0,
        }),
        hash,
        metadata,
        tags: vec!["leef".to_string(), "syslog".to_string()],
        ..Default::default()
    };

    if !src_ip.is_empty() || !dst_ip.is_empty() {
        event.network = Some(percepta_server::percepta::event::Network {
            src_ip: if src_ip.is_empty() {
                src.ip().to_string()
            } else {
                src_ip
            },
            dst_ip,
            ..Default::default()
        });
    }

    Some(event)
}
