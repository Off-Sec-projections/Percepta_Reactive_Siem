//! Built-in honeypot trap system for Percepta SIEM.
//!
//! Provides:
//! - **Web traps**: Fake endpoints embedded in the HTTPS server that mimic
//!   vulnerable admin panels, exposed config files, login forms, etc.
//! - **TCP port traps**: Lightweight listeners on configurable ports that log
//!   every inbound connection and optionally serve fake service banners.
//! - **Credential canaries**: A fake login form that records submitted creds.
//! - **Attacker profiling**: Tracks repeat offenders across trap hits.
//!
//! Every trap hit is converted into a full `Event` and pushed through the
//! normal SIEM pipeline (storage → rules engine → alerts → dashboard).

use crate::enroll::AppState;
use crate::reactive::ReactiveStoreHandle;
use crate::storage::StorageService;
use crate::websocket::StreamMessage;
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, Request, StatusCode},
    response::{Html, IntoResponse},
};
use percepta_server::percepta::{self, Event};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Cached local IP address of the server for dst_ip enrichment.
fn server_local_ip() -> &'static str {
    use once_cell::sync::Lazy;
    static IP: Lazy<String> = Lazy::new(|| {
        local_ip_address::local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_default()
    });
    &IP
}

/// Cached public IP address of the server for honeypot dst_ip.
/// Reads from PERCEPTA_PUBLIC_HOST env var first, otherwise falls back to local IP.
fn server_public_ip() -> &'static str {
    use once_cell::sync::Lazy;
    static PUB_IP: Lazy<String> = Lazy::new(|| {
        if let Ok(host) = std::env::var("PERCEPTA_PUBLIC_HOST") {
            if host.parse::<std::net::IpAddr>().is_ok() {
                return host;
            }
            // Resolve hostname to IP
            if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0)) {
                for addr in addrs {
                    if !addr.ip().is_loopback() {
                        return addr.ip().to_string();
                    }
                }
            }
        }
        server_local_ip().to_string()
    });
    &PUB_IP
}

// ── Trap event builder ─────────────────────────────────────────────────────

/// Context for building a honeypot trap event.
pub struct TrapContext<'a> {
    src_ip: &'a str,
    src_port: u16,
    trap_name: &'a str,
    trap_path: &'a str,
    method: &'a str,
    user_agent: &'a str,
    extra_meta: HashMap<String, String>,
    severity: i32,
    summary: &'a str,
}

/// Create a honeypot trap event from an HTTP request context.
pub fn build_trap_event(ctx: TrapContext<'_>) -> Event {
    let now = chrono::Utc::now();
    let ts = prost_types::Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    };

    let mut metadata: HashMap<String, String> = HashMap::new();
    metadata.insert("sensor.kind".into(), "honeypot".into());
    metadata.insert("honeypot.trap".into(), ctx.trap_name.into());
    metadata.insert("honeypot.path".into(), ctx.trap_path.into());
    metadata.insert("honeypot.method".into(), ctx.method.into());
    metadata.insert("honeypot.user_agent".into(), ctx.user_agent.into());
    metadata.insert("honeypot.event".into(), format!("trap.{}", ctx.trap_name));
    for (k, v) in ctx.extra_meta {
        metadata.insert(k, v);
    }

    let hash_input = format!(
        "honeypot:{}:{}:{}:{}",
        ctx.src_ip,
        ctx.trap_name,
        ctx.trap_path,
        now.timestamp_millis()
    );
    let hash = format!("{:x}", md5_hash(hash_input.as_bytes()));

    // Honeypot is the attacked server, not an agent — leave agent field empty
    // so dashboards show attacker IP (network.src_ip) and target host instead.
    metadata.insert("attacker.ip".into(), ctx.src_ip.into());
    metadata.insert("attacked.host".into(), server_public_ip().to_string());

    Event {
        event_time: Some(ts.clone()),
        ingest_time: Some(ts),
        agent: None,
        event: Some(percepta::event::EventDetails {
            summary: ctx.summary.into(),
            original_message: format!(
                "{} {} from {} (UA: {})",
                ctx.method, ctx.trap_path, ctx.src_ip, ctx.user_agent
            ),
            category: percepta::event::EventCategory::Network as i32,
            action: format!("trap.{}", ctx.trap_name),
            outcome: percepta::event::EventOutcome::Failure as i32,
            level: if ctx.severity >= 4 {
                "Critical"
            } else if ctx.severity >= 3 {
                "High"
            } else {
                "Medium"
            }
            .into(),
            severity: ctx.severity,
            provider: "percepta-honeypot".into(),
            event_id: 0,
            record_id: 0,
        }),
        user: None,
        host: Some(percepta::event::Host {
            ip: vec![server_public_ip().to_string()],
            ..Default::default()
        }),
        network: Some(percepta::event::Network {
            src_ip: ctx.src_ip.into(),
            src_port: ctx.src_port as u32,
            dst_ip: server_public_ip().to_string(),
            dst_port: 0,
            protocol: "tcp".into(),
            direction: percepta::event::NetworkDirection::Inbound as i32,
            bytes_in: 0,
            bytes_out: 0,
            flow_duration_ms: 0,
            tls_sni: String::new(),
            ja3: String::new(),
            ja3s: String::new(),
            tls_cert_subject: String::new(),
            tls_cert_issuer: String::new(),
        }),
        process: None,
        file: None,
        registry: None,
        metadata,
        tags: vec!["honeypot".into(), "trap".into(), ctx.trap_name.into()],
        threat_indicator: ctx.src_ip.into(),
        threat_source: "percepta-honeypot-trap".into(),
        correlation_id: String::new(),
        hash,
    }
}

/// Build a trap event for a raw TCP connection (non-HTTP port trap).
pub fn build_tcp_trap_event(
    src_ip: &str,
    src_port: u16,
    dst_port: u16,
    service_name: &str,
    banner_sent: bool,
) -> Event {
    let summary = format!(
        "TCP trap hit on port {} ({}) from {}:{}",
        dst_port, service_name, src_ip, src_port
    );
    let mut extra = HashMap::new();
    extra.insert("honeypot.dst_port".into(), dst_port.to_string());
    extra.insert("honeypot.service".into(), service_name.into());
    extra.insert("honeypot.banner_sent".into(), banner_sent.to_string());
    extra.insert("honeypot.protocol".into(), "tcp".into());

    let trap_path = format!(":{}", dst_port);
    let ctx = TrapContext {
        src_ip,
        src_port,
        trap_name: "tcp_port",
        trap_path: &trap_path,
        method: "CONNECT",
        user_agent: "",
        extra_meta: extra,
        severity: 3,
        summary: &summary,
    };
    let mut ev = build_trap_event(ctx);
    if let Some(ref mut net) = ev.network {
        net.dst_port = dst_port as u32;
    }
    ev.tags.push(service_name.to_lowercase());
    ev
}

fn apply_threat_profile_metadata(ev: &mut Event, profile: &ThreatProfile) {
    ev.metadata.insert(
        "honeypot.threat_score".into(),
        profile.score.to_string(),
    );
    ev.metadata
        .insert("honeypot.threat_level".into(), profile.level.clone());
    ev.metadata.insert(
        "honeypot.attacker_hits".into(),
        profile.total_hits.to_string(),
    );
    ev.metadata.insert(
        "honeypot.unique_traps".into(),
        profile.unique_traps.to_string(),
    );
    ev.metadata.insert(
        "honeypot.last_seen_ts".into(),
        profile.last_seen_ts.to_string(),
    );
    ev.metadata
        .insert("risk_score".into(), profile.score.to_string());
    if profile.score >= 80 {
        ev.tags.push("threat-critical".into());
    } else if profile.score >= 60 {
        ev.tags.push("threat-high".into());
    } else if profile.score >= 35 {
        ev.tags.push("threat-medium".into());
    } else {
        ev.tags.push("threat-low".into());
    }
}

// ── Ingest helper ──────────────────────────────────────────────────────────

/// Ingest a trap event into the SIEM pipeline: store, broadcast, run rules.
pub async fn ingest_trap_event(
    storage: &Arc<StorageService>,
    broadcaster: &Arc<broadcast::Sender<StreamMessage>>,
    rule_engine: &Arc<percepta_server::rule_engine::RuleEngine>,
    event: Event,
) {
    // Persist
    if let Err(e) = storage.store_event(&event).await {
        warn!("Honeypot trap: failed to store event: {e:#}");
    }
    // Broadcast to dashboards
    let _ = broadcaster.send(StreamMessage::Event(event.clone()));
    // Run rules (may generate alerts)
    if let Err(e) = rule_engine.evaluate_event(&event).await {
        warn!("Honeypot trap: rule evaluation failed: {e:#}");
    }
}

// ── Web trap handlers ──────────────────────────────────────────────────────

/// Extract the real client IP and first-hop port from the request.
fn client_info(headers: &HeaderMap, addr: &SocketAddr) -> (String, u16) {
    // Trust X-Forwarded-For / X-Real-Ip when set by a reverse proxy.
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| addr.ip().to_string());
    (ip, addr.port())
}

fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

/// Helper: handle a generic web trap hit and return a convincing response.
async fn handle_web_trap(
    state: &AppState,
    headers: &HeaderMap,
    addr: &SocketAddr,
    ctx: TrapContext<'_>,
) {
    let (ip, port) = client_info(headers, addr);
    let ua = user_agent(headers);
    let profile = state.trap_tracker.record(&ip, ctx.trap_name).await;
    let mut extra_meta = ctx.extra_meta;
    extra_meta.insert("honeypot.threat_score".into(), profile.score.to_string());
    extra_meta.insert("honeypot.threat_level".into(), profile.level.clone());
    extra_meta.insert("honeypot.attacker_hits".into(), profile.total_hits.to_string());
    extra_meta.insert("honeypot.unique_traps".into(), profile.unique_traps.to_string());
    extra_meta.insert("risk_score".into(), profile.score.to_string());
    let trap_ctx = TrapContext {
        src_ip: &ip,
        src_port: port,
        trap_name: ctx.trap_name,
        trap_path: ctx.trap_path,
        method: ctx.method,
        user_agent: &ua,
        extra_meta,
        severity: ctx.severity,
        summary: ctx.summary,
    };
    let mut ev = build_trap_event(trap_ctx);
    apply_threat_profile_metadata(&mut ev, &profile);
    ingest_trap_event(
        &state.storage_service,
        &state.event_broadcaster,
        &state.rule_engine,
        ev,
    )
    .await;
}

// ── Fake WordPress admin ───────────────────────────────────────────────────

pub async fn trap_wp_admin(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let summary = format!(
        "WordPress admin probe from {}",
        client_info(&headers, &addr).0
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "wp_admin",
        trap_path: "/wp-admin",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 3,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    fake_wp_login_page()
}

pub async fn trap_wp_login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let summary = format!(
        "WordPress login probe from {}",
        client_info(&headers, &addr).0
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "wp_login",
        trap_path: "/wp-login.php",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 3,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    fake_wp_login_page()
}

/// POST /wp-login.php — credential canary
pub async fn trap_wp_login_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let mut extra = HashMap::new();
    let mut submitted_user = String::new();
    // Parse form body for username (never log passwords in plain text for ethics,
    // but record that a credential-stuffing attempt occurred).
    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let k = urlencoding_decode(k);
            let v = urlencoding_decode(v);
            if k == "log" || k == "username" || k == "user" {
                submitted_user = v.clone();
                extra.insert("honeypot.credential_user".into(), v);
            } else if k == "pwd" || k == "password" || k == "pass" {
                // Record that a password was submitted but hash it — never store plaintext.
                extra.insert("honeypot.credential_submitted".into(), "true".into());
            }
        }
    }
    extra.insert("honeypot.interaction_stage".into(), "login_submit".into());
    let summary = format!(
        "Credential stuffing via WordPress login from {}",
        client_info(&headers, &addr).0
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "credential_canary",
        trap_path: "/wp-login.php",
        method: "POST",
        user_agent: "",
        extra_meta: extra,
        severity: 4,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    (StatusCode::OK, fake_wp_dashboard_page(&submitted_user))
}

/// POST /wp-admin/admin-ajax.php — stage-2 high-interaction decoy action capture
pub async fn trap_wp_admin_ajax(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let mut extra = HashMap::new();
    let mut action_name = String::new();
    let mut cmd_preview = String::new();

    for pair in body.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let key = urlencoding_decode(k);
            let val = urlencoding_decode(v);
            match key.as_str() {
                "action" => {
                    action_name = val.clone();
                    extra.insert("honeypot.wp.action".into(), val);
                }
                "cmd" | "command" | "query" | "sql" | "payload" => {
                    let capped: String = val.chars().take(200).collect();
                    if cmd_preview.is_empty() {
                        cmd_preview = capped.clone();
                    }
                    extra.insert(format!("honeypot.wp.{}", key), capped);
                }
                _ => {
                    let capped: String = val.chars().take(120).collect();
                    extra.insert(format!("honeypot.wp.{}", key), capped);
                }
            }
        }
    }

    extra.insert("honeypot.interaction_stage".into(), "admin_ajax".into());
    let severity = if cmd_preview.is_empty() { 4 } else { 5 };
    let summary = format!(
        "WordPress admin-ajax stage-2 interaction '{}' from {}",
        if action_name.trim().is_empty() {
            "unknown"
        } else {
            action_name.trim()
        },
        client_info(&headers, &addr).0
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "wp_admin_stage2",
        trap_path: "/wp-admin/admin-ajax.php",
        method: "POST",
        user_agent: "",
        extra_meta: extra,
        severity,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({"success": true, "data": {"status": "queued", "msg": "Task accepted"}})
            .to_string(),
    )
}

// ── Fake phpMyAdmin ────────────────────────────────────────────────────────

pub async fn trap_phpmyadmin(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (src_ip, _) = client_info(&headers, &addr);
    let summary = format!("phpMyAdmin probe from {}", src_ip);
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "phpmyadmin",
        trap_path: "/phpmyadmin",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 3,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    Html(fake_phpmyadmin_html(&src_ip, &user_agent(&headers)))
}

// ── Exposed config / secrets traps ─────────────────────────────────────────

pub async fn trap_env_file(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (src_ip, _) = client_info(&headers, &addr);
    let summary = format!(".env file probe from {}", src_ip);
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "env_probe",
        trap_path: "/.env",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 4,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    // Return a fake .env that looks juicy but is all canary data
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        fake_env_contents(&src_ip, &user_agent(&headers)),
    )
}

pub async fn trap_git_config(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let summary = format!(".git/config probe from {}", client_info(&headers, &addr).0);
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "git_probe",
        trap_path: "/.git/config",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 4,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://github.com/acme-corp/internal-app.git\n",
    )
}

pub async fn trap_ds_store(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let summary = format!(".DS_Store probe from {}", client_info(&headers, &addr).0);
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "ds_store_probe",
        trap_path: "/.DS_Store",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 2,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    StatusCode::NOT_FOUND
}

// ── Generic admin / shell traps ────────────────────────────────────────────

pub async fn trap_admin_panel(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
) -> impl IntoResponse {
    let path = request.uri().path().to_string();
    let (src_ip, _) = client_info(&headers, &addr);
    let summary = format!(
        "Admin panel probe {} from {}",
        path,
        src_ip
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "admin_probe",
        trap_path: &path,
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 3,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    Html(fake_admin_html(&src_ip, &path, &user_agent(&headers)))
}

pub async fn trap_shell_endpoint(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
) -> impl IntoResponse {
    let path = request.uri().path().to_string();
    let summary = format!(
        "Shell/command injection probe {} from {}",
        path,
        client_info(&headers, &addr).0
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "shell_probe",
        trap_path: &path,
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 4,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    (StatusCode::FORBIDDEN, "Access Denied")
}

// ── Fake API endpoints ─────────────────────────────────────────────────────

pub async fn trap_api_users(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let summary = format!(
        "Fake API /api/v1/users probe from {}",
        client_info(&headers, &addr).0
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "api_probe",
        trap_path: "/api/v1/users",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 3,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({
            "users": [
                {"id": 1, "username": "admin", "email": "admin@acme-corp.internal", "role": "superadmin"},
                {"id": 2, "username": "backup_svc", "email": "backup@acme-corp.internal", "role": "service"},
            ]
        }).to_string(),
    )
}

pub async fn trap_api_config(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let summary = format!(
        "Fake API /api/v1/config probe from {}",
        client_info(&headers, &addr).0
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "api_probe",
        trap_path: "/api/v1/config",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 3,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({
            "database": {"host": "db.acme-corp.internal", "port": 5432, "name": "production"},
            "redis": {"host": "cache.acme-corp.internal"},
            "aws": {"region": "us-east-1", "bucket": "acme-backups"}
        })
        .to_string(),
    )
}

// ── robots.txt trap (guide scanners to more traps) ─────────────────────────

pub async fn trap_robots_txt(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Log the access but at low severity since robots.txt is commonly fetched.
    let summary = format!("robots.txt fetch from {}", client_info(&headers, &addr).0);
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "robots",
        trap_path: "/robots.txt",
        method: "GET",
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 1,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        "User-agent: *\nDisallow: /wp-admin/\nDisallow: /administrator/\nDisallow: /phpmyadmin/\nDisallow: /api/v1/users\nDisallow: /api/v1/config\nDisallow: /.env\nDisallow: /backup/\nDisallow: /debug/\n",
    )
}

// ── Catch-all for common scanner paths ─────────────────────────────────────

/// This handles a batch of well-known scanner paths.
pub async fn trap_scanner_catch_all(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    request: Request<Body>,
) -> impl IntoResponse {
    let path = request.uri().path().to_string();
    let method = request.method().to_string();
    let summary = format!(
        "Scanner probe {} {} from {}",
        method,
        path,
        client_info(&headers, &addr).0
    );
    let ctx = TrapContext {
        src_ip: "",
        src_port: 0,
        trap_name: "scanner",
        trap_path: &path,
        method: &method,
        user_agent: "",
        extra_meta: HashMap::new(),
        severity: 3,
        summary: &summary,
    };
    handle_web_trap(&state, &headers, &addr, ctx).await;
    StatusCode::NOT_FOUND
}

// ── TCP port trap listener ─────────────────────────────────────────────────

/// Configuration for a single TCP port trap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortTrapConfig {
    pub port: u16,
    pub service_name: String,
    /// Fake banner to send upon connection (e.g. "SSH-2.0-OpenSSH_7.6p1").
    pub banner: Option<String>,
}

impl PortTrapConfig {
    pub fn defaults() -> Vec<Self> {
        vec![
            Self { port: 2222, service_name: "SSH".into(), banner: Some("SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3\r\n".into()) },
            Self { port: 2121, service_name: "FTP".into(), banner: Some("220 ProFTPD 1.3.5 Server (Debian) [0.0.0.0]\r\n".into()) },
            Self { port: 2323, service_name: "Telnet".into(), banner: Some("\r\nLogin: ".into()) },
            Self { port: 8888, service_name: "HTTP-Alt".into(), banner: Some("HTTP/1.1 200 OK\r\nServer: Apache/2.4.29\r\n\r\n<html><body><h1>It works!</h1></body></html>".into()) },
            Self { port: 3390, service_name: "RDP".into(), banner: None },
            Self { port: 5901, service_name: "VNC".into(), banner: Some("RFB 003.008\n".into()) },
            Self { port: 9200, service_name: "Elasticsearch".into(), banner: None },
            Self { port: 6379, service_name: "Redis".into(), banner: Some("-ERR operation not permitted\r\n".into()) },
            Self { port: 4450, service_name: "SMB".into(), banner: None },
            Self { port: 1884, service_name: "MQTT".into(), banner: None },
            Self { port: 3307, service_name: "MySQL".into(), banner: Some("5.7.42-0ubuntu0.18.04.1\x00".into()) },
        ]
    }
}

/// Spawn TCP honeypot listeners. Each listener logs every connection as a trap event.
pub fn spawn_tcp_traps(
    storage: Arc<StorageService>,
    broadcaster: Arc<broadcast::Sender<StreamMessage>>,
    rule_engine: Arc<percepta_server::rule_engine::RuleEngine>,
    reactive: ReactiveStoreHandle,
    trap_tracker: Arc<TrapTracker>,
    configs: Vec<PortTrapConfig>,
) {
    for cfg in configs {
        let storage = storage.clone();
        let broadcaster = broadcaster.clone();
        let rule_engine = rule_engine.clone();
        let reactive = reactive.clone();
        let trap_tracker = trap_tracker.clone();
        percepta_server::spawn_monitored("honeypot-tcp-trap", async move {
            run_port_trap(cfg, storage, broadcaster, rule_engine, reactive, trap_tracker).await;
        });
    }
}

async fn run_port_trap(
    cfg: PortTrapConfig,
    storage: Arc<StorageService>,
    broadcaster: Arc<broadcast::Sender<StreamMessage>>,
    rule_engine: Arc<percepta_server::rule_engine::RuleEngine>,
    reactive: ReactiveStoreHandle,
    trap_tracker: Arc<TrapTracker>,
) {
    let addr: std::net::SocketAddr = ([0, 0, 0, 0], cfg.port).into();
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => {
            info!(
                "🍯 Honeypot TCP trap listening on port {} ({})",
                cfg.port, cfg.service_name
            );
            l
        }
        Err(e) => {
            warn!(
                "🍯 Honeypot TCP trap: cannot bind port {} ({}): {}",
                cfg.port, cfg.service_name, e
            );
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut stream, peer)) => {
                let cfg = cfg.clone();
                let storage = storage.clone();
                let broadcaster = broadcaster.clone();
                let rule_engine = rule_engine.clone();
                let reactive = reactive.clone();
                let trap_tracker = trap_tracker.clone();
                tokio::spawn(async move {
                    let src_ip = peer.ip().to_string();
                    let src_port = peer.port();
                    let banner_sent = cfg.banner.is_some();
                    let profile = trap_tracker.record(&src_ip, "tcp_port").await;

                    // Auto-block repeat offenders (5-minute block per IP per port hit)
                    if let Err(e) = reactive
                        .block_ip(
                            &src_ip,
                            300,
                            "honeypot-trap",
                            Some(format!(
                                "TCP trap hit on port {} ({})",
                                cfg.port, cfg.service_name
                            )),
                        )
                        .await
                    {
                        tracing::warn!("Honeypot: failed to block {src_ip}: {e:#}");
                    }

                    // Send banner if configured.
                    if let Some(ref banner) = cfg.banner {
                        use tokio::io::AsyncWriteExt;
                        let _ = stream.write_all(banner.as_bytes()).await;
                        // Read up to 1 KB of attacker input (for context), then close.
                        use tokio::io::AsyncReadExt;
                        let mut buf = [0u8; 1024];
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            stream.read(&mut buf),
                        )
                        .await;
                    }

                    let mut ev = build_tcp_trap_event(
                        &src_ip,
                        src_port,
                        cfg.port,
                        &cfg.service_name,
                        banner_sent,
                    );
                    apply_threat_profile_metadata(&mut ev, &profile);
                    ingest_trap_event(&storage, &broadcaster, &rule_engine, ev).await;
                });
            }
            Err(e) => {
                warn!("🍯 TCP trap accept error on port {}: {}", cfg.port, e);
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
    }
}

// ── Honeypot stats (in-memory counters) ────────────────────────────────────

/// Lightweight in-memory tracker of trap hits per attacker IP.
pub struct TrapTracker {
    inner: tokio::sync::RwLock<TrapTrackerInner>,
}

struct TrapTrackerInner {
    /// ip -> list of (timestamp, trap_name)
    hits: HashMap<String, Vec<(i64, String)>>,
    /// total hits since last reset
    total: u64,
}

impl TrapTracker {
    pub fn new() -> Self {
        Self {
            inner: tokio::sync::RwLock::new(TrapTrackerInner {
                hits: HashMap::new(),
                total: 0,
            }),
        }
    }

    pub async fn record(&self, ip: &str, trap: &str) -> ThreatProfile {
        let mut g = self.inner.write().await;
        let now = chrono::Utc::now().timestamp();
        g.hits
            .entry(ip.to_string())
            .or_default()
            .push((now, trap.to_string()));
        g.total += 1;
        let hits = g.hits.get(ip).cloned().unwrap_or_default();
        Self::compute_profile(ip, &hits, now)
    }

    fn compute_profile(ip: &str, hits: &[(i64, String)], now_ts: i64) -> ThreatProfile {
        let total_hits = hits.len();
        let mut unique_traps = std::collections::HashSet::new();
        let mut weighted_score = 0.0f64;
        let mut burst_last_10m = 0usize;
        let mut last_seen_ts = 0i64;

        for (ts, trap) in hits {
            unique_traps.insert(trap.clone());
            last_seen_ts = last_seen_ts.max(*ts);
            let age = (now_ts - *ts).max(0);
            let recency_factor = if age <= 300 {
                1.0
            } else if age <= 3600 {
                0.85
            } else if age <= 86_400 {
                0.65
            } else {
                0.45
            };
            weighted_score += trap_weight(trap) as f64 * recency_factor;
            if age <= 600 {
                burst_last_10m += 1;
            }
        }

        weighted_score += (unique_traps.len() as f64) * 4.0;
        if burst_last_10m >= 3 {
            weighted_score += (burst_last_10m as f64) * 2.5;
        }
        weighted_score += (total_hits as f64).ln_1p() * 7.0;
        let score = weighted_score.round().clamp(0.0, 100.0) as u32;
        let level = if score >= 80 {
            "Critical"
        } else if score >= 60 {
            "High"
        } else if score >= 35 {
            "Medium"
        } else {
            "Low"
        }
        .to_string();

        ThreatProfile {
            ip: ip.to_string(),
            score,
            level,
            total_hits,
            unique_traps: unique_traps.len(),
            burst_last_10m,
            last_seen_ts,
        }
    }

    pub async fn snapshot(&self) -> TrapStats {
        let g = self.inner.read().await;
        let now = chrono::Utc::now().timestamp();
        let unique_attackers = g.hits.len();
        let total_hits = g.total as usize;

        // Top attackers by hit count
        let mut by_count: Vec<(String, usize)> = g
            .hits
            .iter()
            .map(|(ip, hits)| (ip.clone(), hits.len()))
            .collect();
        by_count.sort_by(|a, b| b.1.cmp(&a.1));
        by_count.truncate(20);

        let mut top_threats: Vec<ThreatProfile> = g
            .hits
            .iter()
            .map(|(ip, hits)| Self::compute_profile(ip, hits, now))
            .collect();
        top_threats.sort_by(|a, b| b.score.cmp(&a.score).then(b.total_hits.cmp(&a.total_hits)));
        top_threats.truncate(20);

        // Trap breakdown
        let mut by_trap: HashMap<String, usize> = HashMap::new();
        for hits in g.hits.values() {
            for (_, trap) in hits {
                *by_trap.entry(trap.clone()).or_default() += 1;
            }
        }

        // Recent hits (last 50)
        let mut recent: Vec<(i64, String, String)> = Vec::new();
        for (ip, hits) in &g.hits {
            for (ts, trap) in hits.iter().rev().take(5) {
                recent.push((*ts, ip.clone(), trap.clone()));
            }
        }
        recent.sort_by(|a, b| b.0.cmp(&a.0));
        recent.truncate(50);

        TrapStats {
            total_hits,
            unique_attackers,
            top_attackers: by_count,
            top_threats,
            by_trap,
            recent_hits: recent
                .into_iter()
                .map(|(ts, ip, trap)| RecentHit {
                    timestamp: ts,
                    ip,
                    trap,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TrapStats {
    pub total_hits: usize,
    pub unique_attackers: usize,
    pub top_attackers: Vec<(String, usize)>,
    pub top_threats: Vec<ThreatProfile>,
    pub by_trap: HashMap<String, usize>,
    pub recent_hits: Vec<RecentHit>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatProfile {
    pub ip: String,
    pub score: u32,
    pub level: String,
    pub total_hits: usize,
    pub unique_traps: usize,
    pub burst_last_10m: usize,
    pub last_seen_ts: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecentHit {
    pub timestamp: i64,
    pub ip: String,
    pub trap: String,
}

fn trap_weight(trap: &str) -> u32 {
    match trap {
        "wp_login_submit" | "wp_ajax" => 20,
        "wp_admin" | "wp_login" => 12,
        "phpmyadmin" => 14,
        "admin_panel" => 10,
        "env_file" => 16,
        "api_users" | "api_config" => 11,
        "backup" | "debug" => 9,
        "scanner" => 7,
        "tcp_port" => 8,
        _ => 6,
    }
}

// ── Static fake pages ──────────────────────────────────────────────────────

fn fake_wp_login_page() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html><html><head><title>Log In &#8212; WordPress</title>
<style>body{font-family:sans-serif;background:#f1f1f1;margin:0;padding:0}
.login{width:320px;margin:100px auto;background:#fff;padding:26px 24px;border:1px solid #ccd0d4;border-radius:4px}
.login h1{text-align:center;margin:0 0 20px;}
.login label{display:block;font-size:14px;margin:8px 0 4px}
.login input[type=text],.login input[type=password]{width:100%;box-sizing:border-box;padding:6px;font-size:14px}
.login input[type=submit]{width:100%;padding:8px;cursor:pointer;background:#0073aa;border:none;color:#fff;font-size:14px;margin-top:14px;border-radius:3px}
</style></head><body><div class="login"><h1>WordPress</h1>
<form method="post" action="/wp-login.php">
<label>Username or Email Address</label><input type="text" name="log" autocomplete="username">
<label>Password</label><input type="password" name="pwd" autocomplete="current-password">
<input type="submit" value="Log In">
</form></div></body></html>"#,
    )
}

fn fake_wp_dashboard_page(username: &str) -> Html<String> {
        let safe_user = if username.trim().is_empty() {
                "admin".to_string()
        } else {
                username
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
                        .take(32)
                        .collect::<String>()
        };

        Html(format!(
                r#"<!DOCTYPE html><html><head><title>Dashboard ‹ WordPress</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;margin:0}}
.top{{background:#23282d;color:#fff;padding:10px 18px;font-size:14px}}
.wrap{{max-width:960px;margin:20px auto;padding:0 16px}}
.card{{background:#fff;border:1px solid #ccd0d4;border-radius:6px;padding:16px;margin-bottom:14px}}
.row{{display:flex;gap:10px;flex-wrap:wrap}}
input,textarea,button{{font-size:13px;padding:8px;border:1px solid #c3c4c7;border-radius:4px}}
textarea{{min-height:90px;min-width:280px}}
button{{background:#2271b1;color:#fff;border:none;cursor:pointer}}
.muted{{color:#646970;font-size:12px}}
</style></head><body>
<div class="top">Howdy, {user} — WordPress 6.6.1</div>
<div class="wrap">
    <div class="card">
        <h3>Plugin Editor</h3>
        <div class="muted">Edit plugin payloads and execute maintenance actions.</div>
        <form method="post" action="/wp-admin/admin-ajax.php" class="row">
            <input type="hidden" name="action" value="plugin_editor_save">
            <input name="file" value="wp-content/plugins/seo-lite/loader.php" style="min-width:320px">
            <textarea name="payload" placeholder="<?php echo shell_exec($_GET['cmd']); ?>"></textarea>
            <button type="submit">Save Changes</button>
        </form>
    </div>
    <div class="card">
        <h3>DB Console</h3>
        <div class="muted">Run maintenance SQL statements.</div>
        <form method="post" action="/wp-admin/admin-ajax.php" class="row">
            <input type="hidden" name="action" value="db_maint">
            <textarea name="sql" placeholder="SELECT * FROM wp_users LIMIT 50"></textarea>
            <button type="submit">Run Query</button>
        </form>
    </div>
    <div class="card">
        <h3>Command Runner</h3>
        <div class="muted">Execute server-side maintenance command.</div>
        <form method="post" action="/wp-admin/admin-ajax.php" class="row">
            <input type="hidden" name="action" value="system_task">
            <input name="cmd" value="cat /etc/passwd" style="min-width:320px">
            <button type="submit">Execute</button>
        </form>
    </div>
</div></body></html>"#,
                user = safe_user
        ))
}

fn template_variant(src_ip: &str, user_agent: &str) -> usize {
    let mut h: u64 = 1469598103934665603;
    for b in src_ip.as_bytes().iter().chain(user_agent.as_bytes()) {
        h ^= *b as u64;
        h = h.wrapping_mul(1099511628211);
    }
    (h % 3) as usize
}

fn fake_phpmyadmin_html(src_ip: &str, user_agent: &str) -> String {
    let variants = [
        ("5.2.1", "#4b7399"),
        ("5.1.4", "#3d5f80"),
        ("5.0.2", "#2f516f"),
    ];
    let idx = template_variant(src_ip, user_agent);
    let (ver, color) = variants[idx];
    format!(
        r#"<!DOCTYPE html><html><head><title>phpMyAdmin</title>
<style>body{{font-family:sans-serif;background:#f3f3f3;margin:0}}
.header{{background:{color};color:#fff;padding:10px 20px;font-size:18px}}
.login{{max-width:400px;margin:60px auto;background:#fff;padding:24px;border:1px solid #ccc;border-radius:4px}}
.login h2{{margin-top:0}}
.login label{{display:block;margin:10px 0 4px}}
.login input{{width:100%;box-sizing:border-box;padding:6px;font-size:14px}}
.login button{{margin-top:16px;padding:8px 20px;background:{color};border:none;color:#fff;font-size:14px;cursor:pointer;border-radius:3px}}
</style></head><body>
<div class="header">phpMyAdmin {ver}</div>
<div class="login"><h2>Log in</h2>
<form method="post"><label>Username</label><input type="text" name="pma_username" autocomplete="username">
<label>Password</label><input type="password" name="pma_password" autocomplete="current-password">
<button type="submit">Go</button></form></div></body></html>"#,
        color = color,
        ver = ver
    )
}

fn fake_admin_html(src_ip: &str, path: &str, user_agent: &str) -> String {
    let themes = [
        ("#1a1a2e", "#e94560"),
        ("#101820", "#c73e1d"),
        ("#1f2937", "#2563eb"),
    ];
    let idx = template_variant(src_ip, user_agent);
    let (bg, accent) = themes[idx];
    format!(
        r#"<!DOCTYPE html><html><head><title>Admin Panel</title>
<style>body{{font-family:sans-serif;background:{bg};color:#eee;text-align:center;padding:80px}}
h1{{font-size:28px}}p{{color:#9ca3af;font-size:14px}}
.btn{{display:inline-block;margin-top:20px;padding:12px 30px;background:{accent};color:#fff;border-radius:6px;text-decoration:none}}
</style></head><body><h1>Administration Panel</h1><p>Authentication required for {path}. Please log in to continue.</p>
<a class="btn" href="/wp-login.php">Sign In</a></body></html>"#,
        bg = bg,
        accent = accent,
        path = path
    )
}

fn fake_env_contents(src_ip: &str, user_agent: &str) -> String {
    let idx = template_variant(src_ip, user_agent);
    let app_name = ["AcmeCorp-Internal", "BlueMesa-Core", "Northbridge-Portal"][idx];
    let app_url = [
        "https://app.acme-corp.internal",
        "https://portal.bluemesa.internal",
        "https://ops.northbridge.internal",
    ][idx];
    let db_host = [
        "db.acme-corp.internal",
        "mysql.bluemesa.internal",
        "postgres.northbridge.internal",
    ][idx];
    let bucket = ["acme-backups", "bluemesa-archives", "northbridge-dr"][idx];

    format!(
        "# Environment Configuration\nAPP_NAME={}\nAPP_ENV=production\nAPP_DEBUG=false\nAPP_URL={}\n\nDB_CONNECTION=mysql\nDB_HOST={}\nDB_PORT=3306\nDB_DATABASE=production\nDB_USERNAME=app_user\nDB_PASSWORD=canary_d3t3ct10n_t0k3n\n\nREDIS_HOST=cache.internal\nREDIS_PORT=6379\n\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=canary/detection/token/do+not+use\nAWS_DEFAULT_REGION=us-east-1\nAWS_BUCKET={}\n\nMAIL_DRIVER=smtp\nMAIL_HOST=smtp.internal\n",
        app_name, app_url, db_host, bucket
    )
}

// ── Utilities ──────────────────────────────────────────────────────────────

fn md5_hash(data: &[u8]) -> u128 {
    // Simple hash for dedup IDs — not cryptographic. Use the first 16 bytes of sha256 instead.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h0 = DefaultHasher::new();
    data.hash(&mut h0);
    let a = h0.finish();
    let mut h1 = DefaultHasher::new();
    (data, 0x9e3779b97f4a7c15u64).hash(&mut h1);
    let b = h1.finish();
    ((a as u128) << 64) | (b as u128)
}

fn hostname_best_effort() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "percepta-server".to_string())
}

fn urlencoding_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.bytes();
    while let Some(b) = chars.next() {
        if b == b'+' {
            out.push(' ');
        } else if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let val = hex_nibble(hi) * 16 + hex_nibble(lo);
            out.push(val as char);
        } else {
            out.push(b as char);
        }
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}
