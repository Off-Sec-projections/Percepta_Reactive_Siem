use crate::audit_log;
use crate::auth::{resolve_client_ip, AuthConfig, AuthedUser, Role, SessionStore};
use crate::enroll::AppState;
use crate::response::CommandStatusView;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Duration, Utc};
use percepta_server::db::Db;
use percepta_server::percepta::CommandKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
pub struct BlockEntry {
    pub value: String,
    pub until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub reason: Option<String>,
}

#[derive(Default)]
pub struct ReactiveStore {
    blocked_ips: RwLock<HashMap<String, BlockEntry>>, // key: canonical ip string
    blocked_users: RwLock<HashMap<String, BlockEntry>>, // key: lowercase username
    action_rate: RwLock<HashMap<String, ActionRateState>>, // key: actor:action
    db: RwLock<Option<Db>>,
    last_sync_unix: RwLock<i64>,
}

#[derive(Debug, Clone)]
struct ActionRateState {
    window_start: DateTime<Utc>,
    count: u32,
}

impl ReactiveStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn canonical_user(username: &str) -> String {
        username.trim().to_lowercase()
    }

    fn canonical_ip(ip: &str) -> Option<String> {
        let ip: IpAddr = ip.trim().parse().ok()?;
        Some(ip.to_string())
    }

    fn reactive_max_actions_per_minute() -> u32 {
        std::env::var("PERCEPTA_REACTIVE_MAX_ACTIONS_PER_MIN")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .map(|v| v.clamp(1, 10_000))
            .unwrap_or(120)
    }

    fn reactive_sync_interval_seconds() -> i64 {
        std::env::var("PERCEPTA_REACTIVE_SYNC_SECS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .map(|v| v.clamp(1, 120))
            .unwrap_or(5)
    }

    pub async fn attach_db(&self, db: Db) {
        {
            let mut guard = self.db.write().await;
            *guard = Some(db);
        }
        let _ = self.sync_from_db(true).await;
    }

    async fn db_client(&self) -> Option<clickhouse::Client> {
        self.db.read().await.as_ref().map(|db| db.client().clone())
    }

    async fn sync_from_db(&self, force: bool) -> anyhow::Result<()> {
        let now = Utc::now().timestamp();
        if !force {
            // Use a write lock to atomically check and update the timestamp,
            // preventing concurrent callers from both passing the interval check.
            let mut last = self.last_sync_unix.write().await;
            if now.saturating_sub(*last) < Self::reactive_sync_interval_seconds() {
                return Ok(());
            }
            *last = now; // Claim the slot; actual sync follows.
            drop(last);
        }

        let Some(client) = self.db_client().await else {
            return Ok(());
        };

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            target_type: String,
            value: String,
            until: i64,
            created_at: i64,
            created_by: String,
            reason: String,
            deleted: u8,
            updated_at: i64,
        }

        let rows = client
            .query(
                "SELECT target_type, value, until, created_at, created_by, reason, deleted, updated_at
                 FROM reactive_blocks",
            )
            .fetch_all::<Row>()
            .await?;

        let mut latest: HashMap<(String, String), Row> = HashMap::new();
        for row in rows {
            let key = (row.target_type.clone(), row.value.clone());
            match latest.get(&key) {
                Some(prev) if prev.updated_at >= row.updated_at => {}
                _ => {
                    latest.insert(key, row);
                }
            }
        }

        let mut next_ips: HashMap<String, BlockEntry> = HashMap::new();
        let mut next_users: HashMap<String, BlockEntry> = HashMap::new();
        for (_, row) in latest {
            if row.deleted != 0 || row.until <= now {
                continue;
            }
            let created_at =
                chrono::DateTime::<Utc>::from_timestamp(row.created_at, 0).unwrap_or_else(Utc::now);
            let until =
                chrono::DateTime::<Utc>::from_timestamp(row.until, 0).unwrap_or_else(Utc::now);
            let entry = BlockEntry {
                value: row.value.clone(),
                until,
                created_at,
                created_by: row.created_by,
                reason: if row.reason.trim().is_empty() {
                    None
                } else {
                    Some(row.reason)
                },
            };
            if row.target_type == "ip" {
                next_ips.insert(entry.value.clone(), entry);
            } else if row.target_type == "user" {
                next_users.insert(entry.value.clone(), entry);
            }
        }

        {
            let mut ips = self.blocked_ips.write().await;
            *ips = next_ips;
        }
        {
            let mut users = self.blocked_users.write().await;
            *users = next_users;
        }
        {
            let mut last = self.last_sync_unix.write().await;
            *last = now;
        }

        Ok(())
    }

    async fn persist_block_entry(&self, target_type: &str, entry: &BlockEntry, deleted: bool) {
        let Some(client) = self.db_client().await else {
            return;
        };

        #[derive(clickhouse::Row, serde::Serialize)]
        struct Row<'a> {
            target_type: &'a str,
            value: &'a str,
            until: i64,
            created_at: i64,
            created_by: &'a str,
            reason: &'a str,
            deleted: u8,
            updated_at: i64,
        }

        let reason = entry.reason.as_deref().unwrap_or("");
        let row = Row {
            target_type,
            value: &entry.value,
            until: entry.until.timestamp(),
            created_at: entry.created_at.timestamp(),
            created_by: &entry.created_by,
            reason,
            deleted: u8::from(deleted),
            updated_at: Utc::now().timestamp(),
        };

        match client.insert("reactive_blocks") {
            Ok(mut insert) => {
                if let Err(e) = insert.write(&row).await {
                    tracing::warn!("reactive_blocks write failed: {:#}", e);
                    return;
                }
                if let Err(e) = insert.end().await {
                    tracing::warn!("reactive_blocks flush failed: {:#}", e);
                    return;
                }
                let mut last = self.last_sync_unix.write().await;
                *last = Utc::now().timestamp();
            }
            Err(e) => {
                tracing::warn!("reactive_blocks insert init failed: {:#}", e);
            }
        }
    }

    async fn allow_action(&self, actor: &str, action: &str) -> bool {
        let actor = actor.trim().to_lowercase();
        let action = action.trim().to_lowercase();
        if actor.is_empty() || action.is_empty() {
            return true;
        }

        let key = format!("{actor}:{action}");
        let now = Utc::now();
        let window = Duration::seconds(60);
        let max = Self::reactive_max_actions_per_minute();

        let mut guard = self.action_rate.write().await;
        let entry = guard.entry(key).or_insert(ActionRateState {
            window_start: now,
            count: 0,
        });

        if now - entry.window_start >= window {
            entry.window_start = now;
            entry.count = 0;
        }

        if entry.count >= max {
            return false;
        }

        entry.count = entry.count.saturating_add(1);
        true
    }

    async fn prune_expired(&self) {
        if let Err(e) = self.sync_from_db(false).await {
            tracing::warn!("reactive DB sync failed during prune: {:#}", e);
        }
        let now = Utc::now();
        {
            let mut ips = self.blocked_ips.write().await;
            ips.retain(|_, v| v.until > now);
        }
        {
            let mut users = self.blocked_users.write().await;
            users.retain(|_, v| v.until > now);
        }
        // Prune stale action-rate windows (older than 2 minutes)
        {
            let mut rates = self.action_rate.write().await;
            rates.retain(|_, v| now - v.window_start < chrono::Duration::seconds(120));
        }
    }

    pub async fn is_ip_blocked(&self, ip: &str) -> bool {
        self.prune_expired().await;
        let Some(key) = Self::canonical_ip(ip) else {
            return false;
        };
        let ips = self.blocked_ips.read().await;
        ips.get(&key).map(|e| e.until > Utc::now()).unwrap_or(false)
    }

    pub async fn is_user_blocked(&self, username: &str) -> bool {
        self.prune_expired().await;
        let key = Self::canonical_user(username);
        let users = self.blocked_users.read().await;
        users
            .get(&key)
            .map(|e| e.until > Utc::now())
            .unwrap_or(false)
    }

    pub async fn blocked_user_until(&self, username: &str) -> Option<DateTime<Utc>> {
        self.prune_expired().await;
        let key = Self::canonical_user(username);
        let users = self.blocked_users.read().await;
        users.get(&key).map(|e| e.until)
    }

    pub async fn blocked_ip_until(&self, ip: &str) -> Option<DateTime<Utc>> {
        self.prune_expired().await;
        let key = Self::canonical_ip(ip)?;
        let ips = self.blocked_ips.read().await;
        ips.get(&key).map(|e| e.until)
    }

    pub async fn block_ip(
        &self,
        ip: &str,
        ttl_seconds: i64,
        created_by: &str,
        reason: Option<String>,
    ) -> Result<BlockEntry, StatusCode> {
        let Some(key) = Self::canonical_ip(ip) else {
            return Err(StatusCode::BAD_REQUEST);
        };
        let ttl = ttl_seconds.clamp(30, 60 * 60 * 24 * 365);
        let now = Utc::now();
        let desired_until = now + Duration::seconds(ttl);

        // Practical containment rule: do not shorten an existing active block.
        // If the IP is already blocked longer than requested, keep the longer block.
        {
            let ips = self.blocked_ips.read().await;
            if let Some(existing) = ips.get(&key) {
                if existing.until > now && existing.until >= desired_until {
                    return Ok(existing.clone());
                }
            }
        }
        let entry = BlockEntry {
            value: key.clone(),
            until: desired_until,
            created_at: now,
            created_by: created_by.to_string(),
            reason,
        };
        self.blocked_ips.write().await.insert(key, entry.clone());
        self.persist_block_entry("ip", &entry, false).await;
        Ok(entry)
    }

    pub async fn unblock_ip(&self, ip: &str) -> Result<(), StatusCode> {
        let Some(key) = Self::canonical_ip(ip) else {
            return Err(StatusCode::BAD_REQUEST);
        };
        let removed = self.blocked_ips.write().await.remove(&key);
        if let Some(existing) = removed {
            self.persist_block_entry("ip", &existing, true).await;
        }
        Ok(())
    }

    pub async fn block_user(
        &self,
        username: &str,
        ttl_seconds: i64,
        created_by: &str,
        reason: Option<String>,
    ) -> Result<BlockEntry, StatusCode> {
        let key = Self::canonical_user(username);
        if key.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let ttl = ttl_seconds.clamp(30, 60 * 60 * 24 * 365);
        let now = Utc::now();
        let entry = BlockEntry {
            value: key.clone(),
            until: now + Duration::seconds(ttl),
            created_at: now,
            created_by: created_by.to_string(),
            reason,
        };
        self.blocked_users.write().await.insert(key, entry.clone());
        self.persist_block_entry("user", &entry, false).await;
        Ok(entry)
    }

    pub async fn unblock_user(&self, username: &str) -> Result<(), StatusCode> {
        let key = Self::canonical_user(username);
        if key.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let removed = self.blocked_users.write().await.remove(&key);
        if let Some(existing) = removed {
            self.persist_block_entry("user", &existing, true).await;
        }
        Ok(())
    }

    pub async fn list_blocks(&self) -> BlocksResponse {
        self.prune_expired().await;
        let ips: Vec<BlockEntry> = self.blocked_ips.read().await.values().cloned().collect();
        let users: Vec<BlockEntry> = self.blocked_users.read().await.values().cloned().collect();
        BlocksResponse {
            blocked_ips: ips,
            blocked_users: users,
        }
    }
}

pub type ReactiveStoreHandle = Arc<ReactiveStore>;

pub fn init_reactive_store() -> ReactiveStoreHandle {
    Arc::new(ReactiveStore::new())
}

fn want_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

fn is_loopback_or_local(ip: &IpAddr) -> bool {
    match ip {
        // RFC 1918 private ranges, link-local, and loopback are all "local" for
        // safety-valve purposes — blocking any of them could sever admin access
        // or take down internal infrastructure (gateways, DCs, internal servers).
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            // Unique Local Addresses (ULA) fc00::/7 — covers fd00::/8 where
            // most private IPv6 allocations live.
            let segs = v6.segments();
            (segs[0] & 0xfe00) == 0xfc00
        }
    }
}

/// Middleware: blocks requests from blocked client IPs (HTTP only).
///
/// Resolves the real client IP from proxy headers (X-Forwarded-For, X-Real-IP),
/// falling back to the socket peer address.
pub async fn reject_blocked_ip(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Resolve the real client IP from proxy headers first, then socket addr.
    let socket_addr = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0);

    let client_ip_str = match socket_addr {
        Some(addr) => resolve_client_ip(req.headers(), &addr),
        None => return Ok(next.run(req).await),
    };

    // Safety valve: always allow loopback so local admin can't brick themselves.
    if let Ok(ip) = client_ip_str.parse::<IpAddr>() {
        if !is_loopback_or_local(&ip)
            && state.reactive.is_ip_blocked(&client_ip_str).await
        {
            let until = state.reactive.blocked_ip_until(&client_ip_str).await;
            let retry_after_seconds = until
                .and_then(|u| (u - Utc::now()).to_std().ok())
                .map(|d| d.as_secs());

            let mut resp = if want_json(req.headers()) {
                let payload = serde_json::json!({
                    "error": "blocked_ip",
                    "until": until.map(|u| u.to_rfc3339()),
                    "retry_after_seconds": retry_after_seconds,
                });
                (StatusCode::FORBIDDEN, Json(payload)).into_response()
            } else {
                let msg = match until {
                    Some(u) => format!("Blocked until {}", u.to_rfc3339()),
                    None => "Blocked".to_string(),
                };
                (StatusCode::FORBIDDEN, msg).into_response()
            };

            if let Some(secs) = retry_after_seconds {
                if let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string()) {
                    resp.headers_mut().insert(header::RETRY_AFTER, v);
                }
            }
            return Ok(resp);
        }
    }

    Ok(next.run(req).await)
}

fn require_authority(user: &AuthedUser) -> Result<(), StatusCode> {
    if user.role != Role::Authority {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

fn require_analyst_or_authority(user: &AuthedUser) -> Result<(), StatusCode> {
    if user.role != Role::Authority && user.role != Role::Analyst {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

fn require_reason(reason: &Option<String>) -> Result<String, StatusCode> {
    let r = reason.as_deref().unwrap_or("").trim();
    if r.len() < 5 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(r.to_string())
}

fn cap_ttl_for_role(user: &AuthedUser, ttl_seconds: i64, max_for_analyst: i64) -> i64 {
    if user.role == Role::Analyst {
        ttl_seconds.clamp(30, max_for_analyst)
    } else {
        ttl_seconds
    }
}

#[derive(Debug, Deserialize)]
pub struct BlockRequest {
    pub value: String,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub context_alert_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UnblockRequest {
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub value: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub context_alert_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BlocksResponse {
    pub blocked_ips: Vec<BlockEntry>,
    pub blocked_users: Vec<BlockEntry>,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

#[derive(Debug, Serialize)]
pub struct LogoutResponse {
    pub ok: bool,
    pub revoked_sessions: usize,
}

#[derive(Debug, Deserialize)]
pub struct WindowsScriptQuery {
    pub kind: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WindowsScriptResponse {
    pub filename: String,
    pub content: String,
}
pub async fn api_list_blocks(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> Result<Json<BlocksResponse>, StatusCode> {
    require_analyst_or_authority(&user)?;
    Ok(Json(state.reactive.list_blocks().await))
}

pub async fn api_block_ip(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<BlockRequest>,
) -> Result<Json<BlockEntry>, StatusCode> {
    require_analyst_or_authority(&user)?;

    // Self-block protection: reject if the IP being blocked matches the requester's IP.
    let client_ip = resolve_client_ip(&headers, &addr);
    if req.value.trim() == client_ip {
        tracing::warn!(
            user = %user.username,
            ip = %client_ip,
            "Rejected self-block: user tried to block their own IP"
        );
        return Err(StatusCode::CONFLICT);
    }

    if !state
        .reactive
        .allow_action(&user.username, "block_ip")
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let reason = require_reason(&req.reason)?;
    let tuning = state.runtime_tuning.snapshot().await;
    let ttl_raw = req.ttl_seconds.unwrap_or(tuning.reactive_default_ttl_secs);
    let ttl = cap_ttl_for_role(&user, ttl_raw, tuning.reactive_analyst_max_ttl_secs);

    let result = state
        .reactive
        .block_ip(&req.value, ttl, &user.username, Some(reason.clone()))
        .await;

    match result {
        Ok(entry) => {
            audit_log::log_reactive_action(
                &state,
                &user,
                "block_ip",
                "ip",
                &entry.value,
                Some(ttl),
                Some(reason),
                req.context_alert_id.clone(),
                true,
            )
            .await;
            Ok(Json(entry))
        }
        Err(code) => {
            audit_log::log_reactive_action(
                &state,
                &user,
                "block_ip",
                "ip",
                req.value.trim(),
                Some(ttl),
                Some(reason),
                req.context_alert_id.clone(),
                false,
            )
            .await;
            Err(code)
        }
    }
}

pub async fn api_unblock_ip(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(req): Json<UnblockRequest>,
) -> Result<Json<OkResponse>, StatusCode> {
    require_authority(&user)?;
    state.reactive.unblock_ip(&req.value).await?;
    Ok(Json(OkResponse { ok: true }))
}

pub async fn api_block_user(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<BlockEntry>, StatusCode> {
    require_analyst_or_authority(&user)?;
    if !state
        .reactive
        .allow_action(&user.username, "block_user")
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let reason = require_reason(&req.reason)?;
    let tuning = state.runtime_tuning.snapshot().await;
    let ttl_raw = req.ttl_seconds.unwrap_or(tuning.reactive_default_ttl_secs);
    let ttl = cap_ttl_for_role(&user, ttl_raw, tuning.reactive_analyst_max_ttl_secs);

    let result = state
        .reactive
        .block_user(&req.value, ttl, &user.username, Some(reason.clone()))
        .await;

    let entry = match result {
        Ok(e) => e,
        Err(code) => {
            audit_log::log_reactive_action(
                &state,
                &user,
                "block_user",
                "username",
                req.value.trim(),
                Some(ttl),
                Some(reason),
                req.context_alert_id.clone(),
                false,
            )
            .await;
            return Err(code);
        }
    };

    // Enforce immediately: revoke existing sessions for this user.
    let revoked = revoke_sessions_for_user(&state.sessions, &req.value).await;
    let _ = revoked;

    audit_log::log_reactive_action(
        &state,
        &user,
        "block_user",
        "username",
        &entry.value,
        Some(ttl),
        Some(reason),
        req.context_alert_id.clone(),
        true,
    )
    .await;

    Ok(Json(entry))
}

pub async fn api_unblock_user(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(req): Json<UnblockRequest>,
) -> Result<Json<OkResponse>, StatusCode> {
    require_authority(&user)?;
    state.reactive.unblock_user(&req.value).await?;
    Ok(Json(OkResponse { ok: true }))
}

pub async fn api_logout_user(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(req): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, StatusCode> {
    require_analyst_or_authority(&user)?;
    if !state
        .reactive
        .allow_action(&user.username, "logout_user")
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let reason = require_reason(&req.reason)?;
    let revoked = revoke_sessions_for_user(&state.sessions, &req.value).await;

    audit_log::log_reactive_action(
        &state,
        &user,
        "logout_user",
        "username",
        req.value.trim(),
        None,
        Some(reason),
        req.context_alert_id.clone(),
        true,
    )
    .await;
    Ok(Json(LogoutResponse {
        ok: true,
        revoked_sessions: revoked,
    }))
}

fn ps_quote_single(s: &str) -> String {
    // PowerShell single-quoted string escape: '' represents a single quote.
    format!("'{}'", s.replace('\'', "''"))
}

fn clamp_ttl(ttl_seconds: Option<i64>, default_secs: i64) -> i64 {
    ttl_seconds
        .unwrap_or(default_secs)
        .clamp(30, 60 * 60 * 24 * 30)
}

fn windows_script_block_ip(
    ip: &str,
    ttl: i64,
    note: Option<&str>,
) -> Option<WindowsScriptResponse> {
    let ip = ReactiveStore::canonical_ip(ip)?;
    let minutes = (ttl as f64 / 60.0).ceil() as i64;
    let display = format!("Percepta Block {}", ip);
    let note = note.unwrap_or("Percepta SIEM reactive containment");
    let content = format!(
        r#"# Percepta SIEM — Reactive containment (Windows)
# Blocks a remote IP at the Windows Firewall for a limited time, then removes the rule.
# Requires: Run PowerShell as Administrator.

$ErrorActionPreference = 'Stop'

$Ip = {ip}
$RuleName = {rname}
$Minutes = {mins}
$Note = {note}

Write-Host "[percepta] Blocking IP $Ip for $Minutes minute(s)" -ForegroundColor Yellow

# Create inbound + outbound block rules (remote address match)
New-NetFirewallRule -DisplayName $RuleName -Direction Inbound  -Action Block -RemoteAddress $Ip -Enabled True | Out-Null
New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Action Block -RemoteAddress $Ip -Enabled True | Out-Null

Write-Host "[percepta] Rule created: $RuleName" -ForegroundColor Green
Write-Host "[percepta] Note: $Note" -ForegroundColor DarkGray

Start-Sleep -Seconds ($Minutes * 60)

Write-Host "[percepta] Unblocking IP $Ip (removing firewall rules)" -ForegroundColor Yellow
Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host "[percepta] Done" -ForegroundColor Green
"#,
        ip = ps_quote_single(&ip),
        rname = ps_quote_single(&display),
        mins = minutes,
        note = ps_quote_single(note)
    );
    Some(WindowsScriptResponse {
        filename: format!(
            "percepta_block_ip_{}_{}m.ps1",
            ip.replace([':', '.'], "-"),
            minutes
        ),
        content,
    })
}

fn windows_script_block_user(
    username: &str,
    ttl: i64,
    note: Option<&str>,
) -> Option<WindowsScriptResponse> {
    let user = username.trim();
    if user.is_empty() {
        return None;
    }
    let minutes = (ttl as f64 / 60.0).ceil() as i64;
    let note = note.unwrap_or("Percepta SIEM reactive containment");
    let content = format!(
        r#"# Percepta SIEM — Reactive containment (Windows)
# Temporarily disables a LOCAL Windows user account, then re-enables it.
# WARNING: For domain accounts, use AD tooling; this script targets local accounts.
# Requires: Run PowerShell as Administrator.

$ErrorActionPreference = 'Stop'

$User = {user}
$Minutes = {mins}
$Note = {note}

Write-Host "[percepta] Disabling local user $User for $Minutes minute(s)" -ForegroundColor Yellow
Write-Host "[percepta] Note: $Note" -ForegroundColor DarkGray

try {{
    Disable-LocalUser -Name $User
}} catch {{
    # Fallback for older systems
    & net user $User /active:no | Out-Null
}}

Start-Sleep -Seconds ($Minutes * 60)

Write-Host "[percepta] Re-enabling local user $User" -ForegroundColor Yellow
try {{
    Enable-LocalUser -Name $User
}} catch {{
    & net user $User /active:yes | Out-Null
}}

Write-Host "[percepta] Done" -ForegroundColor Green
"#,
        user = ps_quote_single(user),
        mins = minutes,
        note = ps_quote_single(note)
    );
    Some(WindowsScriptResponse {
        filename: format!(
            "percepta_block_user_{}_{}m.ps1",
            user.replace(['\\', '/'], "_"),
            minutes
        ),
        content,
    })
}

fn windows_script_logout_user(username: &str, note: Option<&str>) -> Option<WindowsScriptResponse> {
    let user = username.trim();
    if user.is_empty() {
        return None;
    }
    let note = note.unwrap_or("Percepta SIEM reactive containment");
    let content = format!(
        r#"# Percepta SIEM — Reactive response (Windows)
# Logs off interactive sessions for a given username (best-effort).
# Requires: Run PowerShell as Administrator.

$ErrorActionPreference = 'Continue'

$User = {user}
$Note = {note}

Write-Host "[percepta] Logging off sessions for $User" -ForegroundColor Yellow
Write-Host "[percepta] Note: $Note" -ForegroundColor DarkGray

$sessions = (query session) 2>$null
if (-not $sessions) {{
    Write-Host "[percepta] No sessions found (query session failed)" -ForegroundColor DarkGray
    exit 0
}}

foreach ($line in $sessions) {{
    if ($line -match $User) {{
        # Parse session id (works for typical 'query session' output)
        $parts = $line -split '\\s+'
        $id = $parts | Where-Object {{ $_ -match '^\\d+$' }} | Select-Object -First 1
        if ($id) {{
            Write-Host "[percepta] logoff $id" -ForegroundColor Yellow
            & logoff $id 2>$null
        }}
    }}
}}

Write-Host "[percepta] Done" -ForegroundColor Green
"#,
        user = ps_quote_single(user),
        note = ps_quote_single(note)
    );
    Some(WindowsScriptResponse {
        filename: format!(
            "percepta_logout_user_{}.ps1",
            user.replace(['\\', '/'], "_")
        ),
        content,
    })
}

fn windows_script_triage_bundle(note: Option<&str>) -> WindowsScriptResponse {
    let note = note.unwrap_or("Percepta SIEM triage collection");
    let safe_note = note.replace('\'', "''");
    let content = format!(
        r#"# Percepta SIEM — Triage collection (Windows)
# Collects basic incident triage artifacts into a folder and zips it.
# Requires: PowerShell. Some commands require Administrator.

$ErrorActionPreference = 'Continue'

$Stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$OutDir = Join-Path $env:TEMP ("percepta_triage_" + $Stamp)
$ZipPath = $OutDir + '.zip'
$Note = @'
{note}
'@

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

"Percepta Triage Note: $Note" | Out-File -FilePath (Join-Path $OutDir 'note.txt') -Encoding utf8

function Save-Cmd($name, $cmd) {{
    $path = Join-Path $OutDir $name
    "== $cmd ==" | Out-File -FilePath $path -Encoding utf8
    try {{
        cmd.exe /c $cmd 2>&1 | Out-File -FilePath $path -Append -Encoding utf8
    }} catch {{
        $_ | Out-File -FilePath $path -Append -Encoding utf8
    }}
}}

function Save-PS($name, $scriptBlock) {{
    $path = Join-Path $OutDir $name
    try {{
        & $scriptBlock 2>&1 | Out-File -FilePath $path -Encoding utf8
    }} catch {{
        $_ | Out-File -FilePath $path -Encoding utf8
    }}
}}

Save-PS 'computerinfo.txt' {{ Get-ComputerInfo | Format-List * }}
Save-PS 'processes.txt' {{ Get-Process | Sort-Object CPU -Descending | Select-Object -First 200 | Format-Table -AutoSize }}
Save-PS 'services.txt' {{ Get-Service | Sort-Object Status, Name | Format-Table -AutoSize }}
Save-PS 'net_tcp.txt' {{ Get-NetTCPConnection | Sort-Object State, LocalPort | Format-Table -AutoSize }}
Save-PS 'net_adapters.txt' {{ Get-NetAdapter | Format-Table -AutoSize }}
Save-Cmd 'ipconfig_all.txt' 'ipconfig /all'
Save-Cmd 'route_print.txt' 'route print'
Save-Cmd 'arp_a.txt' 'arp -a'
Save-Cmd 'netstat_ano.txt' 'netstat -ano'
Save-Cmd 'whoami_all.txt' 'whoami /all'

# Export recent Security log entries (best-effort; may require admin)
Save-PS 'security_log_recent.txt' {{
    wevtutil qe Security /c:200 /rd:true /f:text
}}

# Export firewall rules summary
Save-PS 'firewall_rules.txt' {{ Get-NetFirewallRule | Select-Object DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize }}

if (Test-Path $ZipPath) {{ Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue }}
Compress-Archive -Path $OutDir -DestinationPath $ZipPath -Force

Write-Host "[percepta] Triage bundle created:" -ForegroundColor Green
Write-Host $ZipPath -ForegroundColor Green
"#,
        note = safe_note
    );
    WindowsScriptResponse {
        filename: "percepta_triage_bundle.ps1".to_string(),
        content,
    }
}

pub async fn api_windows_script(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    axum::extract::Query(q): axum::extract::Query<WindowsScriptQuery>,
) -> Result<Json<WindowsScriptResponse>, StatusCode> {
    require_authority(&user)?;
    let tuning = state.runtime_tuning.snapshot().await;
    let ttl = clamp_ttl(q.ttl_seconds, tuning.reactive_windows_script_ttl_secs);
    let note = q.note.as_deref();

    let kind = q.kind.trim().to_lowercase();
    match kind.as_str() {
        "block_ip" => {
            let Some(v) = q.value.as_deref() else {
                return Err(StatusCode::BAD_REQUEST);
            };
            let Some(resp) = windows_script_block_ip(v, ttl, note) else {
                return Err(StatusCode::BAD_REQUEST);
            };
            Ok(Json(resp))
        }
        "block_user" => {
            let Some(v) = q.value.as_deref() else {
                return Err(StatusCode::BAD_REQUEST);
            };
            let Some(resp) = windows_script_block_user(v, ttl, note) else {
                return Err(StatusCode::BAD_REQUEST);
            };
            Ok(Json(resp))
        }
        "logout_user" => {
            let Some(v) = q.value.as_deref() else {
                return Err(StatusCode::BAD_REQUEST);
            };
            let Some(resp) = windows_script_logout_user(v, note) else {
                return Err(StatusCode::BAD_REQUEST);
            };
            Ok(Json(resp))
        }
        "triage_bundle" => Ok(Json(windows_script_triage_bundle(note))),
        _ => Err(StatusCode::BAD_REQUEST),
    }
}

#[derive(Debug, Deserialize)]
pub struct DispatchCommandRequest {
    pub agent_id: String,
    pub kind: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u32>,
    #[serde(default)]
    pub args: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub context_alert_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DispatchCommandResponse {
    pub command_id: String,
}

fn is_safe_custom_kind(kind: &str) -> bool {
    let t = kind.trim();
    if t.is_empty() {
        return false;
    }
    // Constrain to a simple identifier: a-z0-9_ (avoids injection/log weirdness)
    t.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn parse_command_kind(kind: &str) -> Option<(CommandKind, Option<String>)> {
    let k = kind.trim().to_lowercase();
    let known = match k.as_str() {
        "block_ip" => Some(CommandKind::BlockIp),
        "unblock_ip" => Some(CommandKind::UnblockIp),
        "disable_user" => Some(CommandKind::DisableUser),
        "enable_user" => Some(CommandKind::EnableUser),
        "logoff_user" => Some(CommandKind::LogoffUser),
        "triage_bundle" => Some(CommandKind::TriageBundle),
        "isolate_host" => Some(CommandKind::IsolateHost),
        "restore_network" => Some(CommandKind::RestoreNetwork),
        "logoff_active_user" => Some(CommandKind::LogoffActiveUser),
        "lock_workstation" => Some(CommandKind::LockWorkstation),
        _ => None,
    };

    if let Some(k) = known {
        return Some((k, None));
    }
    if !is_safe_custom_kind(&k) {
        return None;
    }
    Some((CommandKind::Custom, Some(k)))
}

fn is_uuid_like(s: &str) -> bool {
    let t = s.trim();
    if t.len() != 36 {
        return false;
    }
    // 8-4-4-4-12 with hex digits
    let mut parts = t.split('-');
    let (a, b, c, d, e) = match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some(a), Some(b), Some(c), Some(d), Some(e), None) => (a, b, c, d, e),
        _ => return false,
    };
    let ok = |p: &str, n: usize| p.len() == n && p.chars().all(|ch| ch.is_ascii_hexdigit());
    ok(a, 8) && ok(b, 4) && ok(c, 4) && ok(d, 4) && ok(e, 12)
}

fn is_sid_like(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return false;
    }
    // Basic SID shape: S-1-5-21-...
    let u = t.to_ascii_uppercase();
    if !u.starts_with("S-") {
        return false;
    }
    u.split('-')
        .skip(1)
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn normalize_endpoint_username(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    let short = t.rsplit(['\\', '/']).next().unwrap_or("").trim();
    if short.is_empty() {
        return None;
    }
    if short.eq_ignore_ascii_case("unknown") {
        return None;
    }
    if is_uuid_like(short) || is_sid_like(short) {
        return None;
    }
    Some(short.to_string())
}

pub async fn api_dispatch_command(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(req): Json<DispatchCommandRequest>,
) -> Result<Json<DispatchCommandResponse>, StatusCode> {
    require_authority(&user)?;
    if req.agent_id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let Some((kind, custom_kind)) = parse_command_kind(&req.kind) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let tuning = state.runtime_tuning.snapshot().await;
    let ttl = req
        .ttl_seconds
        .unwrap_or(tuning.reactive_dispatch_default_ttl_secs);

    let mut args = req.args.unwrap_or_default();

    let (ip, username) = match kind {
        CommandKind::BlockIp | CommandKind::UnblockIp => (req.value.clone(), None),
        CommandKind::DisableUser | CommandKind::EnableUser | CommandKind::LogoffUser => {
            let Some(v) = req.value.as_deref() else {
                return Err(StatusCode::BAD_REQUEST);
            };
            let Some(u) = normalize_endpoint_username(v) else {
                return Err(StatusCode::BAD_REQUEST);
            };
            (None, Some(u))
        }
        CommandKind::TriageBundle
        | CommandKind::IsolateHost
        | CommandKind::RestoreNetwork
        | CommandKind::LogoffActiveUser
        | CommandKind::LockWorkstation => (None, None),
        CommandKind::Custom => {
            if let Some(v) = req
                .value
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                args.entry("value".to_string())
                    .or_insert_with(|| v.to_string());
            }
            (None, None)
        }
        _ => (None, None),
    };

    let command_id = state
        .response_hub
        .dispatch(
            req.agent_id.trim(),
            kind,
            ip,
            username,
            ttl,
            args,
            custom_kind,
        )
        .await
        .map_err(|st| {
            use tonic::Code;
            match st.code() {
                Code::NotFound => StatusCode::CONFLICT,
                Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::BAD_GATEWAY,
            }
        })?;

    audit_log::log_reactive_action(
        &state,
        &user,
        "dispatch_command",
        "agent_id",
        req.agent_id.trim(),
        Some(ttl as i64),
        req.reason.clone(),
        req.context_alert_id.clone(),
        true,
    )
    .await;

    Ok(Json(DispatchCommandResponse { command_id }))
}

pub async fn api_get_command_status(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<CommandStatusView>, StatusCode> {
    require_authority(&user)?;
    let Some(status) = state.response_hub.get_status(&id).await else {
        return Err(StatusCode::NOT_FOUND);
    };
    Ok(Json(status))
}

pub async fn api_get_command_artifact(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<axum::response::Response, StatusCode> {
    const MAX_ARTIFACT_BYTES: usize = 100 * 1024 * 1024;

    require_authority(&user)?;
    let Some((name, bytes)) = state.response_hub.get_artifact(&id).await else {
        return Err(StatusCode::NOT_FOUND);
    };

    if bytes.len() > MAX_ARTIFACT_BYTES {
        tracing::warn!(
            "Artifact '{}' too large ({} bytes > {} bytes)",
            name,
            bytes.len(),
            MAX_ARTIFACT_BYTES
        );
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/zip"),
    );
    headers.insert(
        axum::http::header::CONTENT_DISPOSITION,
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{}\"", name))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    Ok((headers, bytes).into_response())
}
pub async fn revoke_sessions_for_user(sessions: &SessionStore, username: &str) -> usize {
    let target = username.trim().to_string();
    if target.is_empty() {
        return 0;
    }

    // Single write lock to avoid TOCTOU race between read and remove.
    let mut map = sessions.write().await;
    let tokens_to_remove: Vec<String> = map
        .iter()
        .filter(|(_, sess)| sess.user.username == target)
        .map(|(token, _)| token.clone())
        .collect();

    let mut n = 0;
    for t in tokens_to_remove {
        if map.remove(&t).is_some() {
            n += 1;
        }
    }
    n
}

/// Optional automatic reaction when a high/critical alert is generated.
///
/// Controlled by env var `PERCEPTA_REACTIVE_AUTOBLOCK=1`.
/// TTL via `PERCEPTA_REACTIVE_AUTOBLOCK_TTL_SECS` (default 900).
pub async fn maybe_autoblock_from_alert(
    reactive: &ReactiveStore,
    response_hub: &crate::response::ResponseHubHandle,
    sessions: &SessionStore,
    auth_config: &AuthConfig,
    alert: &percepta_server::alerts::Alert,
) {
    let enabled = std::env::var("PERCEPTA_REACTIVE_AUTOBLOCK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enabled {
        return;
    }

    // Only aggressive on high/critical.
    let sev = format!("{:?}", alert.severity).to_lowercase();
    if sev != "high" && sev != "critical" {
        return;
    }

    let ttl = std::env::var("PERCEPTA_REACTIVE_AUTOBLOCK_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(900)
        .clamp(30, 60 * 60 * 24);

    // Best-effort keys that commonly contain attacker IP/user.
    let ip_keys = ["src_ip", "source_ip", "ip", "remote_ip", "attacker_ip"];
    let user_keys = ["user", "username", "account", "account_name", "target_user"];

    let mut src_ip: Option<String> = None;
    for k in ip_keys {
        if let Some(v) = alert.metadata.get(k) {
            if ReactiveStore::canonical_ip(v).is_some() {
                src_ip = Some(v.clone());
                break;
            }
        }
    }

    let mut username: Option<String> = None;
    for k in user_keys {
        if let Some(v) = alert.metadata.get(k) {
            let s = v.trim();
            if !s.is_empty() {
                username = Some(s.to_string());
                break;
            }
        }
    }

    // Apply best-effort blocks.
    let mut blocked_ip_value: Option<String> = None;
    let mut blocked_user_value: Option<String> = None;

    if let Some(ip) = src_ip {
        let _ = reactive
            .block_ip(
                &ip,
                ttl,
                "autoblock",
                Some(format!("auto from alert {}", alert.rule_id)),
            )
            .await;
        blocked_ip_value = Some(ip);
    }

    if let Some(user) = username {
        let is_protected_operator = user.eq_ignore_ascii_case(&auth_config.analyst_user)
            || user.eq_ignore_ascii_case(&auth_config.admin_user);
        if !is_protected_operator {
            if let Ok(_entry) = reactive
                .block_user(
                    &user,
                    ttl,
                    "autoblock",
                    Some(format!("auto from alert {}", alert.rule_id)),
                )
                .await
            {
                blocked_user_value = Some(user.clone());
                let _ = revoke_sessions_for_user(sessions, &user).await;
            }
        }
    }

    // Optional endpoint auto-containment dispatch (enabled by default when autoblock is enabled).
    // This allows true host-level response in addition to server-side logical blocks.
    let dispatch_enabled = std::env::var("PERCEPTA_REACTIVE_AUTOCONTAIN_AGENT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    if !dispatch_enabled {
        return;
    }

    let agent_id = alert.agent_id.trim();
    if agent_id.is_empty() {
        return;
    }

    let command_ttl = std::env::var("PERCEPTA_REACTIVE_AUTOCONTAIN_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or_else(|| u32::try_from(ttl.clamp(30, 60 * 60 * 24)).unwrap_or(900))
        .clamp(30, 60 * 60 * 24);

    let critical_auto_isolate = std::env::var("PERCEPTA_REACTIVE_AUTOCONTAIN_ISOLATE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let triage_bundle_enabled = std::env::var("PERCEPTA_REACTIVE_AUTOCONTAIN_TRIAGE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    if let Some(ip) = blocked_ip_value {
        let _ = response_hub
            .dispatch(
                agent_id,
                CommandKind::BlockIp,
                Some(ip),
                None,
                command_ttl,
                HashMap::new(),
                None,
            )
            .await;
    }

    if let Some(user) = blocked_user_value.and_then(|u| normalize_endpoint_username(&u)) {
        let _ = response_hub
            .dispatch(
                agent_id,
                CommandKind::DisableUser,
                None,
                Some(user),
                command_ttl,
                HashMap::new(),
                None,
            )
            .await;
    }

    if critical_auto_isolate && sev == "critical" {
        let _ = response_hub
            .dispatch(
                agent_id,
                CommandKind::IsolateHost,
                None,
                None,
                command_ttl,
                HashMap::new(),
                None,
            )
            .await;
    }

    if triage_bundle_enabled {
        let _ = response_hub
            .dispatch(
                agent_id,
                CommandKind::TriageBundle,
                None,
                None,
                command_ttl,
                HashMap::new(),
                None,
            )
            .await;
    }
}

// ── Enhanced Reactive Response Endpoints ─────────────────────────────────

/// POST /api/reactive/isolate_host — Queue network isolation command for agent
pub async fn api_isolate_host(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "authority role required"})),
        )
            .into_response();
    }
    let agent_id = body
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if agent_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "agent_id required"})),
        )
            .into_response();
    }

    let ttl = body
        .get("ttl_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(3600) as u32;
    match state
        .response_hub
        .dispatch(
            agent_id,
            CommandKind::IsolateHost,
            None,
            None,
            ttl,
            HashMap::new(),
            None,
        )
        .await
    {
        Ok(command_id) => {
            audit_log::log_reactive_action(
                &state,
                &user,
                "isolate_host",
                "agent_id",
                agent_id,
                Some(ttl as i64),
                body.get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                None,
                true,
            )
            .await;
            (StatusCode::OK, Json(serde_json::json!({ "command_id": command_id, "agent_id": agent_id, "action": "isolate_host", "status": "queued" }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e.message()})),
        )
            .into_response(),
    }
}

/// POST /api/reactive/unisolate_host — Remove network isolation
pub async fn api_unisolate_host(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "authority role required"})),
        )
            .into_response();
    }
    let agent_id = body
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if agent_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "agent_id required"})),
        )
            .into_response();
    }

    match state
        .response_hub
        .dispatch(
            agent_id,
            CommandKind::RestoreNetwork,
            None,
            None,
            60,
            HashMap::new(),
            None,
        )
        .await
    {
        Ok(command_id) => {
            audit_log::log_reactive_action(
                &state,
                &user,
                "unisolate_host",
                "agent_id",
                agent_id,
                None,
                body.get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                None,
                true,
            )
            .await;
            (StatusCode::OK, Json(serde_json::json!({ "command_id": command_id, "agent_id": agent_id, "action": "unisolate_host", "status": "queued" }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e.message()})),
        )
            .into_response(),
    }
}

/// POST /api/reactive/collect_evidence — Request triage bundle  from agent
pub async fn api_collect_evidence(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "authority role required"})),
        )
            .into_response();
    }
    let agent_id = body
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if agent_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "agent_id required"})),
        )
            .into_response();
    }

    let mut args = HashMap::new();
    if let Some(et) = body.get("evidence_type").and_then(|v| v.as_str()) {
        args.insert("evidence_type".to_string(), et.to_string());
    }

    match state
        .response_hub
        .dispatch(
            agent_id,
            CommandKind::TriageBundle,
            None,
            None,
            300,
            args,
            None,
        )
        .await
    {
        Ok(command_id) => {
            audit_log::log_reactive_action(
                &state,
                &user,
                "collect_evidence",
                "agent_id",
                agent_id,
                None,
                body.get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                None,
                true,
            )
            .await;
            (StatusCode::OK, Json(serde_json::json!({ "command_id": command_id, "agent_id": agent_id, "action": "collect_evidence", "status": "queued" }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e.message()})),
        )
            .into_response(),
    }
}

/// POST /api/reactive/kill_process — Kill a process on an agent via custom command
pub async fn api_kill_process(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "authority role required"})),
        )
            .into_response();
    }
    let agent_id = body
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if agent_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "agent_id and pid or process_name required"})),
        )
            .into_response();
    }

    let mut args = HashMap::new();
    if let Some(pid) = body.get("pid").and_then(|v| v.as_u64()) {
        args.insert("pid".to_string(), pid.to_string());
    }
    if let Some(pname) = body.get("process_name").and_then(|v| v.as_str()) {
        args.insert("process_name".to_string(), pname.to_string());
    }

    match state
        .response_hub
        .dispatch(
            agent_id,
            CommandKind::Custom,
            None,
            None,
            60,
            args,
            Some("kill_process".to_string()),
        )
        .await
    {
        Ok(command_id) => {
            audit_log::log_reactive_action(
                &state,
                &user,
                "kill_process",
                "agent_id",
                agent_id,
                None,
                body.get("reason")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                None,
                true,
            )
            .await;
            (StatusCode::OK, Json(serde_json::json!({ "command_id": command_id, "agent_id": agent_id, "action": "kill_process", "status": "queued" }))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": e.message()})),
        )
            .into_response(),
    }
}

/// GET /api/reactive/summary — Summary of all reactive controls
pub async fn api_reactive_summary(State(state): State<AppState>) -> impl IntoResponse {
    let blocks = state.reactive.list_blocks().await;
    Json(serde_json::json!({
        "blocked_ips": blocks.blocked_ips.len(),
        "blocked_users": blocks.blocked_users.len(),
        "blocks": blocks,
        "capabilities": [
            "block_ip", "unblock_ip", "block_user", "unblock_user",
            "isolate_host", "unisolate_host", "collect_evidence",
            "kill_process", "logout_user", "dispatch_command",
        ],
        "timestamp": chrono::Utc::now().to_rfc3339(),
    }))
}
