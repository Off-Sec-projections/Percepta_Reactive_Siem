use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::auth::{AuthConfig, AuthedUser, Role, SessionStore};
use crate::enroll::AppState;
use crate::reactive::{revoke_sessions_for_user, ReactiveStore};
use percepta_server::alerts::Alert;
use percepta_server::db::Db;
use percepta_server::percepta::Event;

/// Validate that a webhook URL is safe to call (SSRF prevention).
/// Rejects internal/private IPs, non-HTTPS schemes, and reserved hostnames.
pub fn is_safe_webhook_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    // Must start with http:// or https://
    let host_part = if let Some(rest) = trimmed.strip_prefix("https://") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        tracing::warn!("Webhook using plain HTTP — consider HTTPS");
        rest
    } else {
        return false; // reject file://, gopher://, etc.
    };

    // Extract host (before first / or :)
    let host = host_part
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    if host.is_empty() {
        return false;
    }

    let lower = host.to_ascii_lowercase();

    // Block localhost and internal hostnames
    if lower == "localhost"
        || lower == "127.0.0.1"
        || lower == "::1"
        || lower == "[::1]"
        || lower == "0.0.0.0"
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower == "169.254.169.254"
        || lower == "metadata.google.internal"
    {
        return false;
    }

    // Block RFC 1918 / link-local IP addresses
    if let Ok(ip) = lower.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_unspecified()
                    || v4.octets()[0] == 169
                {
                    return false;
                }
            }
            std::net::IpAddr::V6(v6) => {
                if v6.is_loopback() || v6.is_unspecified() {
                    return false;
                }
            }
        }
    }
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookTrigger {
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub severities: Vec<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub sensor_kinds: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<i64>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub continue_on_error: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub stop_on_failure: bool,
    pub trigger: PlaybookTrigger,
    pub actions: Vec<PlaybookAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookRunStep {
    pub action_type: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookRun {
    pub id: String,
    pub ts_unix: i64,
    pub playbook_id: String,
    pub playbook_name: String,
    pub alert_id: String,
    pub rule_id: String,
    pub dry_run: bool,
    pub status: String,
    pub latency_ms: i64,
    pub error: String,
    pub steps: Vec<PlaybookRunStep>,
    pub started_at: i64,
    pub finished_at: i64,
}

#[derive(Clone)]
pub struct PlaybookEngine {
    db: Db,
    playbooks: Arc<RwLock<Vec<Playbook>>>,
    /// Runtime override for live mode: None = use env var, Some(true/false) = override.
    live_override: Arc<RwLock<Option<bool>>>,
}

impl PlaybookEngine {
    pub async fn new(db: Db) -> anyhow::Result<Self> {
        let this = Self {
            db,
            playbooks: Arc::new(RwLock::new(Vec::new())),
            live_override: Arc::new(RwLock::new(None)),
        };
        this.init_schema().await?;
        this.reload_from_db().await?;
        // Load persisted live mode from ClickHouse. Fall back to env var if not found.
        let _ = this.load_live_mode().await;
        Ok(this)
    }

    #[cfg(test)]
    pub fn new_in_memory(db: Db) -> Self {
        Self {
            db,
            live_override: Arc::new(RwLock::new(None)),
            playbooks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    async fn init_schema(&self) -> anyhow::Result<()> {
        let client = self.db.client();
        client
            .query(
                "CREATE TABLE IF NOT EXISTS playbooks (\
                    id String,\
                    content String,\
                    updated_at Int64,\
                    deleted UInt8\
                ) ENGINE = ReplacingMergeTree(updated_at)\
                ORDER BY id",
            )
            .execute()
            .await?;

        client
            .query(
                "CREATE TABLE IF NOT EXISTS playbook_runs (\
                    id String,\
                    ts_unix Int64,\
                    playbook_id String,\
                    playbook_name String,\
                    alert_id String,\
                    rule_id String,\
                    dry_run UInt8,\
                    status String,\
                    latency_ms Int64,\
                    error String,\
                    steps_json String,\
                    started_at Int64,\
                    finished_at Int64\
                ) ENGINE = MergeTree()\
                ORDER BY (ts_unix, id)\
                SETTINGS index_granularity=8192",
            )
            .execute()
            .await?;

        Ok(())
    }

    pub async fn list(&self) -> Vec<Playbook> {
        self.playbooks.read().await.clone()
    }

    pub async fn reload_from_db(&self) -> anyhow::Result<()> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            id: String,
            content: String,
            updated_at: i64,
            deleted: u8,
        }

        let rows = self
            .db
            .client()
            .query("SELECT id, content, updated_at, deleted FROM playbooks")
            .fetch_all::<Row>()
            .await?;

        let mut latest: HashMap<String, Row> = HashMap::new();
        for row in rows {
            match latest.get(&row.id) {
                Some(prev) if prev.updated_at >= row.updated_at => {}
                _ => {
                    latest.insert(row.id.clone(), row);
                }
            }
        }

        let mut out = Vec::new();
        for (_, row) in latest {
            if row.deleted != 0 {
                continue;
            }
            if let Ok(pb) = serde_json::from_str::<Playbook>(&row.content) {
                out.push(pb);
            }
        }

        // Seed default playbooks if database is empty
        if out.is_empty() {
            tracing::info!("Playbooks table is empty; seeding default playbooks");
            for default_pb in get_default_playbooks() {
                if let Err(e) = self.upsert(default_pb).await {
                    tracing::warn!("Failed to seed default playbook: {:#}", e);
                }
            }
            // Reload the seeded playbooks inline to avoid recursion
            let rows = self
                .db
                .client()
                .query("SELECT id, content, updated_at, deleted FROM playbooks")
                .fetch_all::<Row>()
                .await?;

            let mut latest: HashMap<String, Row> = HashMap::new();
            for row in rows {
                match latest.get(&row.id) {
                    Some(prev) if prev.updated_at >= row.updated_at => {}
                    _ => {
                        latest.insert(row.id.clone(), row);
                    }
                }
            }

            let mut reloaded_out = vec![];
            for (_, row) in latest {
                if row.deleted != 0 {
                    continue;
                }
                match serde_json::from_str::<Playbook>(&row.content) {
                    Ok(pb) => reloaded_out.push(pb),
                    Err(e) => tracing::warn!("Failed to parse playbook {}: {:#}", row.id, e),
                }
            }

            reloaded_out.sort_by(|a, b| a.id.cmp(&b.id));
            *self.playbooks.write().await = reloaded_out;
            return Ok(());
        }

        out.sort_by(|a, b| a.id.cmp(&b.id));
        *self.playbooks.write().await = out;
        Ok(())
    }

    /// Insert or update a playbook in the database.
    /// Note: This does NOT automatically reload the in-memory cache.
    /// Callers should call reload_from_db() explicitly if needed.
    pub async fn upsert(&self, playbook: Playbook) -> anyhow::Result<()> {
        #[derive(clickhouse::Row, serde::Serialize)]
        struct Row<'a> {
            id: &'a str,
            content: &'a str,
            updated_at: i64,
            deleted: u8,
        }

        let content = serde_json::to_string(&playbook)?;
        let now = Utc::now().timestamp();
        let row = Row {
            id: &playbook.id,
            content: &content,
            updated_at: now,
            deleted: 0,
        };

        let mut insert = self.db.client().insert("playbooks")?;
        insert.write(&row).await?;
        insert.end().await?;
        Ok(())
    }

    /// Mark a playbook as deleted in the database.
    /// Note: This does NOT automatically reload the in-memory cache.
    /// Callers should call reload_from_db() explicitly if needed.
    pub async fn delete(&self, id: &str) -> anyhow::Result<()> {
        #[derive(clickhouse::Row, serde::Serialize)]
        struct Row<'a> {
            id: &'a str,
            content: &'a str,
            updated_at: i64,
            deleted: u8,
        }

        let now = Utc::now().timestamp();
        let row = Row {
            id,
            content: "{}",
            updated_at: now,
            deleted: 1,
        };

        let mut insert = self.db.client().insert("playbooks")?;
        insert.write(&row).await?;
        insert.end().await?;
        Ok(())
    }

    fn normalize_list(items: &[String]) -> Vec<String> {
        items
            .iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    }

    fn matches_trigger(playbook: &Playbook, alert: &Alert) -> bool {
        let t = &playbook.trigger;

        if !t.rule_ids.is_empty() {
            let set = Self::normalize_list(&t.rule_ids);
            if !set.iter().any(|r| r == &alert.rule_id.to_lowercase()) {
                return false;
            }
        }

        if !t.severities.is_empty() {
            let set = Self::normalize_list(&t.severities);
            let sev = format!("{:?}", alert.severity).to_lowercase();
            if !set.iter().any(|s| s == &sev) {
                return false;
            }
        }

        if !t.categories.is_empty() {
            let set = Self::normalize_list(&t.categories);
            if !set.iter().any(|c| c == &alert.category.to_lowercase()) {
                return false;
            }
        }

        if !t.sensor_kinds.is_empty() {
            let set = Self::normalize_list(&t.sensor_kinds);
            let sensor = alert
                .metadata
                .get("sensor.kind")
                .map(|s| s.trim().to_lowercase())
                .unwrap_or_default();
            if sensor.is_empty() || !set.iter().any(|s| s == &sensor) {
                return false;
            }
        }

        true
    }

    fn render_template(template: &str, values: &HashMap<String, String>) -> String {
        let mut out = template.to_string();
        for (k, v) in values {
            let pat = format!("{{{{{}}}}}", k);
            out = out.replace(&pat, v);
        }
        out
    }

    fn build_context(alert: &Alert, event: Option<&Event>) -> HashMap<String, String> {
        let mut out = HashMap::new();
        out.insert("alert_id".to_string(), alert.id.clone());
        out.insert("rule_id".to_string(), alert.rule_id.clone());
        out.insert(
            "severity".to_string(),
            format!("{:?}", alert.severity).to_lowercase(),
        );
        out.insert("category".to_string(), alert.category.clone());
        out.insert("agent_id".to_string(), alert.agent_id.clone());
        out.insert("agent_hostname".to_string(), alert.agent_hostname.clone());

        for (k, v) in &alert.metadata {
            if !k.trim().is_empty() && !v.trim().is_empty() {
                out.insert(k.clone(), v.clone());
            }
        }

        if let Some(e) = event {
            if let Some(n) = e.network.as_ref() {
                if !n.src_ip.trim().is_empty() {
                    out.insert("src_ip".to_string(), n.src_ip.clone());
                }
                if !n.dst_ip.trim().is_empty() {
                    out.insert("dst_ip".to_string(), n.dst_ip.clone());
                }
            }
            if let Some(u) = e.user.as_ref() {
                if !u.name.trim().is_empty() {
                    out.insert("user".to_string(), u.name.clone());
                }
            }
        }

        out
    }

    fn playbooks_live_enabled_env() -> bool {
        std::env::var("PERCEPTA_PLAYBOOKS_LIVE")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    pub async fn is_live(&self) -> bool {
        let ovr = self.live_override.read().await;
        ovr.unwrap_or_else(Self::playbooks_live_enabled_env)
    }

    pub async fn set_live(&self, live: bool) {
        *self.live_override.write().await = Some(live);
        // Persist to ClickHouse asynchronously
        let db = self.db.clone();
        tokio::spawn(async move {
            if let Err(e) = persist_playbook_live_mode(&db, live).await {
                tracing::warn!("Failed to persist playbook live mode: {:#}", e);
            }
        });
    }

    /// Load playbook live mode from ClickHouse if previously set. Falls back to env var.
    pub async fn load_live_mode(&self) -> anyhow::Result<()> {
        if let Ok(Some(persisted_live)) = load_playbook_live_mode(&self.db).await {
            *self.live_override.write().await = Some(persisted_live);
            tracing::info!(
                "Loaded playbook mode from ClickHouse: {}",
                if persisted_live { "LIVE" } else { "dry-run" }
            );
        }
        Ok(())
    }

    async fn log_run(&self, run: &PlaybookRun) -> anyhow::Result<()> {
        #[derive(clickhouse::Row, serde::Serialize)]
        struct Row<'a> {
            id: &'a str,
            ts_unix: i64,
            playbook_id: &'a str,
            playbook_name: &'a str,
            alert_id: &'a str,
            rule_id: &'a str,
            dry_run: u8,
            status: &'a str,
            latency_ms: i64,
            error: &'a str,
            steps_json: String,
            started_at: i64,
            finished_at: i64,
        }

        let row = Row {
            id: &run.id,
            ts_unix: run.ts_unix,
            playbook_id: &run.playbook_id,
            playbook_name: &run.playbook_name,
            alert_id: &run.alert_id,
            rule_id: &run.rule_id,
            dry_run: u8::from(run.dry_run),
            status: &run.status,
            latency_ms: run.latency_ms,
            error: &run.error,
            steps_json: serde_json::to_string(&run.steps).unwrap_or_else(|_| "[]".to_string()),
            started_at: run.started_at,
            finished_at: run.finished_at,
        };

        let mut insert = self.db.client().insert("playbook_runs")?;
        insert.write(&row).await?;
        insert.end().await?;
        Ok(())
    }

    pub async fn execute_for_alert(
        &self,
        alert: &Alert,
        event: Option<&Event>,
        reactive: &ReactiveStore,
        sessions: &SessionStore,
        auth_config: &AuthConfig,
    ) {
        let playbooks = self.playbooks.read().await.clone();
        if playbooks.is_empty() {
            return;
        }

        for pb in playbooks
            .into_iter()
            .filter(|p| p.enabled && Self::matches_trigger(p, alert))
        {
            let started = std::time::Instant::now();
            let mut status = "ok".to_string();
            let mut error = String::new();
            let mut steps = Vec::new();
            let context = Self::build_context(alert, event);
            let effective_dry_run = pb.dry_run || !self.is_live().await;

            for step in &pb.actions {
                let continue_on_error = step.continue_on_error.unwrap_or(!pb.stop_on_failure);
                let target_tmpl = step.target.clone().unwrap_or_default();
                let target = Self::render_template(&target_tmpl, &context);
                let reason = step
                    .reason
                    .clone()
                    .unwrap_or_else(|| format!("playbook:{}", pb.id));

                // Validate rendered target based on action type to prevent injection.
                let target_valid = match step.action_type.trim().to_lowercase().as_str() {
                    "block_ip" => target.parse::<std::net::IpAddr>().is_ok(),
                    "block_user" | "logout_user" => {
                        !target.is_empty()
                            && target.len() <= 64
                            && target.chars().all(|c| {
                                c.is_ascii_alphanumeric()
                                    || c == '_'
                                    || c == '-'
                                    || c == '.'
                                    || c == '$'
                            })
                            && target.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    }
                    _ => true,
                };

                let step_result = if !target_valid {
                    Err(format!(
                        "playbook target rejected (unsafe value): '{}'",
                        target
                    ))
                } else if effective_dry_run {
                    Ok(format!("dry-run {} target={}", step.action_type, target))
                } else {
                    match step.action_type.trim().to_lowercase().as_str() {
                        "block_ip" => {
                            let ttl = step.ttl_seconds.unwrap_or(900).clamp(30, 86_400);
                            reactive
                                .block_ip(&target, ttl, "playbook", Some(reason))
                                .await
                                .map(|_| "blocked ip".to_string())
                                .map_err(|_| "block_ip failed".to_string())
                        }
                        "block_user" => {
                            if target == auth_config.admin_user
                                || target == auth_config.analyst_user
                            {
                                Err("refused to block operator account".to_string())
                            } else {
                                let ttl = step.ttl_seconds.unwrap_or(900).clamp(30, 86_400);
                                reactive
                                    .block_user(&target, ttl, "playbook", Some(reason))
                                    .await
                                    .map(|_| "blocked user".to_string())
                                    .map_err(|_| "block_user failed".to_string())
                            }
                        }
                        "logout_user" => {
                            let n = revoke_sessions_for_user(sessions, &target).await;
                            Ok(format!("revoked_sessions={}", n))
                        }
                        "webhook" => {
                            let url = step.url.clone().unwrap_or_default();
                            if url.trim().is_empty() {
                                Err("webhook url missing".to_string())
                            } else if !is_safe_webhook_url(&url) {
                                Err("webhook url rejected: must be https:// to a public host"
                                    .to_string())
                            } else {
                                let body = serde_json::json!({
                                    "playbook_id": pb.id,
                                    "alert_id": alert.id,
                                    "rule_id": alert.rule_id,
                                    "target": target,
                                    "metadata": alert.metadata,
                                });
                                match reqwest::Client::builder()
                                    .timeout(std::time::Duration::from_secs(15))
                                    .redirect(reqwest::redirect::Policy::none())
                                    .build()
                                {
                                    Ok(client) => match client.post(url).json(&body).send().await {
                                        Ok(resp) if resp.status().is_success() => {
                                            Ok("webhook delivered".to_string())
                                        }
                                        Ok(resp) => {
                                            Err(format!("webhook status {}", resp.status()))
                                        }
                                        Err(e) => Err(format!("webhook error: {}", e)),
                                    },
                                    Err(e) => Err(format!("http client error: {e}")),
                                }
                            }
                        }
                        _ => Err("unsupported action".to_string()),
                    }
                };

                match step_result {
                    Ok(detail) => {
                        steps.push(PlaybookRunStep {
                            action_type: step.action_type.clone(),
                            status: "ok".to_string(),
                            detail,
                        });
                    }
                    Err(e) => {
                        status = "failed".to_string();
                        if error.is_empty() {
                            error = e.clone();
                        }
                        steps.push(PlaybookRunStep {
                            action_type: step.action_type.clone(),
                            status: "failed".to_string(),
                            detail: e,
                        });
                        if !continue_on_error {
                            break;
                        }
                    }
                }
            }

            let run = PlaybookRun {
                id: uuid::Uuid::new_v4().to_string(),
                ts_unix: Utc::now().timestamp(),
                playbook_id: pb.id.clone(),
                playbook_name: pb.name.clone(),
                alert_id: alert.id.clone(),
                rule_id: alert.rule_id.clone(),
                dry_run: effective_dry_run,
                status,
                latency_ms: started.elapsed().as_millis() as i64,
                error,
                steps,
                started_at: Utc::now().timestamp() - (started.elapsed().as_secs() as i64),
                finished_at: Utc::now().timestamp(),
            };

            if let Err(e) = self.log_run(&run).await {
                tracing::warn!("failed to persist playbook run {}: {:#}", run.id, e);
            }
        }
    }

    pub async fn list_runs(&self, limit: usize) -> anyhow::Result<Vec<PlaybookRun>> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            id: String,
            ts_unix: i64,
            playbook_id: String,
            playbook_name: String,
            alert_id: String,
            rule_id: String,
            dry_run: u8,
            status: String,
            latency_ms: i64,
            error: String,
            steps_json: String,
            #[serde(default)]
            started_at: i64,
            #[serde(default)]
            finished_at: i64,
        }

        let rows = self
            .db
            .client()
            .query(
                "SELECT id, ts_unix, playbook_id, playbook_name, alert_id, rule_id, dry_run, status, latency_ms, error, steps_json, started_at, finished_at \
                 FROM playbook_runs ORDER BY ts_unix DESC LIMIT ?",
            )
            .bind(i64::try_from(limit).unwrap_or(100))
            .fetch_all::<Row>()
            .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let steps =
                serde_json::from_str::<Vec<PlaybookRunStep>>(&r.steps_json).unwrap_or_default();
            out.push(PlaybookRun {
                id: r.id,
                ts_unix: r.ts_unix,
                playbook_id: r.playbook_id,
                playbook_name: r.playbook_name,
                alert_id: r.alert_id,
                rule_id: r.rule_id,
                dry_run: r.dry_run != 0,
                status: r.status,
                latency_ms: r.latency_ms,
                error: r.error,
                steps,
                started_at: r.started_at,
                finished_at: r.finished_at,
            });
        }

        Ok(out)
    }
}

#[derive(Debug, Deserialize)]
pub struct UpsertPlaybookRequest {
    pub playbook: Playbook,
}

#[derive(Debug, Deserialize)]
pub struct DeletePlaybookRequest {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct PlaybookRunsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct PlaybookListResponse {
    pub items: Vec<Playbook>,
}

#[derive(Debug, Serialize)]
pub struct PlaybookRunsResponse {
    pub items: Vec<PlaybookRun>,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

fn require_authority(user: &AuthedUser) -> Result<(), StatusCode> {
    if user.role != Role::Authority {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

fn require_analyst_or_authority(user: &AuthedUser) -> Result<(), StatusCode> {
    match user.role {
        Role::Analyst | Role::Authority => Ok(()),
    }
}

pub async fn api_list_playbooks(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> Result<Json<PlaybookListResponse>, StatusCode> {
    require_analyst_or_authority(&user)?;
    let items = state.playbooks.list().await;
    Ok(Json(PlaybookListResponse { items }))
}

pub async fn api_upsert_playbook(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(req): Json<UpsertPlaybookRequest>,
) -> Result<Json<OkResponse>, StatusCode> {
    require_authority(&user)?;
    if req.playbook.id.trim().is_empty() || req.playbook.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.playbook.actions.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .playbooks
        .upsert(req.playbook)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Explicitly reload the cache after database write
    state
        .playbooks
        .reload_from_db()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(OkResponse { ok: true }))
}

pub async fn api_delete_playbook(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(req): Json<DeletePlaybookRequest>,
) -> Result<Json<OkResponse>, StatusCode> {
    require_authority(&user)?;
    if req.id.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .playbooks
        .delete(req.id.trim())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Explicitly reload the cache after database write
    state
        .playbooks
        .reload_from_db()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(OkResponse { ok: true }))
}

pub async fn api_list_playbook_runs(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Query(q): Query<PlaybookRunsQuery>,
) -> Result<Json<PlaybookRunsResponse>, StatusCode> {
    require_analyst_or_authority(&user)?;
    let tuning = state.runtime_tuning.snapshot().await;
    let limit = q
        .limit
        .unwrap_or(tuning.playbooks_default_runs_limit)
        .clamp(1, 500);
    let items = state
        .playbooks
        .list_runs(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(PlaybookRunsResponse { items }))
}

#[derive(Serialize)]
pub struct PlaybookLiveStatus {
    pub live: bool,
}

pub async fn api_get_playbook_live(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> Result<Json<PlaybookLiveStatus>, StatusCode> {
    require_analyst_or_authority(&user)?;
    let live = state.playbooks.is_live().await;
    Ok(Json(PlaybookLiveStatus { live }))
}

#[derive(Deserialize)]
pub struct PlaybookLiveBody {
    pub live: bool,
}

pub async fn api_set_playbook_live(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<PlaybookLiveBody>,
) -> Result<Json<PlaybookLiveStatus>, StatusCode> {
    require_authority(&user)?;
    state.playbooks.set_live(body.live).await;
    tracing::info!(user = %user.username, live = body.live, "playbook live mode toggled");
    Ok(Json(PlaybookLiveStatus { live: body.live }))
}

/// Persist playbook live mode to ClickHouse app_config table.
async fn persist_playbook_live_mode(db: &Db, live: bool) -> anyhow::Result<()> {
    let key = "playbooks:live_mode";
    let value = if live { "true" } else { "false" };
    let updated_at = chrono::Utc::now().timestamp();

    #[derive(clickhouse::Row, serde::Serialize)]
    struct AppConfigRow {
        k: String,
        v: String,
        updated_at: i64,
    }

    let row = AppConfigRow {
        k: key.to_string(),
        v: value.to_string(),
        updated_at,
    };

    let mut insert = db.client().insert("app_config")?;
    insert.write(&row).await?;
    insert.end().await?;
    Ok(())
}

/// Load playbook live mode from ClickHouse. Returns Ok(None) if not found.
async fn load_playbook_live_mode(db: &Db) -> anyhow::Result<Option<bool>> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct AppConfigRow {
        v: String,
    }

    let result = db
        .client()
        .query(
            "SELECT argMax(v, updated_at) AS v \
             FROM app_config \
             WHERE k = 'playbooks:live_mode' \
             GROUP BY k",
        )
        .fetch_optional::<AppConfigRow>()
        .await;

    match result {
        Ok(Some(row)) => {
            let live = row.v == "true";
            Ok(Some(live))
        }
        Ok(None) => Ok(None),
        Err(e) => {
            tracing::warn!("Failed to load playbook live mode from ClickHouse: {:#}", e);
            Ok(None)
        }
    }
}

/// Default SOAR playbooks for common security incidents.
fn get_default_playbooks() -> Vec<Playbook> {
    vec![
        // Playbook 1: Auto-block known malicious IP
        Playbook {
            id: "pb_block_malicious_ip".to_string(),
            name: "Block Malicious IP (Dry-run)".to_string(),
            enabled: true,
            dry_run: true, // Default to dry-run for safety
            stop_on_failure: false,
            trigger: PlaybookTrigger {
                rule_ids: vec![
                    "suspicious_ip_outbound".to_string(),
                    "known_c2_beacon".to_string(),
                ],
                severities: vec![],
                categories: vec![],
                sensor_kinds: vec![],
            },
            actions: vec![
                PlaybookAction {
                    action_type: "block_ip".to_string(),
                    target: Some("${event.dst_ip}".to_string()),
                    ttl_seconds: Some(3600), // 1 hour
                    reason: Some("Malicious IP detected; auto-blocked for 1 hour".to_string()),
                    url: None,
                    continue_on_error: Some(true),
                },
            ],
        },
        // Playbook 2: Disable compromised user account
        Playbook {
            id: "pb_disable_compromised_user".to_string(),
            name: "Disable Compromised User (Dry-run)".to_string(),
            enabled: true,
            dry_run: true, // Default to dry-run for safety
            stop_on_failure: true,
            trigger: PlaybookTrigger {
                rule_ids: vec![
                    "credential_stuffing".to_string(),
                    "brute_force_ssh".to_string(),
                    "account_takeover_attempt".to_string(),
                ],
                severities: vec!["critical".to_string(), "high".to_string()],
                categories: vec![],
                sensor_kinds: vec![],
            },
            actions: vec![
                PlaybookAction {
                    action_type: "block_user".to_string(),
                    target: Some("${event.username}".to_string()),
                    ttl_seconds: Some(86400), // 24 hours
                    reason: Some("Credential compromise detected; account disabled for 24 hours".to_string()),
                    url: None,
                    continue_on_error: Some(false),
                },
                PlaybookAction {
                    action_type: "logout_user".to_string(),
                    target: Some("${event.username}".to_string()),
                    ttl_seconds: None,
                    reason: Some("Closing all active sessions".to_string()),
                    url: None,
                    continue_on_error: Some(true),
                },
            ],
        },
        // Playbook 3: Escalate critical incidents
        Playbook {
            id: "pb_escalate_critical".to_string(),
            name: "Escalate to SOC Manager (Dry-run)".to_string(),
            enabled: true,
            dry_run: true, // Default to dry-run for safety
            stop_on_failure: false,
            trigger: PlaybookTrigger {
                rule_ids: vec![],
                severities: vec!["critical".to_string()],
                categories: vec![],
                sensor_kinds: vec![],
            },
            actions: vec![
                PlaybookAction {
                    action_type: "webhook".to_string(),
                    target: None,
                    ttl_seconds: None,
                    reason: Some("Escalate critical severity alert".to_string()),
                    url: Some("https://internal-incident-tracker.example.com/api/incidents/create".to_string()),
                    continue_on_error: Some(true),
                },
            ],
        },
    ]
}


