//! REST API for honeypot trap management.
//!
//! - `GET  /api/honeypot/stats`    — trap statistics (hits, attackers, breakdown)
//! - `GET  /api/honeypot/config`   — current trap configuration
//! - `POST /api/honeypot/config`   — update trap configuration (Authority only)
//! - `POST /api/honeypot/block`    — manually block an attacker IP via traps

use crate::auth::{resolve_client_ip, AuthedUser, Role};
use crate::enroll::AppState;
use crate::honeypot_traps::PortTrapConfig;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

// ── Stats ──────────────────────────────────────────────────────────────────

/// GET /api/honeypot/stats
pub async fn api_honeypot_stats(
    State(state): State<AppState>,
    axum::extract::Extension(_user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    let stats = state.trap_tracker.snapshot().await;
    (StatusCode::OK, Json(stats)).into_response()
}

// ── Configuration ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneypotConfig {
    /// Whether web traps are enabled (fake endpoints on the HTTPS server).
    pub web_traps_enabled: bool,
    /// Whether TCP port traps are enabled. Changing this requires restart.
    pub tcp_traps_enabled: bool,
    /// TCP port trap definitions.
    pub tcp_traps: Vec<PortTrapConfig>,
    /// Auto-block attackers who hit traps (TTL in seconds, 0 = disabled).
    pub auto_block_ttl_seconds: i64,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            web_traps_enabled: true,
            tcp_traps_enabled: true,
            tcp_traps: PortTrapConfig::defaults(),
            auto_block_ttl_seconds: 300,
        }
    }
}

/// GET /api/honeypot/config
pub async fn api_honeypot_config_get(
    State(state): State<AppState>,
    axum::extract::Extension(_user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    let cfg = state.honeypot_config.read().await;
    (StatusCode::OK, Json(cfg.clone())).into_response()
}

/// POST /api/honeypot/config
pub async fn api_honeypot_config_set(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<HoneypotConfig>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "authority role required"})),
        )
            .into_response();
    }
    let mut cfg = state.honeypot_config.write().await;
    *cfg = body.clone();
    drop(cfg);
    // Persist to ClickHouse
    persist_honeypot_config(&state.db, &body).await;
    (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response()
}

/// Persist honeypot config to ClickHouse app_config table.
async fn persist_honeypot_config(db: &crate::db::Db, config: &HoneypotConfig) {
    let content = match serde_json::to_string(config) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to serialize honeypot config: {}", e);
            return;
        }
    };
    #[derive(clickhouse::Row, serde::Serialize)]
    struct CfgRow<'a> {
        k: &'a str,
        v: &'a str,
        updated_at: i64,
    }
    let row = CfgRow {
        k: "honeypot_config",
        v: &content,
        updated_at: chrono::Utc::now().timestamp(),
    };
    // Ensure app_config table exists
    let _ = db.client().query(
        "CREATE TABLE IF NOT EXISTS app_config (k String, v String, updated_at Int64) ENGINE = ReplacingMergeTree(updated_at) ORDER BY k"
    ).execute().await;
    if let Err(e) = async {
        let mut ins = db
            .client()
            .insert("app_config")
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        ins.write(&row)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok::<_, anyhow::Error>(())
    }
    .await
    {
        tracing::warn!("Failed to persist honeypot config: {:#}", e);
    }
}

/// Load honeypot config from ClickHouse on startup.
pub async fn load_honeypot_config_from_ch(
    db: &crate::db::Db,
    handle: &std::sync::Arc<tokio::sync::RwLock<HoneypotConfig>>,
) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CfgRow {
        v: String,
    }
    let rows = match db.client()
        .query("SELECT argMax(v, updated_at) AS v FROM app_config WHERE k = 'honeypot_config' GROUP BY k")
        .fetch_all::<CfgRow>().await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                "Failed to load honeypot config from ClickHouse: {} (keeping defaults)",
                e
            );
            return;
        }
    };
    let Some(row) = rows.first() else {
        tracing::info!("No persisted honeypot config found in ClickHouse; using defaults");
        return;
    };

    match serde_json::from_str::<HoneypotConfig>(&row.v) {
        Ok(cfg) => {
            if cfg.tcp_traps.is_empty() {
                tracing::warn!("Loaded honeypot config is empty; keeping current defaults");
                return;
            }
            *handle.write().await = cfg;
            tracing::info!("Loaded honeypot config from ClickHouse");
        }
        Err(e) => tracing::warn!(
            "Failed to parse saved honeypot config: {} (keeping defaults)",
            e
        ),
    }
}

// ── Manual block ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct BlockRequest {
    pub ip: String,
    #[serde(default = "default_block_ttl")]
    pub ttl_seconds: i64,
}

fn default_block_ttl() -> i64 {
    3600
}

/// POST /api/honeypot/block
pub async fn api_honeypot_block(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<BlockRequest>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "authority role required"})),
        )
            .into_response();
    }
    let ip = body.ip.trim();
    if ip.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "ip is required"})),
        )
            .into_response();
    }

    // Self-block protection
    let client_ip = resolve_client_ip(&headers, &addr);
    if ip == client_ip {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "cannot block your own IP"})),
        )
            .into_response();
    }

    match state
        .reactive
        .block_ip(
            ip,
            body.ttl_seconds,
            &user.username,
            Some("honeypot manual block".into()),
        )
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "ip": ip, "ttl": body.ttl_seconds})),
        )
            .into_response(),
        Err(status) => (status, Json(serde_json::json!({"error": "block failed"}))).into_response(),
    }
}
