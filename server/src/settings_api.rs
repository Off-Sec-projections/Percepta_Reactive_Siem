use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::warn;
use tracing::info;
use crate::auth::{AuthedUser, Role};
use crate::dr::DrRuntimeOverridePatch;
use crate::enroll::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeTuning {
    pub reactive_default_ttl_secs: i64,
    pub reactive_analyst_max_ttl_secs: i64,
    pub reactive_windows_script_ttl_secs: i64,
    pub reactive_dispatch_default_ttl_secs: u32,
    pub playbooks_default_runs_limit: usize,
}

impl RuntimeTuning {
    fn from_env() -> Self {
        Self {
            reactive_default_ttl_secs: env_i64(
                "PERCEPTA_REACTIVE_DEFAULT_TTL_SECS",
                900,
                30,
                31_536_000,
            ),
            reactive_analyst_max_ttl_secs: env_i64(
                "PERCEPTA_REACTIVE_ANALYST_MAX_TTL_SECS",
                900,
                30,
                31_536_000,
            ),
            reactive_windows_script_ttl_secs: env_i64(
                "PERCEPTA_REACTIVE_WINDOWS_SCRIPT_DEFAULT_TTL_SECS",
                900,
                30,
                2_592_000,
            ),
            reactive_dispatch_default_ttl_secs: env_u32(
                "PERCEPTA_REACTIVE_DISPATCH_DEFAULT_TTL_SECS",
                0,
                0,
                31_536_000,
            ),
            playbooks_default_runs_limit: env_usize(
                "PERCEPTA_PLAYBOOK_RUNS_DEFAULT_LIMIT",
                100,
                1,
                500,
            ),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuntimeTuningPatch {
    #[serde(default)]
    pub reactive_default_ttl_secs: Option<i64>,
    #[serde(default)]
    pub reactive_analyst_max_ttl_secs: Option<i64>,
    #[serde(default)]
    pub reactive_windows_script_ttl_secs: Option<i64>,
    #[serde(default)]
    pub reactive_dispatch_default_ttl_secs: Option<u32>,
    #[serde(default)]
    pub playbooks_default_runs_limit: Option<usize>,

    #[serde(default)]
    pub dr_enabled_override: Option<bool>,
    #[serde(default)]
    pub dr_verify_interval_secs: Option<u64>,
    #[serde(default)]
    pub dr_restore_drill_enabled: Option<bool>,
    #[serde(default)]
    pub dr_restore_drill_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeTuningResponse {
    pub tuning: RuntimeTuning,
    pub dr_effective: crate::dr::DrEffectiveConfig,
    /// Non-empty when one or more requested values were silently clamped.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub struct RuntimeTuningStore {
    inner: RwLock<RuntimeTuning>,
}

impl RuntimeTuningStore {
    pub fn from_env() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(RuntimeTuning::from_env()),
        })
    }

    pub async fn snapshot(&self) -> RuntimeTuning {
        self.inner.read().await.clone()
    }

    pub async fn apply_patch(&self, patch: &RuntimeTuningPatch) -> RuntimeTuning {
        let mut guard = self.inner.write().await;

        if let Some(v) = patch.reactive_default_ttl_secs {
            guard.reactive_default_ttl_secs = v.clamp(30, 31_536_000);
        }
        if let Some(v) = patch.reactive_analyst_max_ttl_secs {
            guard.reactive_analyst_max_ttl_secs = v.clamp(30, 31_536_000);
        }
        if let Some(v) = patch.reactive_windows_script_ttl_secs {
            guard.reactive_windows_script_ttl_secs = v.clamp(30, 2_592_000);
        }
        if let Some(v) = patch.reactive_dispatch_default_ttl_secs {
            guard.reactive_dispatch_default_ttl_secs = v.clamp(1, 3_600);
        }
        if let Some(v) = patch.playbooks_default_runs_limit {
            guard.playbooks_default_runs_limit = v.clamp(1, 500);
        }

        if guard.reactive_analyst_max_ttl_secs > guard.reactive_default_ttl_secs {
            guard.reactive_analyst_max_ttl_secs = guard.reactive_default_ttl_secs;
        }

        guard.clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UiSnapshot {
    #[serde(default)]
    pub updated_at_ms: i64,
    #[serde(default)]
    pub items: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UiSnapshotPatch {
    #[serde(default)]
    pub updated_at_ms: Option<i64>,
    #[serde(default)]
    pub items: HashMap<String, String>,
}

pub struct UiSnapshotStore {
    path: PathBuf,
    inner: RwLock<UiSnapshot>,
}

impl UiSnapshotStore {
    pub fn from_env() -> Arc<Self> {
        let path = std::env::var("PERCEPTA_UI_SNAPSHOT_FILE")
            .ok()
            .map(PathBuf::from)
            .unwrap_or_else(default_ui_snapshot_path);

        let initial = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<UiSnapshot>(&raw).ok())
            .unwrap_or_default();

        Arc::new(Self {
            path,
            inner: RwLock::new(initial),
        })
    }

    pub async fn snapshot(&self) -> UiSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn apply_patch(&self, patch: UiSnapshotPatch) -> UiSnapshot {
        let next = UiSnapshot {
            updated_at_ms: patch
                .updated_at_ms
                .unwrap_or_else(now_ms)
                .clamp(0, 4_102_444_800_000),
            items: sanitize_ui_items(patch.items),
        };

        {
            let mut guard = self.inner.write().await;
            *guard = next.clone();
        }

        if let Err(err) = self.persist(&next).await {
            warn!("Failed to persist UI snapshot: {}", err);
        }

        next
    }

    async fn persist(&self, snapshot: &UiSnapshot) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let tmp_path = self.path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(snapshot)?;
        tokio::fs::write(&tmp_path, body).await?;
        tokio::fs::rename(&tmp_path, &self.path).await?;
        Ok(())
    }
}

pub async fn api_get_ui_snapshot(State(state): State<AppState>) -> Json<UiSnapshot> {
    Json(state.ui_snapshot.snapshot().await)
}

pub async fn api_update_ui_snapshot(
    State(state): State<AppState>,
    Json(req): Json<UiSnapshotPatch>,
) -> Json<UiSnapshot> {
    Json(state.ui_snapshot.apply_patch(req).await)
}

pub async fn api_get_runtime_tuning(
    State(state): State<AppState>,
    Extension(user): Extension<AuthedUser>,
) -> Result<Json<RuntimeTuningResponse>, StatusCode> {
    if user.role != Role::Authority && user.role != Role::Analyst {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Json(RuntimeTuningResponse {
        tuning: state.runtime_tuning.snapshot().await,
        dr_effective: state.dr.effective_config().await,
        warnings: vec![],
    }))
}

pub async fn api_update_runtime_tuning(
    State(state): State<AppState>,
    Extension(user): Extension<AuthedUser>,
    Json(req): Json<RuntimeTuningPatch>,
) -> Result<Json<RuntimeTuningResponse>, StatusCode> {
    if user.role != Role::Authority {
        return Err(StatusCode::FORBIDDEN);
    }

    let tuning = state.runtime_tuning.apply_patch(&req).await;

    // Persist the updated tuning to ClickHouse so it survives restarts.
    {
        let db = state.db.clone();
        let tuning_snapshot = tuning.clone();
        tokio::spawn(async move {
            persist_runtime_tuning(&db, &tuning_snapshot).await;
        });
    }

    let dr_patch = DrRuntimeOverridePatch {
        enabled: req.dr_enabled_override,
        verify_interval_secs: req.dr_verify_interval_secs.map(|v| v.clamp(60, 86_400)),
        restore_drill_enabled: req.dr_restore_drill_enabled,
        restore_drill_interval_secs: req
            .dr_restore_drill_interval_secs
            .map(|v| v.clamp(300, 2_592_000)),
    };
    state.dr.apply_runtime_overrides(dr_patch).await;

    // Detect and surface any values that were silently clamped so the operator
    // is not left wondering why their setting did not take effect.
    let mut warnings = Vec::new();
    if let Some(requested) = req.reactive_analyst_max_ttl_secs {
        let clamped = requested.clamp(30, 31_536_000);
        if tuning.reactive_analyst_max_ttl_secs != clamped {
            warnings.push(format!(
                "reactive_analyst_max_ttl_secs adjusted from {} to {} \
                 (cannot exceed reactive_default_ttl_secs = {})",
                requested, tuning.reactive_analyst_max_ttl_secs, tuning.reactive_default_ttl_secs
            ));
        }
    }

    Ok(Json(RuntimeTuningResponse {
        tuning,
        dr_effective: state.dr.effective_config().await,
        warnings,
    }))
}

fn env_i64(key: &str, default: i64, min: i64, max: i64) -> i64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

fn env_u32(key: &str, default: u32, min: u32, max: u32) -> u32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

fn default_ui_snapshot_path() -> PathBuf {
    if let Ok(d) = std::env::var("PERCEPTA_BASE_DIR") {
        let p = PathBuf::from(&d);
        if p.is_dir() {
            return p.join("ui_snapshot.json");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(format!(
        "{}/.local/share/percepta-siem/ui_snapshot.json",
        home
    ))
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(dur.as_millis()).unwrap_or(i64::MAX)
}

fn sanitize_ui_items(items: HashMap<String, String>) -> HashMap<String, String> {
    const MAX_ITEMS: usize = 512;
    const MAX_KEY_LEN: usize = 128;
    const MAX_VAL_LEN: usize = 8192;

    let mut out = HashMap::with_capacity(items.len().min(MAX_ITEMS));
    for (key, value) in items.into_iter().take(MAX_ITEMS) {
        let k = key.trim();
        if k.is_empty() || k.len() > MAX_KEY_LEN {
            continue;
        }
        if !(k.starts_with("percepta.") || k == "percepta_theme" || k == "theme") {
            continue;
        }
        if value.len() > MAX_VAL_LEN {
            continue;
        }
        out.insert(k.to_string(), value);
    }
    out
}

// ── RuntimeTuning persistence ─────────────────────────────────────────────

/// Persist the current RuntimeTuning snapshot to the shared `app_config`
/// ClickHouse table so settings survive server restarts.
pub async fn persist_runtime_tuning(db: &crate::db::Db, tuning: &RuntimeTuning) {
    let content = match serde_json::to_string(tuning) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to serialize RuntimeTuning for persistence: {}", e);
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
        k: "runtime_tuning",
        v: &content,
        updated_at: chrono::Utc::now().timestamp(),
    };
    // Ensure app_config table exists (idempotent).
    let _ = db
        .client()
        .query(
            "CREATE TABLE IF NOT EXISTS app_config \
             (k String, v String, updated_at Int64) \
             ENGINE = ReplacingMergeTree(updated_at) ORDER BY k",
        )
        .execute()
        .await;
    if let Err(e) = async {
        let mut ins = db
            .client()
            .insert("app_config")
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        ins.write(&row).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok::<_, anyhow::Error>(())
    }
    .await
    {
        warn!("Failed to persist runtime_tuning to ClickHouse: {:#}", e);
    }
}

/// Load RuntimeTuning from ClickHouse on startup and apply it to the store.
/// On failure the store keeps its compile-time / env-var defaults.
pub async fn load_runtime_tuning_from_ch(
    db: &crate::db::Db,
    store: &std::sync::Arc<RuntimeTuningStore>,
) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CfgRow {
        v: String,
    }
    let row = match db
        .client()
        .query(
            "SELECT argMax(v, updated_at) AS v \
             FROM app_config WHERE k = 'runtime_tuning' GROUP BY k",
        )
        .fetch_one::<CfgRow>()
        .await
    {
        Ok(r) => r,
        Err(_) => return, // table empty or not yet created — keep defaults
    };
    match serde_json::from_str::<RuntimeTuning>(&row.v) {
        Ok(saved) => {
            let mut guard = store.inner.write().await;
            *guard = saved;
            info!("Loaded persisted RuntimeTuning from ClickHouse");
        }
        Err(e) => {
            warn!("Failed to deserialize persisted RuntimeTuning: {} (keeping defaults)", e);
        }
    }
}

// ── FIM Configuration ─────────────────────────────────────────────────────

/// FIM configuration stored in `app_config` under key `fim_config`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FimConfig {
    pub paths: Vec<String>,
    #[serde(default = "default_true")]
    pub recursive: bool,
    #[serde(default = "default_fim_debounce")]
    pub debounce_ms: u64,
}

fn default_true() -> bool { true }
fn default_fim_debounce() -> u64 { 250 }

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            recursive: true,
            debounce_ms: 250,
        }
    }
}

/// GET /api/settings/fim — retrieve current FIM configuration.
pub async fn api_get_fim_config(
    State(state): State<crate::AppState>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match load_fim_config(&state.db).await {
        Some(cfg) => axum::Json(cfg).into_response(),
        None => axum::Json(FimConfig::default()).into_response(),
    }
}

/// POST /api/settings/fim — save FIM configuration.
pub async fn api_update_fim_config(
    State(state): State<crate::AppState>,
    axum::Json(payload): axum::Json<FimConfig>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Validate paths are non-empty strings
    let paths: Vec<String> = payload
        .paths
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    let cfg = FimConfig {
        paths,
        recursive: payload.recursive,
        debounce_ms: payload.debounce_ms.clamp(50, 10_000),
    };
    persist_fim_config(&state.db, &cfg).await;
    axum::Json(serde_json::json!({"ok": true})).into_response()
}

/// Persist FIM config to ClickHouse `app_config` table.
async fn persist_fim_config(db: &crate::db::Db, cfg: &FimConfig) {
    let content = match serde_json::to_string(cfg) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to serialize FimConfig: {}", e);
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
        k: "fim_config",
        v: &content,
        updated_at: chrono::Utc::now().timestamp(),
    };
    let _ = db
        .client()
        .query(
            "CREATE TABLE IF NOT EXISTS app_config \
             (k String, v String, updated_at Int64) \
             ENGINE = ReplacingMergeTree(updated_at) ORDER BY k",
        )
        .execute()
        .await;
    if let Err(e) = async {
        let mut ins = db
            .client()
            .insert("app_config")
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        ins.write(&row).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok::<_, anyhow::Error>(())
    }
    .await
    {
        warn!("Failed to persist fim_config to ClickHouse: {:#}", e);
    }
}

/// Load FIM config from ClickHouse.
pub async fn load_fim_config(db: &crate::db::Db) -> Option<FimConfig> {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CfgRow {
        v: String,
    }
    let row = db
        .client()
        .query(
            "SELECT argMax(v, updated_at) AS v \
             FROM app_config WHERE k = 'fim_config' GROUP BY k",
        )
        .fetch_one::<CfgRow>()
        .await
        .ok()?;
    serde_json::from_str(&row.v).ok()
}
