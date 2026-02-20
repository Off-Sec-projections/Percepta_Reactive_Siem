use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use chrono::Utc;
use serde::Serialize;
use tokio::process::Command;
use tokio::sync::RwLock;

use crate::auth::{AuthedUser, Role};
use crate::enroll::AppState;

#[derive(Debug, Clone)]
pub struct DrConfig {
    pub enabled: bool,
    pub verify_interval_secs: u64,
    pub backup_dir: PathBuf,
    pub backup_max_age_secs: u64,
    pub backup_verify_cmd: Option<String>,
    pub restore_drill_enabled: bool,
    pub restore_drill_interval_secs: u64,
    pub restore_drill_cmd: Option<String>,
    pub cmd_timeout_secs: u64,
}

impl DrConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: env_bool("PERCEPTA_DR_ENABLE", true),
            verify_interval_secs: env_u64("PERCEPTA_DR_VERIFY_INTERVAL_SECS", 3600, 60, 86400),
            backup_dir: PathBuf::from(
                std::env::var("PERCEPTA_DR_BACKUP_DIR")
                    .unwrap_or_else(|_| "database/dumps".to_string()),
            ),
            backup_max_age_secs: env_u64("PERCEPTA_DR_BACKUP_MAX_AGE_SECS", 172800, 300, 2_592_000),
            backup_verify_cmd: env_opt("PERCEPTA_DR_BACKUP_VERIFY_CMD"),
            restore_drill_enabled: env_bool("PERCEPTA_DR_RESTORE_DRILL_ENABLE", false),
            restore_drill_interval_secs: env_u64(
                "PERCEPTA_DR_RESTORE_DRILL_INTERVAL_SECS",
                86400,
                300,
                2_592_000,
            ),
            restore_drill_cmd: env_opt("PERCEPTA_DR_RESTORE_DRILL_CMD"),
            cmd_timeout_secs: env_u64("PERCEPTA_DR_CMD_TIMEOUT_SECS", 900, 10, 7200),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DrStatus {
    pub enabled: bool,
    pub last_backup_verify_unix: Option<i64>,
    pub backup_verify_ok: bool,
    pub backup_verify_detail: String,
    pub last_restore_drill_unix: Option<i64>,
    pub restore_drill_ok: bool,
    pub restore_drill_detail: String,
    pub next_backup_verify_unix: Option<i64>,
    pub next_restore_drill_unix: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct DrRuntimeOverridePatch {
    pub enabled: Option<bool>,
    pub verify_interval_secs: Option<u64>,
    pub restore_drill_enabled: Option<bool>,
    pub restore_drill_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DrEffectiveConfig {
    pub enabled: bool,
    pub verify_interval_secs: u64,
    pub backup_dir: String,
    pub backup_max_age_secs: u64,
    pub backup_verify_cmd: Option<String>,
    pub restore_drill_enabled: bool,
    pub restore_drill_interval_secs: u64,
    pub restore_drill_cmd: Option<String>,
    pub cmd_timeout_secs: u64,
}

impl DrStatus {
    fn initial(enabled: bool) -> Self {
        Self {
            enabled,
            last_backup_verify_unix: None,
            backup_verify_ok: false,
            backup_verify_detail: "pending".to_string(),
            last_restore_drill_unix: None,
            restore_drill_ok: false,
            restore_drill_detail: "pending".to_string(),
            next_backup_verify_unix: None,
            next_restore_drill_unix: None,
        }
    }
}

pub struct DrAutomation {
    cfg: DrConfig,
    status: RwLock<DrStatus>,
    runtime_overrides: RwLock<DrRuntimeOverridePatch>,
}

impl DrAutomation {
    pub fn from_env() -> Self {
        let cfg = DrConfig::from_env();
        Self {
            status: RwLock::new(DrStatus::initial(cfg.enabled)),
            cfg,
            runtime_overrides: RwLock::new(DrRuntimeOverridePatch::default()),
        }
    }

    pub async fn snapshot(&self) -> DrStatus {
        self.status.read().await.clone()
    }

    pub async fn apply_runtime_overrides(&self, patch: DrRuntimeOverridePatch) {
        let mut ov = self.runtime_overrides.write().await;
        if let Some(v) = patch.enabled {
            ov.enabled = Some(v);
        }
        if let Some(v) = patch.verify_interval_secs {
            ov.verify_interval_secs = Some(v.clamp(60, 86_400));
        }
        if let Some(v) = patch.restore_drill_enabled {
            ov.restore_drill_enabled = Some(v);
        }
        if let Some(v) = patch.restore_drill_interval_secs {
            ov.restore_drill_interval_secs = Some(v.clamp(300, 2_592_000));
        }
    }

    pub async fn effective_config(&self) -> DrEffectiveConfig {
        let cfg = self.current_cfg().await;
        DrEffectiveConfig {
            enabled: cfg.enabled,
            verify_interval_secs: cfg.verify_interval_secs,
            backup_dir: cfg.backup_dir.display().to_string(),
            backup_max_age_secs: cfg.backup_max_age_secs,
            backup_verify_cmd: cfg.backup_verify_cmd,
            restore_drill_enabled: cfg.restore_drill_enabled,
            restore_drill_interval_secs: cfg.restore_drill_interval_secs,
            restore_drill_cmd: cfg.restore_drill_cmd,
            cmd_timeout_secs: cfg.cmd_timeout_secs,
        }
    }

    async fn current_cfg(&self) -> DrConfig {
        let ov = self.runtime_overrides.read().await.clone();
        let mut cfg = self.cfg.clone();
        if let Some(v) = ov.enabled {
            cfg.enabled = v;
        }
        if let Some(v) = ov.verify_interval_secs {
            cfg.verify_interval_secs = v.clamp(60, 86_400);
        }
        if let Some(v) = ov.restore_drill_enabled {
            cfg.restore_drill_enabled = v;
        }
        if let Some(v) = ov.restore_drill_interval_secs {
            cfg.restore_drill_interval_secs = v.clamp(300, 2_592_000);
        }
        cfg
    }

    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        percepta_server::spawn_monitored("dr-automation", async move {
            let mut last_restore_drill_run = 0i64;
            loop {
                let cfg = self.current_cfg().await;
                let now = Utc::now().timestamp();

                if !cfg.enabled {
                    {
                        let mut st = self.status.write().await;
                        st.enabled = false;
                        st.next_backup_verify_unix = None;
                        st.next_restore_drill_unix = None;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    continue;
                }

                {
                    let mut st = self.status.write().await;
                    st.enabled = true;
                }

                let (backup_ok, backup_detail) = self.verify_backup(&cfg).await;
                {
                    let mut st = self.status.write().await;
                    st.last_backup_verify_unix = Some(now);
                    st.backup_verify_ok = backup_ok;
                    st.backup_verify_detail = backup_detail;
                    st.next_backup_verify_unix =
                        Some(now.saturating_add(cfg.verify_interval_secs as i64));
                }

                if cfg.restore_drill_enabled {
                    let due = last_restore_drill_run == 0
                        || now.saturating_sub(last_restore_drill_run)
                            >= cfg.restore_drill_interval_secs as i64;
                    if due {
                        let (ok, detail) = self.run_restore_drill(&cfg).await;
                        last_restore_drill_run = now;
                        let mut st = self.status.write().await;
                        st.last_restore_drill_unix = Some(now);
                        st.restore_drill_ok = ok;
                        st.restore_drill_detail = detail;
                        st.next_restore_drill_unix =
                            Some(now.saturating_add(cfg.restore_drill_interval_secs as i64));
                    }
                } else {
                    let mut st = self.status.write().await;
                    st.next_restore_drill_unix = None;
                }

                tokio::time::sleep(std::time::Duration::from_secs(cfg.verify_interval_secs)).await;
            }
        })
    }

    async fn verify_backup(&self, cfg: &DrConfig) -> (bool, String) {
        if let Some(cmd) = cfg.backup_verify_cmd.as_ref() {
            return Self::run_command(cmd, cfg.cmd_timeout_secs).await;
        }

        let dir = cfg.backup_dir.clone();
        let mut rd = match tokio::fs::read_dir(&dir).await {
            Ok(v) => v,
            Err(e) => {
                return (
                    false,
                    format!("backup dir not readable: {} ({})", dir.display(), e),
                );
            }
        };

        let mut latest_mtime: Option<std::time::SystemTime> = None;
        let mut latest_name = String::new();

        loop {
            match rd.next_entry().await {
                Ok(Some(ent)) => {
                    let path = ent.path();
                    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                        continue;
                    };
                    if !(name.ends_with(".sql")
                        || name.ends_with(".sql.gz")
                        || name.ends_with(".dump"))
                    {
                        continue;
                    }
                    let meta = match ent.metadata().await {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let mtime = match meta.modified() {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let newer = latest_mtime.map(|cur| mtime > cur).unwrap_or(true);
                    if newer {
                        latest_mtime = Some(mtime);
                        latest_name = name.to_string();
                    }
                }
                Ok(None) => break,
                Err(e) => return (false, format!("failed reading backup dir entries: {}", e)),
            }
        }

        let Some(mtime) = latest_mtime else {
            return (false, format!("no backup files found in {}", dir.display()));
        };

        let age_secs = match std::time::SystemTime::now().duration_since(mtime) {
            Ok(d) => d.as_secs(),
            Err(_) => 0,
        };

        if age_secs > cfg.backup_max_age_secs {
            (
                false,
                format!(
                    "latest backup {} is stale: age={}s max={}s",
                    latest_name, age_secs, cfg.backup_max_age_secs
                ),
            )
        } else {
            (
                true,
                format!("latest backup {} age={}s (ok)", latest_name, age_secs),
            )
        }
    }

    async fn run_restore_drill(&self, cfg: &DrConfig) -> (bool, String) {
        match cfg.restore_drill_cmd.as_ref() {
            Some(cmd) => Self::run_command(cmd, cfg.cmd_timeout_secs).await,
            None => (
                false,
                "restore drill enabled but PERCEPTA_DR_RESTORE_DRILL_CMD is not set".to_string(),
            ),
        }
    }

    async fn run_command(cmd: &str, timeout_secs: u64) -> (bool, String) {
        let child = match Command::new("sh")
            .arg("-lc")
            .arg(cmd)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => return (false, format!("spawn failed: {}", e)),
        };

        let timeout = std::time::Duration::from_secs(timeout_secs);
        let out = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return (false, format!("command failed: {}", e)),
            Err(_) => return (false, format!("command timeout after {}s", timeout_secs)),
        };

        let mut detail = String::new();
        if !out.stdout.is_empty() {
            detail.push_str(&String::from_utf8_lossy(&out.stdout));
        }
        if !out.stderr.is_empty() {
            if !detail.is_empty() {
                detail.push_str(" | ");
            }
            detail.push_str(&String::from_utf8_lossy(&out.stderr));
        }
        detail = detail.trim().chars().take(400).collect::<String>();
        if detail.is_empty() {
            detail = "ok".to_string();
        }

        (out.status.success(), detail)
    }
}

pub async fn api_status(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> Result<Json<DrStatus>, StatusCode> {
    if user.role != Role::Authority && user.role != Role::Analyst {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(state.dr.snapshot().await))
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes"))
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.clamp(min, max))
        .unwrap_or(default)
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|v| {
        let t = v.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}
