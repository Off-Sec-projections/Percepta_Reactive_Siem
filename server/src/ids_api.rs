use axum::{extract::{Query, State}, http::header, response::IntoResponse, Json};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;

use crate::enroll::{AppError, AppState};
use crate::ids_suppression::IdsSuppressionEntry;
use anyhow::Context;
use percepta_server::percepta::event::{EventCategory, EventDetails, EventOutcome, Network};
use percepta_server::percepta::Event;

static SURICATA_FIELD_MAP: Lazy<std::collections::HashMap<String, Vec<String>>> =
    Lazy::new(load_suricata_field_map);

fn load_suricata_field_map() -> std::collections::HashMap<String, Vec<String>> {
    let mut defaults: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    defaults.insert("timestamp".into(), vec!["timestamp".into()]);
    defaults.insert("event_type".into(), vec!["event_type".into()]);
    defaults.insert("src_ip".into(), vec!["src_ip".into()]);
    defaults.insert("dst_ip".into(), vec!["dest_ip".into(), "dst_ip".into()]);
    defaults.insert("src_port".into(), vec!["src_port".into()]);
    defaults.insert("dst_port".into(), vec!["dest_port".into(), "dst_port".into()]);
    defaults.insert("proto".into(), vec!["proto".into(), "app_proto".into()]);
    defaults.insert("flow_id".into(), vec!["flow_id".into()]);
    defaults.insert("signature".into(), vec!["alert.signature".into()]);
    defaults.insert("signature_id".into(), vec!["alert.signature_id".into()]);
    defaults.insert("severity".into(), vec!["alert.severity".into()]);

    let Ok(raw) = std::env::var("PERCEPTA_SURICATA_FIELD_MAP_JSON") else {
        return defaults;
    };
    let Ok(overrides) = serde_json::from_str::<serde_json::Value>(&raw) else {
        tracing::warn!("Invalid PERCEPTA_SURICATA_FIELD_MAP_JSON, using defaults");
        return defaults;
    };

    let Some(obj) = overrides.as_object() else {
        tracing::warn!("PERCEPTA_SURICATA_FIELD_MAP_JSON must be a JSON object, using defaults");
        return defaults;
    };

    for (k, v) in obj {
        let paths = if let Some(s) = v.as_str() {
            vec![s.trim().to_string()]
        } else if let Some(arr) = v.as_array() {
            arr.iter()
                .filter_map(|x| x.as_str())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        } else {
            Vec::new()
        };
        if !paths.is_empty() {
            defaults.insert(k.to_string(), paths);
        }
    }

    defaults
}

fn value_at_path<'a>(payload: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = payload;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

fn mapped_str(payload: &serde_json::Value, key: &str) -> String {
    let Some(paths) = SURICATA_FIELD_MAP.get(key) else {
        return String::new();
    };
    for path in paths {
        if let Some(v) = value_at_path(payload, path).and_then(|x| x.as_str()) {
            return v.to_string();
        }
    }
    String::new()
}

fn mapped_u64(payload: &serde_json::Value, key: &str) -> Option<u64> {
    let paths = SURICATA_FIELD_MAP.get(key)?;
    for path in paths {
        if let Some(v) = value_at_path(payload, path) {
            if let Some(u) = v.as_u64() {
                return Some(u);
            }
            if let Some(s) = v.as_str().and_then(|x| x.parse::<u64>().ok()) {
                return Some(s);
            }
        }
    }
    None
}

// ── Config file management ──────────────────────────────────────────────

/// Allowed config files (relative to CARGO_MANIFEST_DIR).  Strict whitelist
/// prevents path-traversal attacks — only these exact relative paths are
/// permitted for read/write operations.
const CONFIG_FILES: &[(&str, &str)] = &[
    ("rules.yaml", "Detection Rules"),
    ("parsers.yaml", "Parser Definitions"),
    ("config/apis.toml", "API Integrations"),
    ("config/apis.example.toml", "API Template (read-only)"),
];

const WRITABLE_CONFIG_FILES: &[&str] = &["rules.yaml", "parsers.yaml", "config/apis.toml"];

fn config_base_dir() -> PathBuf {
    percepta_server::base_dir()
}

#[derive(Debug, Serialize)]
pub struct ConfigFileInfo {
    pub name: String,
    pub label: String,
    pub size_bytes: u64,
    pub writable: bool,
}

pub async fn list_config_files(
    State(_state): State<AppState>,
) -> Result<Json<Vec<ConfigFileInfo>>, AppError> {
    let base = config_base_dir();
    let mut out = Vec::new();
    for &(name, label) in CONFIG_FILES {
        let path = base.join(name);
        let size = fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
        out.push(ConfigFileInfo {
            name: name.to_string(),
            label: label.to_string(),
            size_bytes: size,
            writable: WRITABLE_CONFIG_FILES.contains(&name),
        });
    }
    Ok(Json(out))
}

#[derive(Debug, Deserialize)]
pub struct ConfigFileQuery {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct ConfigFileContent {
    pub name: String,
    pub content: String,
    pub size_bytes: usize,
}

pub async fn get_config_file(
    State(_state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ConfigFileQuery>,
) -> Result<Json<ConfigFileContent>, AppError> {
    let name = q.name.trim().to_string();
    if !CONFIG_FILES.iter().any(|&(n, _)| n == name) {
        return Err(AppError::bad_request(
            "invalid_file",
            "file not in whitelist",
            anyhow::anyhow!("rejected: {}", name),
        ));
    }
    let path = config_base_dir().join(&name);
    let content = fs::read_to_string(&path).await.unwrap_or_default();
    Ok(Json(ConfigFileContent {
        size_bytes: content.len(),
        name,
        content,
    }))
}

#[derive(Debug, Deserialize)]
pub struct ConfigFileSave {
    pub name: String,
    pub content: String,
}

pub async fn save_config_file(
    State(_state): State<AppState>,
    Json(payload): Json<ConfigFileSave>,
) -> Result<Json<serde_json::Value>, AppError> {
    let name = payload.name.trim().to_string();
    if !WRITABLE_CONFIG_FILES.contains(&name.as_str()) {
        return Err(AppError::bad_request(
            "invalid_file",
            "file not writable or not in whitelist",
            anyhow::anyhow!("rejected write: {}", name),
        ));
    }
    let base = config_base_dir();
    let path = base.join(&name);

    // Create timestamped backup before overwriting.
    if path.exists() {
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let bak_dir = base.join("config").join("backups");
        if let Err(e) = fs::create_dir_all(&bak_dir).await {
            tracing::warn!(
                "IDS backup: failed to create dir {}: {e:#}",
                bak_dir.display()
            );
        }
        let safe_name = name.replace('/', "_");
        let bak_path = bak_dir.join(format!("{}.{}", safe_name, ts));
        if let Err(e) = fs::copy(&path, &bak_path).await {
            tracing::warn!(
                "IDS backup: failed to copy {} → {}: {e:#}",
                path.display(),
                bak_path.display()
            );
        }
    }

    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent).await {
            tracing::warn!(
                "IDS: failed to create parent dir {}: {e:#}",
                parent.display()
            );
        }
    }
    fs::write(&path, payload.content.as_bytes()).await?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "name": name,
        "size_bytes": payload.content.len()
    })))
}

fn ids_root() -> PathBuf {
    if let Ok(dir) = std::env::var("PERCEPTA_IDS_DIR") {
        let p = PathBuf::from(dir);
        if p.is_absolute() {
            return p;
        }
    }
    if let Ok(base) = std::env::var("PERCEPTA_BASE_DIR") {
        let p = PathBuf::from(base);
        if p.is_absolute() {
            return p.join("ids");
        }
    }
    let server_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    server_dir.parent().unwrap_or(&server_dir).join("ids")
}

fn valid_sensor_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
}

fn normalize_sensor_id(raw: Option<&str>) -> String {
    let candidate = raw.unwrap_or("default").trim().to_lowercase();
    if valid_sensor_id(&candidate) {
        candidate
    } else {
        "default".to_string()
    }
}

fn configured_sensor_ids() -> Vec<String> {
    let mut sensors = vec!["default".to_string()];
    if let Ok(raw) = std::env::var("PERCEPTA_IDS_SENSORS") {
        for id in raw
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| valid_sensor_id(s))
        {
            if !sensors.iter().any(|existing| existing == &id) {
                sensors.push(id);
            }
        }
    }
    sensors
}

fn suricata_sensor_dir(sensor_id: &str) -> PathBuf {
    if sensor_id == "default" {
        ids_root().join("suricata").join("rules")
    } else {
        ids_root()
            .join("suricata")
            .join("sensors")
            .join(sensor_id)
            .join("rules")
    }
}

fn suricata_rules_path(sensor_id: &str) -> PathBuf {
    suricata_sensor_dir(sensor_id).join("percepta.rules")
}

fn suricata_versions_dir(sensor_id: &str) -> PathBuf {
    suricata_sensor_dir(sensor_id).join("versions")
}

async fn ensure_rules_file(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    if !path.exists() {
        fs::write(path, "# Percepta managed Suricata rules\n").await?;
    }
    Ok(())
}

async fn write_rules_with_versioning(
    path: &Path,
    content: &str,
    sensor_id: &str,
) -> std::io::Result<()> {
    ensure_rules_file(path).await?;
    let version_dir = suricata_versions_dir(sensor_id);
    fs::create_dir_all(&version_dir).await?;
    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let version_path = version_dir.join(format!("percepta.rules.{}", ts));
    fs::write(&version_path, content.as_bytes()).await?;

    // Keep only the last 20 versions.
    let mut files: Vec<PathBuf> = Vec::new();
    let mut rd = fs::read_dir(&version_dir).await?;
    while let Some(e) = rd.next_entry().await? {
        let p = e.path();
        if p.is_file() {
            files.push(p);
        }
    }
    files.sort();
    if files.len() > 20 {
        let remove_count = files.len() - 20;
        for p in files.into_iter().take(remove_count) {
            if let Err(e) = fs::remove_file(&p).await {
                tracing::warn!(
                    "IDS version cleanup: could not remove {}: {e:#}",
                    p.display()
                );
            }
        }
    }

    fs::write(path, content.as_bytes()).await?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct RulesUpdate {
    pub rules: String,
}

#[derive(Debug, Serialize)]
pub struct RulesResponse {
    pub sensor_id: String,
    pub rules: String,
    pub updated_at_unix: i64,
    pub path: String,
    pub size_bytes: usize,
    #[serde(default)]
    pub validation_ok: bool,
    #[serde(default)]
    pub validation_message: String,
    #[serde(default)]
    pub reload_ok: bool,
    #[serde(default)]
    pub reload_message: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct SensorQuery {
    #[serde(default)]
    pub sensor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IdsSensorInfo {
    pub id: String,
    pub engine: String,
    pub rules_path: String,
    pub versions_path: String,
    pub configured: bool,
    pub rules_exists: bool,
}

pub async fn list_ids_sensors(
    State(_state): State<AppState>,
) -> Result<Json<Vec<IdsSensorInfo>>, AppError> {
    let configured = configured_sensor_ids();
    let mut out = Vec::new();
    for id in configured {
        let rules_path = suricata_rules_path(&id);
        let versions_path = suricata_versions_dir(&id);
        let rules_exists = fs::metadata(&rules_path).await.is_ok();
        out.push(IdsSensorInfo {
            id,
            engine: "suricata".to_string(),
            rules_path: rules_path.display().to_string(),
            versions_path: versions_path.display().to_string(),
            configured: true,
            rules_exists,
        });
    }
    Ok(Json(out))
}

async fn validate_suricata_rules_content(content: &str) -> (bool, String) {
    let version_dir = suricata_versions_dir("default");
    if let Err(e) = fs::create_dir_all(&version_dir).await {
        return (
            false,
            format!("failed to prepare validation directory: {e}"),
        );
    }

    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let candidate = version_dir.join(format!(".validate.percepta.rules.{ts}"));
    if let Err(e) = fs::write(&candidate, content.as_bytes()).await {
        return (
            false,
            format!("failed to write validation candidate file: {e}"),
        );
    }

    let candidate_str = candidate.display().to_string();
    let custom_cmd = std::env::var("PERCEPTA_SURICATA_VALIDATE_CMD").ok();
    let default_cfg = std::env::var("PERCEPTA_SURICATA_CONFIG")
        .unwrap_or_else(|_| "/etc/suricata/suricata.yaml".to_string());

    let validation_cmd = if let Some(cmd) = custom_cmd.as_deref() {
        if cmd.trim().is_empty() {
            None
        } else {
            Some(cmd.replace("{rules_path}", &candidate_str))
        }
    } else if Path::new(&default_cfg).exists() {
        Some(format!(
            "suricata -T -c '{}' -S '{}'",
            default_cfg.replace('"', "\\\""),
            candidate_str.replace('"', "\\\"")
        ))
    } else {
        None
    };

    let Some(cmd) = validation_cmd else {
        let _ = fs::remove_file(&candidate).await;
        return (
            true,
            "Suricata syntax validation skipped (no validation command/config found)"
                .to_string(),
        );
    };

    let output = Command::new("sh").arg("-lc").arg(&cmd).output().await;
    let _ = fs::remove_file(&candidate).await;

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if stdout.is_empty() {
                (true, format!("Suricata rule validation passed: {cmd}"))
            } else {
                (
                    true,
                    format!("Suricata rule validation passed: {stdout}"),
                )
            }
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            (
                false,
                format!(
                    "Suricata rule validation failed (status={}): {}",
                    out.status,
                    if stderr.is_empty() {
                        "no stderr output".to_string()
                    } else {
                        stderr
                    }
                ),
            )
        }
        Err(e) => (
            false,
            format!("Failed to execute Suricata validation command '{}': {}", cmd, e),
        ),
    }
}

async fn try_reload_suricata() -> (bool, String) {
    let commands: Vec<String> = match std::env::var("PERCEPTA_SURICATA_RELOAD_CMD") {
        Ok(cmd) if !cmd.trim().is_empty() => vec![cmd],
        _ => vec![
            "suricatasc -c reload-rules".to_string(),
            "systemctl reload suricata".to_string(),
            "systemctl kill -s USR2 suricata".to_string(),
            "pkill -USR2 suricata".to_string(),
        ],
    };

    let mut failures = Vec::new();
    for cmd in commands {
        match Command::new("sh").arg("-lc").arg(&cmd).output().await {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let msg = if stdout.is_empty() {
                    format!("Suricata reload command succeeded: {}", cmd)
                } else {
                    format!("Suricata reload command succeeded: {}", stdout)
                };
                return (true, msg);
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                failures.push(format!(
                    "{} => status={} stderr={}",
                    cmd,
                    out.status,
                    if stderr.is_empty() {
                        "<none>".to_string()
                    } else {
                        stderr
                    }
                ));
            }
            Err(e) => failures.push(format!("{} => exec error: {}", cmd, e)),
        }
    }

    (
        false,
        format!(
            "All Suricata reload strategies failed: {}",
            failures.join(" | ")
        ),
    )
}

pub async fn get_suricata_rules(
    State(_state): State<AppState>,
    Query(q): Query<SensorQuery>,
) -> Result<Json<RulesResponse>, AppError> {
    let sensor_id = normalize_sensor_id(q.sensor.as_deref());
    let path = suricata_rules_path(&sensor_id);
    ensure_rules_file(&path).await?;
    let rules = fs::read_to_string(&path).await.unwrap_or_default();
    let updated_at_unix = chrono::Utc::now().timestamp();
    Ok(Json(RulesResponse {
        sensor_id,
        size_bytes: rules.len(),
        rules,
        updated_at_unix,
        path: path.display().to_string(),
        validation_ok: false,
        validation_message: String::new(),
        reload_ok: false,
        reload_message: String::new(),
    }))
}

pub async fn update_suricata_rules(
    State(_state): State<AppState>,
    Query(q): Query<SensorQuery>,
    Json(payload): Json<RulesUpdate>,
) -> Result<Json<RulesResponse>, AppError> {
    let sensor_id = normalize_sensor_id(q.sensor.as_deref());
    let path = suricata_rules_path(&sensor_id);
    let (validation_ok, validation_message) = validate_suricata_rules_content(&payload.rules).await;
    if !validation_ok {
        return Err(AppError::bad_request(
            "suricata_validation_failed",
            "suricata rule syntax validation failed",
            anyhow::anyhow!(validation_message),
        ));
    }
    write_rules_with_versioning(&path, &payload.rules, &sensor_id).await?;
    let (reload_ok, reload_message) = try_reload_suricata().await;
    let updated_at_unix = chrono::Utc::now().timestamp();
    Ok(Json(RulesResponse {
        sensor_id,
        size_bytes: payload.rules.len(),
        rules: payload.rules,
        updated_at_unix,
        path: path.display().to_string(),
        validation_ok,
        validation_message,
        reload_ok,
        reload_message,
    }))
}

pub async fn get_suricata_rules_raw(
    State(_state): State<AppState>,
    Query(q): Query<SensorQuery>,
) -> Result<impl IntoResponse, AppError> {
    let sensor_id = normalize_sensor_id(q.sensor.as_deref());
    let path = suricata_rules_path(&sensor_id);
    ensure_rules_file(&path).await?;
    let rules = fs::read_to_string(&path).await.unwrap_or_default();
    Ok(([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], rules))
}

#[derive(Debug, Serialize)]
pub struct RuleVersion {
    pub id: String,
    pub filename: String,
}

pub async fn list_suricata_rule_versions(
    State(_state): State<AppState>,
    Query(q): Query<SensorQuery>,
) -> Result<Json<Vec<RuleVersion>>, AppError> {
    let sensor_id = normalize_sensor_id(q.sensor.as_deref());
    let dir = suricata_versions_dir(&sensor_id);
    let mut out = Vec::new();
    let mut rd = match fs::read_dir(&dir).await {
        Ok(v) => v,
        Err(_) => return Ok(Json(out)),
    };

    while let Some(e) = rd.next_entry().await? {
        let p = e.path();
        if let Some(fname) = p.file_name().and_then(|f| f.to_str()) {
            if fname.starts_with("percepta.rules.") {
                let id = fname.trim_start_matches("percepta.rules.").to_string();
                out.push(RuleVersion {
                    id,
                    filename: fname.to_string(),
                });
            }
        }
    }
    out.sort_by(|a, b| b.id.cmp(&a.id));
    Ok(Json(out))
}

#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    pub id: String,
}

pub async fn rollback_suricata_rules(
    State(_state): State<AppState>,
    Query(q): Query<SensorQuery>,
    Json(payload): Json<RollbackRequest>,
) -> Result<Json<RulesResponse>, AppError> {
    let id = payload.id.trim();
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AppError::bad_request(
            "invalid_version",
            "version id must be alphanumeric/dash/dot",
            anyhow::anyhow!("bad id"),
        ));
    }
    let sensor_id = normalize_sensor_id(q.sensor.as_deref());
    let path = suricata_rules_path(&sensor_id);
    let version_path = suricata_versions_dir(&sensor_id).join(format!("percepta.rules.{}", id));
    let rules = fs::read_to_string(&version_path)
        .await
        .context("failed to read version file")?;
    let (validation_ok, validation_message) = validate_suricata_rules_content(&rules).await;
    if !validation_ok {
        return Err(AppError::bad_request(
            "suricata_validation_failed",
            "suricata rule syntax validation failed",
            anyhow::anyhow!(validation_message),
        ));
    }
    write_rules_with_versioning(&path, &rules, &sensor_id).await?;
    let (reload_ok, reload_message) = try_reload_suricata().await;
    let updated_at_unix = chrono::Utc::now().timestamp();
    Ok(Json(RulesResponse {
        sensor_id,
        size_bytes: rules.len(),
        rules,
        updated_at_unix,
        path: path.display().to_string(),
        validation_ok,
        validation_message,
        reload_ok,
        reload_message,
    }))
}

#[derive(Debug, Serialize)]
pub struct EveIngestResponse {
    pub ok: bool,
    pub hash: String,
    pub alert_count: usize,
}

fn build_suricata_event(
    payload: &serde_json::Value,
    sensor_id: &str,
) -> Result<Event, anyhow::Error> {
    let now = chrono::Utc::now();
    let timestamp_raw = {
        let direct = payload
            .get("timestamp")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if direct.is_empty() {
            mapped_str(payload, "timestamp")
        } else {
            direct
        }
    };
    let event_time = chrono::DateTime::parse_from_rfc3339(&timestamp_raw)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or(now);

    let event_type = mapped_str(payload, "event_type");
    let src_ip = mapped_str(payload, "src_ip");
    let dst_ip = mapped_str(payload, "dst_ip");
    let src_port = mapped_u64(payload, "src_port").unwrap_or(0) as u32;
    let dst_port = mapped_u64(payload, "dst_port").unwrap_or(0) as u32;
    let proto = mapped_str(payload, "proto");

    let signature = {
        let s = mapped_str(payload, "signature");
        if s.is_empty() { "Suricata alert".to_string() } else { s }
    };
    let signature_id = mapped_u64(payload, "signature_id").unwrap_or(0);
    let severity = mapped_u64(payload, "severity").unwrap_or(2) as i32;

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("sensor.kind".to_string(), "suricata_eve".to_string());
    metadata.insert("ids.sensor_id".to_string(), sensor_id.to_string());
    metadata.insert("ids.engine".to_string(), "suricata".to_string());
    metadata.insert("ids.event_type".to_string(), event_type.to_string());
    metadata.insert("ids.signature".to_string(), signature.to_string());
    metadata.insert("ids.sid".to_string(), signature_id.to_string());
    metadata.insert("ids.severity".to_string(), severity.to_string());
    if !proto.is_empty() {
        metadata.insert("network.protocol".to_string(), proto.to_string());
    }

    if let Some(flow_id) = mapped_u64(payload, "flow_id") {
        metadata.insert("ids.flow_id".to_string(), flow_id.to_string());
    }

    let original_message = serde_json::to_string(payload)?;
    let hash_input = format!(
        "eve:{}:{}:{}:{}:{}:{}",
        event_type,
        signature_id,
        src_ip,
        dst_ip,
        src_port,
        dst_port
    );
    let hash = hex::encode(openssl::sha::sha256(hash_input.as_bytes()));

    let event = Event {
        event_time: Some(prost_types::Timestamp {
            seconds: event_time.timestamp(),
            nanos: event_time.timestamp_subsec_nanos() as i32,
        }),
        ingest_time: Some(prost_types::Timestamp {
            seconds: now.timestamp(),
            nanos: 0,
        }),
        event: Some(EventDetails {
            summary: format!("[Suricata] {}", signature),
            original_message,
            category: EventCategory::Other as i32,
            action: if event_type.is_empty() {
                "suricata_event".to_string()
            } else {
                event_type.to_string()
            },
            outcome: EventOutcome::OutcomeUnknown as i32,
            level: match severity {
                1 => "Critical".to_string(),
                2 => "High".to_string(),
                3 => "Medium".to_string(),
                4 => "Low".to_string(),
                _ => "Info".to_string(),
            },
            severity,
            provider: "suricata".to_string(),
            event_id: signature_id,
            record_id: payload.get("flow_id").and_then(|x| x.as_u64()).unwrap_or(0),
        }),
        hash,
        metadata,
        tags: vec!["suricata".to_string(), "eve_json".to_string(), "ids".to_string()],
        network: Some(Network {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: proto.to_string(),
            ..Default::default()
        }),
        ..Default::default()
    };

    Ok(event)
}

pub async fn ingest_suricata_eve(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<EveIngestResponse>, AppError> {
    let sensor_id = req
        .get("sensor_id")
        .and_then(|v| v.as_str())
        .or_else(|| req.get("sensor").and_then(|v| v.as_str()))
        .or_else(|| {
            req.get("payload")
                .and_then(|p| p.get("sensor_id"))
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            req.get("payload")
                .and_then(|p| p.get("sensor"))
                .and_then(|v| v.as_str())
        });
    let sensor_id = normalize_sensor_id(sensor_id);

    let payload = if let Some(p) = req.get("payload") {
        p.clone()
    } else {
        req
    };

    if !payload.is_object() {
        return Err(AppError::bad_request(
            "invalid_eve_payload",
            "suricata eve payload must be a JSON object",
            anyhow::anyhow!("non-object payload"),
        ));
    }

    let mut event =
        build_suricata_event(&payload, &sensor_id).context("invalid suricata eve payload")?;
    event.tags.push(format!("sensor:{}", sensor_id));

    crate::ingest_utils::apply_standard_pipeline(
        &mut event,
        Some("suricata-eve"),
        &state.decoder_engine,
        &state.windows_mappings,
        state.enrichment.as_deref(),
    )
    .await;

    crate::ingest_utils::validate_event(&event).context("failed to validate eve event")?;

    state.lan_topology.observe_event(&event).await;

    state
        .storage_service
        .store_event(&event)
        .await
        .context("failed to persist eve event")?;

    let _ = state
        .event_broadcaster
        .send(crate::websocket::StreamMessage::Event(event.clone()));

    let alerts = state
        .rule_engine
        .evaluate_event(&event)
        .await
        .context("failed to evaluate eve event rules")?;

    Ok(Json(EveIngestResponse {
        ok: true,
        hash: event.hash,
        alert_count: alerts.len(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct SuppressRequest {
    pub key: String,
    #[serde(default)]
    pub seconds: Option<i64>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SuppressRemoveRequest {
    pub key: String,
}

pub async fn list_ids_suppressions(
    State(state): State<AppState>,
) -> Result<Json<Vec<IdsSuppressionEntry>>, AppError> {
    Ok(Json(state.ids_suppressions.list().await))
}

pub async fn add_ids_suppression(
    State(state): State<AppState>,
    Json(payload): Json<SuppressRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let key = payload.key.trim().to_string();
    if key.is_empty() {
        return Err(AppError::bad_request(
            "invalid_key",
            "key required",
            anyhow::anyhow!("missing"),
        ));
    }
    let seconds = payload
        .seconds
        .unwrap_or(24 * 3600)
        .clamp(60, 30 * 24 * 3600);
    let reason = payload
        .reason
        .unwrap_or_else(|| "ids suppression".to_string());
    state.ids_suppressions.add(&key, seconds, &reason).await?;
    Ok(Json(
        serde_json::json!({"ok": true, "key": key, "seconds": seconds}),
    ))
}

pub async fn remove_ids_suppression(
    State(state): State<AppState>,
    Json(payload): Json<SuppressRemoveRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let key = payload.key.trim();
    if key.is_empty() {
        return Err(AppError::bad_request(
            "invalid_key",
            "key required",
            anyhow::anyhow!("missing"),
        ));
    }
    state.ids_suppressions.remove(key).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
