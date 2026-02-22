//! Data Loss Prevention (DLP) — Pattern Library & Detection.
//!
//! 20+ sensitive data patterns: PII, PHI, PCI, secrets, API keys.
//! Custom DLP pattern API. Auto-masking in logs. Violation trends.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;

// ── DLP Pattern ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPattern {
    pub id: String,
    pub name: String,
    pub category: DlpCategory,
    pub regex_pattern: String,
    pub description: String,
    pub severity: String,
    pub enabled: bool,
    pub is_builtin: bool,
    #[serde(skip)]
    #[allow(dead_code)]
    compiled: Option<Regex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpCategory {
    Pii,
    Phi,
    Pci,
    Credentials,
    ApiKeys,
    Secrets,
    Financial,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpViolation {
    pub pattern_id: String,
    pub pattern_name: String,
    pub category: DlpCategory,
    pub severity: String,
    pub event_hash: String,
    pub field: String,
    pub masked_value: String,
    pub detected_at: DateTime<Utc>,
    pub agent_id: String,
}

// ── DLP Engine ───────────────────────────────────────────────────────────

pub type DlpEngineHandle = Arc<RwLock<DlpEngine>>;

pub struct DlpEngine {
    patterns: Vec<DlpPattern>,
    violations: VecDeque<DlpViolation>,
    compiled_patterns: Vec<(String, Regex)>,
    max_violations: usize,
}

impl DlpEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            patterns: Vec::new(),
            violations: VecDeque::new(),
            compiled_patterns: Vec::new(),
            max_violations: 10_000,
        };
        engine.seed_builtin_patterns();
        engine.compile_patterns();
        engine
    }

    fn seed_builtin_patterns(&mut self) {
        let builtins = vec![
            // PII patterns
            (
                "dlp_ssn",
                "US Social Security Number",
                DlpCategory::Pii,
                r"\b\d{3}-\d{2}-\d{4}\b",
                "high",
            ),
            (
                "dlp_email_address",
                "Email Address",
                DlpCategory::Pii,
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                "medium",
            ),
            (
                "dlp_phone_us",
                "US Phone Number",
                DlpCategory::Pii,
                r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                "medium",
            ),
            (
                "dlp_drivers_license",
                "Drivers License Pattern",
                DlpCategory::Pii,
                r"\b[A-Z]\d{7,14}\b",
                "medium",
            ),
            // PCI patterns
            (
                "dlp_credit_card_visa",
                "Visa Card Number",
                DlpCategory::Pci,
                r"\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
                "critical",
            ),
            (
                "dlp_credit_card_mc",
                "MasterCard Number",
                DlpCategory::Pci,
                r"\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
                "critical",
            ),
            (
                "dlp_credit_card_amex",
                "American Express Number",
                DlpCategory::Pci,
                r"\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b",
                "critical",
            ),
            (
                "dlp_cvv",
                "Card Verification Value",
                DlpCategory::Pci,
                r"\bCVV[:\s]*\d{3,4}\b",
                "critical",
            ),
            // PHI patterns
            (
                "dlp_medical_record",
                "Medical Record Number",
                DlpCategory::Phi,
                r"\bMRN[:\s#]*\d{6,10}\b",
                "high",
            ),
            (
                "dlp_icd10",
                "ICD-10 Code",
                DlpCategory::Phi,
                r"\b[A-Z]\d{2}\.\d{1,4}\b",
                "medium",
            ),
            (
                "dlp_npi",
                "National Provider Identifier",
                DlpCategory::Phi,
                r"\bNPI[:\s#]*\d{10}\b",
                "high",
            ),
            // Credential patterns
            (
                "dlp_password_field",
                "Password in Cleartext",
                DlpCategory::Credentials,
                r"(?i)(?:password|passwd|pwd)\s*[=:]\s*\S+",
                "critical",
            ),
            (
                "dlp_bearer_token",
                "Bearer Token",
                DlpCategory::Credentials,
                r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*",
                "critical",
            ),
            (
                "dlp_basic_auth",
                "Basic Auth Header",
                DlpCategory::Credentials,
                r"(?i)basic\s+[a-zA-Z0-9+/]+=*",
                "high",
            ),
            (
                "dlp_private_key",
                "Private Key Block",
                DlpCategory::Credentials,
                r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
                "critical",
            ),
            (
                "dlp_ssh_private",
                "SSH Private Key",
                DlpCategory::Credentials,
                r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
                "critical",
            ),
            // API Key patterns
            (
                "dlp_aws_key",
                "AWS Access Key ID",
                DlpCategory::ApiKeys,
                r"\bAKIA[0-9A-Z]{16}\b",
                "critical",
            ),
            (
                "dlp_aws_secret",
                "AWS Secret Key",
                DlpCategory::ApiKeys,
                r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
                "critical",
            ),
            (
                "dlp_github_token",
                "GitHub Token",
                DlpCategory::ApiKeys,
                r"\bgh[ps]_[A-Za-z0-9_]{36,}\b",
                "critical",
            ),
            (
                "dlp_slack_token",
                "Slack Token",
                DlpCategory::ApiKeys,
                r"\bxox[baprs]-[0-9A-Za-z\-]{10,}",
                "critical",
            ),
            (
                "dlp_generic_api_key",
                "Generic API Key Assignment",
                DlpCategory::ApiKeys,
                r#"(?i)(?:api[_-]?key|apikey)\s*[=:]\s*['"]?[A-Za-z0-9\-._]{20,}['"]?"#,
                "high",
            ),
            // Secret patterns
            (
                "dlp_jwt_token",
                "JWT Token",
                DlpCategory::Secrets,
                r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b",
                "high",
            ),
            (
                "dlp_connection_string",
                "Database Connection String",
                DlpCategory::Secrets,
                r"(?i)(?:postgres|mysql|mongodb|redis)://[^\s]+",
                "critical",
            ),
            // Financial
            (
                "dlp_iban",
                "IBAN Number",
                DlpCategory::Financial,
                r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?\d{0,16})?\b",
                "high",
            ),
            (
                "dlp_swift",
                "SWIFT/BIC Code",
                DlpCategory::Financial,
                r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
                "medium",
            ),
        ];

        for (id, name, category, pattern, severity) in builtins {
            self.patterns.push(DlpPattern {
                id: id.into(),
                name: name.into(),
                category,
                regex_pattern: pattern.into(),
                description: format!("Built-in DLP pattern: {}", name),
                severity: severity.into(),
                enabled: true,
                is_builtin: true,
                compiled: None,
            });
        }
    }

    fn compile_patterns(&mut self) {
        self.compiled_patterns.clear();
        for p in &self.patterns {
            if !p.enabled {
                continue;
            }
            match Regex::new(&p.regex_pattern) {
                Ok(r) => self.compiled_patterns.push((p.id.clone(), r)),
                Err(e) => tracing::warn!("DLP: Failed to compile pattern '{}': {}", p.id, e),
            }
        }
    }

    /// Scan a text value for DLP violations.
    pub fn scan_text(
        &mut self,
        text: &str,
        field: &str,
        event_hash: &str,
        agent_id: &str,
    ) -> Vec<DlpViolation> {
        let mut found = Vec::new();
        for (pattern_id, regex) in &self.compiled_patterns {
            if let Some(m) = regex.find(text) {
                let pattern = self.patterns.iter().find(|p| &p.id == pattern_id);
                if let Some(p) = pattern {
                    let masked = mask_value(m.as_str());
                    let violation = DlpViolation {
                        pattern_id: p.id.clone(),
                        pattern_name: p.name.clone(),
                        category: p.category.clone(),
                        severity: p.severity.clone(),
                        event_hash: event_hash.into(),
                        field: field.into(),
                        masked_value: masked,
                        detected_at: Utc::now(),
                        agent_id: agent_id.into(),
                    };
                    found.push(violation.clone());
                }
            }
        }
        // Store violations
        for v in &found {
            self.violations.push_back(v.clone());
            if self.violations.len() > self.max_violations {
                self.violations.pop_front();
            }
        }
        found
    }

    /// Scan event metadata for DLP violations.
    pub fn scan_event_metadata(
        &mut self,
        metadata: &HashMap<String, String>,
        event_hash: &str,
        agent_id: &str,
    ) -> Vec<DlpViolation> {
        let mut all = Vec::new();
        for (field, value) in metadata {
            let violations = self.scan_text(value, field, event_hash, agent_id);
            all.extend(violations);
        }
        all
    }

    pub fn add_pattern(&mut self, pattern: DlpPattern) -> Result<(), String> {
        // Validate regex
        Regex::new(&pattern.regex_pattern).map_err(|e| format!("Invalid regex: {}", e))?;
        self.patterns.push(pattern);
        self.compile_patterns();
        Ok(())
    }

    pub fn remove_pattern(&mut self, id: &str) -> Result<(), String> {
        if let Some(p) = self.patterns.iter().find(|p| p.id == id) {
            if p.is_builtin {
                return Err("Cannot remove built-in patterns".into());
            }
        }
        self.patterns.retain(|p| p.id != id);
        self.compile_patterns();
        Ok(())
    }

    pub fn list_patterns(&self) -> &[DlpPattern] {
        &self.patterns
    }

    pub fn list_violations(&self, limit: usize) -> Vec<&DlpViolation> {
        let start = self.violations.len().saturating_sub(limit);
        self.violations.iter().skip(start).collect()
    }

    pub fn stats(&self) -> serde_json::Value {
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut by_severity: HashMap<String, usize> = HashMap::new();
        for v in &self.violations {
            *by_category.entry(format!("{:?}", v.category)).or_insert(0) += 1;
            *by_severity.entry(v.severity.clone()).or_insert(0) += 1;
        }
        serde_json::json!({
            "total_patterns": self.patterns.len(),
            "enabled_patterns": self.patterns.iter().filter(|p| p.enabled).count(),
            "total_violations": self.violations.len(),
            "by_category": by_category,
            "by_severity": by_severity,
        })
    }
}

/// Mask a detected sensitive value for display.
fn mask_value(value: &str) -> String {
    let len = value.len();
    if len <= 4 {
        "*".repeat(len)
    } else {
        let show = std::cmp::min(4, len / 4);
        format!("{}{}", &value[..show], "*".repeat(len - show),)
    }
}

pub fn init_dlp_engine() -> DlpEngineHandle {
    Arc::new(RwLock::new(DlpEngine::new()))
}

// ── ClickHouse Persistence ───────────────────────────────────────────────

/// Persist a custom DLP pattern to ClickHouse.
pub async fn persist_dlp_pattern(db: &crate::db::Db, pattern: &DlpPattern) {
    #[derive(clickhouse::Row, serde::Serialize)]
    struct Row {
        id: String,
        name: String,
        pattern_type: String,
        pattern: String,
        severity: String,
        enabled: u8,
        created_at: i64,
        updated_at: i64,
    }
    let row = Row {
        id: pattern.id.clone(),
        name: pattern.name.clone(),
        pattern_type: serde_json::to_string(&pattern.category)
            .unwrap_or_else(|_| "\"custom\"".into()),
        pattern: pattern.regex_pattern.clone(),
        severity: pattern.severity.clone(),
        enabled: if pattern.enabled { 1 } else { 0 },
        created_at: chrono::Utc::now().timestamp(),
        updated_at: chrono::Utc::now().timestamp(),
    };
    if let Err(e) = db
        .retry_insert("persist_dlp_pattern", |cl| {
            let r = Row {
                id: row.id.clone(),
                name: row.name.clone(),
                pattern_type: row.pattern_type.clone(),
                pattern: row.pattern.clone(),
                severity: row.severity.clone(),
                enabled: row.enabled,
                created_at: row.created_at,
                updated_at: row.updated_at,
            };
            async move {
                let mut ins = cl
                    .insert("dlp_patterns")
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.write(&r).await.map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
                Ok(())
            }
        })
        .await
    {
        tracing::warn!("Failed to persist DLP pattern '{}': {:#}", pattern.name, e);
    }
}

/// Load custom DLP patterns from ClickHouse on startup.
pub async fn load_dlp_patterns_from_ch(db: &crate::db::Db, engine: &DlpEngineHandle) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        id: String,
        name: String,
        pattern_type: String,
        pattern: String,
        severity: String,
        enabled: u8,
    }
    let rows = match db.client()
        .query("SELECT id, argMax(name, updated_at) AS name, \
                argMax(pattern_type, updated_at) AS pattern_type, argMax(pattern, updated_at) AS pattern, \
                argMax(severity, updated_at) AS severity, argMax(enabled, updated_at) AS enabled \
                FROM dlp_patterns GROUP BY id")
        .fetch_all::<Row>().await
    {
        Ok(r) => r,
        Err(e) => { tracing::warn!("Failed to load DLP patterns from ClickHouse: {:#}", e); return; }
    };
    if rows.is_empty() {
        return;
    }
    let mut eng = engine.write().await;
    for r in &rows {
        let category: DlpCategory =
            serde_json::from_str(&r.pattern_type).unwrap_or(DlpCategory::Custom);
        let p = DlpPattern {
            id: r.id.clone(),
            name: r.name.clone(),
            category,
            regex_pattern: r.pattern.clone(),
            description: String::new(),
            severity: r.severity.clone(),
            enabled: r.enabled != 0,
            is_builtin: false,
            compiled: None,
        };
        let _ = eng.add_pattern(p);
    }
    tracing::info!("Loaded {} custom DLP patterns from ClickHouse", rows.len());
}

// ── API Handlers ─────────────────────────────────────────────────────────

use crate::enroll::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

/// GET /api/dlp/patterns — list all DLP patterns.
pub async fn api_list_dlp_patterns(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state.dlp_engine.read().await;
    let patterns = engine.list_patterns();
    Json(serde_json::json!({ "patterns": patterns }))
}

/// POST /api/dlp/patterns — add a custom DLP pattern.
pub async fn api_add_dlp_pattern(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let pattern = DlpPattern {
        id: body
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&uuid::Uuid::new_v4().to_string())
            .to_string(),
        name: body
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Custom Pattern")
            .into(),
        category: body
            .get("category")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or(DlpCategory::Custom),
        regex_pattern: body
            .get("regex_pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        description: body
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        severity: body
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("medium")
            .into(),
        enabled: body
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        is_builtin: false,
        compiled: None,
    };

    let mut engine = state.dlp_engine.write().await;
    match engine.add_pattern(pattern.clone()) {
        Ok(()) => {
            drop(engine);
            persist_dlp_pattern(&state.db, &pattern).await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"status": "added"})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/dlp/patterns/remove — remove a custom DLP pattern.
pub async fn api_remove_dlp_pattern(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let mut engine = state.dlp_engine.write().await;
    match engine.remove_pattern(id) {
        Ok(()) => Json(serde_json::json!({"status": "removed"})).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// GET /api/dlp/violations — list recent DLP violations.
pub async fn api_list_dlp_violations(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state.dlp_engine.read().await;
    let violations = engine.list_violations(100);
    Json(serde_json::json!({ "violations": violations }))
}

/// GET /api/dlp/stats — DLP statistics.
pub async fn api_dlp_stats(State(state): State<AppState>) -> impl IntoResponse {
    let engine = state.dlp_engine.read().await;
    Json(engine.stats())
}

/// POST /api/dlp/scan — scan arbitrary text for DLP violations (testing).
pub async fn api_dlp_scan(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let text = body.get("text").and_then(|v| v.as_str()).unwrap_or("");
    let mut engine = state.dlp_engine.write().await;
    let violations = engine.scan_text(text, "manual_scan", "manual", "api");
    Json(serde_json::json!({ "violations": violations }))
}
