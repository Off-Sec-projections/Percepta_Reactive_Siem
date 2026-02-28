//! Alert Notification Channels
//!
//! Supports webhook (Slack, Teams, PagerDuty, generic), email (SMTP), and
//! configurable per-severity routing. Configuration is persisted to ClickHouse.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::auth::AuthedUser;
use crate::enroll::AppState;
use percepta_server::alerts::{Alert, AlertSeverity};

// ── Configuration ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationConfig {
    #[serde(default)]
    pub channels: Vec<NotificationChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationChannel {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub channel_type: ChannelType,
    /// Minimum severity to trigger (critical, high, medium, low, info).
    #[serde(default = "default_min_severity")]
    pub min_severity: String,
    /// Webhook URL (for webhook type).
    #[serde(default)]
    pub webhook_url: String,
    /// Webhook format: "slack", "teams", "pagerduty", "generic".
    #[serde(default = "default_webhook_format")]
    pub webhook_format: String,
    /// SMTP settings (for email type).
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default)]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_from: String,
    #[serde(default)]
    pub smtp_to: String,
}

fn default_min_severity() -> String {
    "high".into()
}
fn default_webhook_format() -> String {
    "generic".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelType {
    Webhook,
    Email,
}

// ── Shared state ─────────────────────────────────────────────

pub type NotificationConfigHandle = Arc<RwLock<NotificationConfig>>;

pub fn init_notification_config() -> NotificationConfigHandle {
    Arc::new(RwLock::new(NotificationConfig::default()))
}

/// Load saved notification config from ClickHouse app_config table.
pub async fn load_notification_config_from_ch(
    db: &crate::db::Db,
    handle: &NotificationConfigHandle,
) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CfgRow {
        v: String,
    }
    let row = match db.client()
        .query("SELECT argMax(v, updated_at) AS v FROM app_config WHERE k = 'notification_config' GROUP BY k")
        .fetch_one::<CfgRow>()
        .await
    {
        Ok(r) => r,
        Err(_) => return, // No saved config yet
    };
    match serde_json::from_str::<NotificationConfig>(&row.v) {
        Ok(cfg) => {
            let count = cfg.channels.len();
            *handle.write().await = cfg;
            info!(
                "Loaded notification config from ClickHouse ({} channels)",
                count
            );
        }
        Err(e) => warn!("Failed to parse saved notification config: {}", e),
    }
}

// ── API handlers ─────────────────────────────────────────────

/// GET /api/notifications/config
pub async fn get_config(
    State(state): State<AppState>,
    axum::extract::Extension(_user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    let cfg = state.notification_config.read().await;
    Json(cfg.clone())
}

/// POST /api/notifications/config — save notification configuration
pub async fn save_config(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<NotificationConfig>,
) -> impl IntoResponse {
    info!("Notification config updated by {}", user.username);
    let mut cfg = state.notification_config.write().await;
    *cfg = body.clone();

    // Persist to ClickHouse (simple JSON blob in a config KV table)
    let client = state.db.client();
    let content = match serde_json::to_string(&body) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to serialize notification config: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error").into_response();
        }
    };

    #[derive(clickhouse::Row, serde::Serialize)]
    struct CfgRow<'a> {
        k: &'a str,
        v: &'a str,
        updated_at: i64,
    }

    // Ensure table exists (idempotent)
    let _ = client
        .query(
            "CREATE TABLE IF NOT EXISTS app_config (\
                k String,\
                v String,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY k",
        )
        .execute()
        .await;

    let row = CfgRow {
        k: "notification_config",
        v: &content,
        updated_at: Utc::now().timestamp(),
    };
    if let Err(e) = async {
        let mut ins = client
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
        warn!("Failed to persist notification config: {:#}", e);
    }

    Json(serde_json::json!({ "ok": true })).into_response()
}

/// POST /api/notifications/test — send a test notification
pub async fn test_notification(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    let cfg = state.notification_config.read().await.clone();
    let test_alert = Alert {
        id: "test-notification".into(),
        rule_id: "test-rule".into(),
        rule_name: "Test Notification Rule".into(),
        severity: AlertSeverity::High,
        category: "test".into(),
        message: format!("Test notification triggered by {}", user.username),
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        count: 1,
        agent_id: "test-agent".into(),
        agent_hostname: "test-host".into(),
        source_events: vec![],
        status: percepta_server::alerts::AlertStatus::New,
        metadata: std::collections::HashMap::new(),
        compliance: Vec::new(),
        compliance_frameworks: Vec::new(),
        compliance_controls: Vec::new(),
        compliance_mappings: Vec::new(),
        assignee: None,
    };

    let mut results = Vec::new();
    for ch in &cfg.channels {
        if !ch.enabled {
            results.push(serde_json::json!({ "channel": ch.name, "status": "skipped (disabled)" }));
            continue;
        }
        let res = send_to_channel(ch, &test_alert).await;
        results.push(serde_json::json!({
            "channel": ch.name,
            "status": if res.is_ok() { "ok" } else { "error" },
            "detail": res.err().map(|e| format!("{:#}", e)),
        }));
    }

    Json(serde_json::json!({ "results": results }))
}

// ── Notification dispatch ────────────────────────────────────

fn severity_rank(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "info" => 1,
        _ => 0,
    }
}

fn alert_severity_rank(s: &AlertSeverity) -> u8 {
    match s {
        AlertSeverity::Critical => 5,
        AlertSeverity::High => 4,
        AlertSeverity::Medium => 3,
        AlertSeverity::Low => 2,
        AlertSeverity::Info => 1,
    }
}

/// Fire notifications for a new alert. Called from the ingest pipeline.
pub async fn dispatch_alert_notifications(config: &NotificationConfigHandle, alert: &Alert) {
    let cfg = config.read().await;
    let alert_rank = alert_severity_rank(&alert.severity);

    for ch in &cfg.channels {
        if !ch.enabled {
            continue;
        }
        let min_rank = severity_rank(&ch.min_severity);
        if alert_rank < min_rank {
            continue;
        }
        if let Err(e) = send_to_channel(ch, alert).await {
            warn!("Notification channel '{}' failed: {:#}", ch.name, e);
        }
    }
}

async fn send_to_channel(ch: &NotificationChannel, alert: &Alert) -> anyhow::Result<()> {
    match ch.channel_type {
        ChannelType::Webhook => send_webhook(ch, alert).await,
        ChannelType::Email => {
            warn!(
                "Email notification to {} for alert {} not sent: Email channel not yet implemented",
                ch.smtp_to, alert.id
            );
            Err(anyhow::anyhow!(
                "Email notification channel is not yet implemented. \
                 Configure a webhook channel instead."
            ))
        }
    }
}

async fn send_webhook(ch: &NotificationChannel, alert: &Alert) -> anyhow::Result<()> {
    if ch.webhook_url.is_empty() {
        anyhow::bail!("webhook_url is empty");
    }

    let payload = match ch.webhook_format.as_str() {
        "slack" => serde_json::json!({
            "text": format!(
                "🚨 *[{}]* {} — {}\nAgent: {} | Rule: {} | Count: {}",
                alert.severity_str(),
                alert.rule_name,
                alert.message,
                alert.agent_hostname,
                alert.rule_id,
                alert.count
            ),
        }),
        "teams" => serde_json::json!({
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": format!("[{}] {}", alert.severity_str(), alert.rule_name),
            "themeColor": match &alert.severity {
                AlertSeverity::Critical => "FF0000",
                AlertSeverity::High => "FF6600",
                AlertSeverity::Medium => "FFAA00",
                _ => "999999",
            },
            "title": format!("Percepta SIEM Alert — {}", alert.rule_name),
            "sections": [{
                "facts": [
                    { "name": "Severity", "value": alert.severity_str() },
                    { "name": "Message", "value": &alert.message },
                    { "name": "Agent", "value": &alert.agent_hostname },
                    { "name": "Count", "value": alert.count },
                ],
            }],
        }),
        "pagerduty" => serde_json::json!({
            "routing_key": "", // filled by user in webhook_url params
            "event_action": "trigger",
            "payload": {
                "summary": format!("[{}] {} — {}", alert.severity_str(), alert.rule_name, alert.message),
                "severity": match &alert.severity {
                    AlertSeverity::Critical => "critical",
                    AlertSeverity::High => "error",
                    AlertSeverity::Medium => "warning",
                    _ => "info",
                },
                "source": "percepta-siem",
                "component": &alert.agent_hostname,
                "group": &alert.category,
                "class": &alert.rule_id,
            },
        }),
        _ => serde_json::json!({
            "alert_id": &alert.id,
            "rule_id": &alert.rule_id,
            "rule_name": &alert.rule_name,
            "severity": alert.severity_str(),
            "category": &alert.category,
            "message": &alert.message,
            "agent_id": &alert.agent_id,
            "agent_hostname": &alert.agent_hostname,
            "count": alert.count,
            "first_seen": alert.first_seen.to_rfc3339(),
            "last_seen": alert.last_seen.to_rfc3339(),
        }),
    };

    if !crate::playbooks::is_safe_webhook_url(&ch.webhook_url) {
        anyhow::bail!("Webhook URL rejected: must be https:// to a public host");
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let resp = client.post(&ch.webhook_url).json(&payload).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Webhook returned {}: {}", status, body);
    }

    info!(
        "Notification sent via webhook '{}' for alert {}",
        ch.name, alert.id
    );
    Ok(())
}
