use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::auth::{AuthedUser, Role};
use crate::enroll::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct ReactiveAuditEntry {
    pub ts_unix: i64,
    pub actor: String,
    pub role: String,
    pub action: String,
    pub target_type: String,
    pub target_value: String,
    pub ttl_seconds: Option<i64>,
    pub reason: Option<String>,
    pub context_alert_id: Option<String>,
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReactiveAuditQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub context_alert_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReactiveAuditResponse {
    pub entries: Vec<ReactiveAuditEntry>,
}

fn ch_client_from_state(state: &AppState) -> &clickhouse::Client {
    state.db.client()
}

#[allow(clippy::too_many_arguments)]
pub async fn log_reactive_action(
    state: &AppState,
    user: &AuthedUser,
    action: &str,
    target_type: &str,
    target_value: &str,
    ttl_seconds: Option<i64>,
    reason: Option<String>,
    context_alert_id: Option<String>,
    ok: bool,
) {
    let client = ch_client_from_state(state);

    let actor = user.username.clone();
    let role = format!("{:?}", user.role);
    let action = action.to_string();
    let target_type = target_type.to_string();
    let target_value = target_value.to_string();
    let ts_unix = Utc::now().timestamp();

    #[derive(clickhouse::Row, serde::Serialize)]
    struct AuditRow {
        id: String,
        ts_unix: i64,
        actor: String,
        role: String,
        action: String,
        target_type: String,
        target_value: String,
        ttl_seconds: i64,
        reason: String,
        context_alert_id: String,
        ok: u8,
    }

    let row = AuditRow {
        id: uuid::Uuid::new_v4().to_string(),
        ts_unix,
        actor,
        role,
        action,
        target_type,
        target_value,
        ttl_seconds: ttl_seconds.unwrap_or(0),
        reason: reason.unwrap_or_default(),
        context_alert_id: context_alert_id.unwrap_or_default(),
        ok: u8::from(ok),
    };

    match client.insert("reactive_audit") {
        Ok(mut insert) => {
            if let Err(e) = insert.write(&row).await {
                tracing::warn!("Audit log write failed: {e:#}");
            } else if let Err(e) = insert.end().await {
                tracing::warn!("Audit log commit failed: {e:#}");
            }
        }
        Err(e) => tracing::warn!("Audit log insert init failed: {e:#}"),
    }
}

pub async fn get_reactive_audit(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Query(q): Query<ReactiveAuditQuery>,
) -> Result<Json<ReactiveAuditResponse>, StatusCode> {
    let limit = q.limit.unwrap_or(60).clamp(1, 200);
    let context_alert_id = q.context_alert_id.and_then(|s| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    });

    let client = ch_client_from_state(&state);
    let actor_filter = if user.role == Role::Authority {
        None
    } else {
        Some(user.username.clone())
    };

    // Build a small number of query variants to avoid dynamic SQL mistakes.
    let sql_limit = i64::try_from(limit).unwrap_or(200);

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct AuditRow {
        ts_unix: i64,
        actor: String,
        role: String,
        action: String,
        target_type: String,
        target_value: String,
        ttl_seconds: i64,
        reason: String,
        context_alert_id: String,
        ok: u8,
    }

    let rows = match (context_alert_id.as_deref(), actor_filter.as_deref()) {
        (Some(ctx), Some(actor)) => {
            client
                .query(
                    "SELECT ts_unix, actor, role, action, target_type, target_value, ttl_seconds, reason, context_alert_id, ok
                     FROM reactive_audit
                     WHERE context_alert_id = ? AND actor = ?
                     ORDER BY ts_unix DESC
                     LIMIT ?",
                )
                .bind(ctx)
                .bind(actor)
                .bind(sql_limit)
                .fetch_all::<AuditRow>()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
        (Some(ctx), None) => {
            client
                .query(
                    "SELECT ts_unix, actor, role, action, target_type, target_value, ttl_seconds, reason, context_alert_id, ok
                     FROM reactive_audit
                     WHERE context_alert_id = ?
                     ORDER BY ts_unix DESC
                     LIMIT ?",
                )
                .bind(ctx)
                .bind(sql_limit)
                .fetch_all::<AuditRow>()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
        (None, Some(actor)) => {
            client
                .query(
                    "SELECT ts_unix, actor, role, action, target_type, target_value, ttl_seconds, reason, context_alert_id, ok
                     FROM reactive_audit
                     WHERE actor = ?
                     ORDER BY ts_unix DESC
                     LIMIT ?",
                )
                .bind(actor)
                .bind(sql_limit)
                .fetch_all::<AuditRow>()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
        (None, None) => {
            client
                .query(
                    "SELECT ts_unix, actor, role, action, target_type, target_value, ttl_seconds, reason, context_alert_id, ok
                     FROM reactive_audit
                     ORDER BY ts_unix DESC
                     LIMIT ?",
                )
                .bind(sql_limit)
                .fetch_all::<AuditRow>()
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
    };

    let mut entries = Vec::with_capacity(rows.len());
    for r in rows {
        entries.push(ReactiveAuditEntry {
            ts_unix: r.ts_unix,
            actor: r.actor,
            role: r.role,
            action: r.action,
            target_type: r.target_type,
            target_value: r.target_value,
            ttl_seconds: if r.ttl_seconds > 0 {
                Some(r.ttl_seconds)
            } else {
                None
            },
            reason: if r.reason.trim().is_empty() {
                None
            } else {
                Some(r.reason)
            },
            context_alert_id: if r.context_alert_id.trim().is_empty() {
                None
            } else {
                Some(r.context_alert_id)
            },
            ok: r.ok != 0,
        });
    }

    Ok(Json(ReactiveAuditResponse { entries }))
}
