//! Search API Module
//! Provides RESTful endpoints for querying events and alerts with filters

use axum::{
    extract::Path,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::collector::{connected_agent_ids_snapshot, GLOBAL_CONNECTED_AGENTS, GLOBAL_EVENTS_ACKED, GLOBAL_EVENTS_RECEIVED};
use crate::auth::{AuthedUser, Role};
use crate::enroll::AppState;
use percepta_server::alerts::Alert;
use std::sync::atomic::Ordering;

fn contains_ci(hay: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    hay.to_lowercase().contains(needle_lower)
}

fn map_contains_ci(map: &std::collections::HashMap<String, String>, needle_lower: &str) -> bool {
    map.iter()
        .any(|(k, v)| contains_ci(k, needle_lower) || contains_ci(v, needle_lower))
}

#[derive(Clone, Debug)]
struct QueryTerm {
    field: Option<String>,
    value_lower: String,
}

fn parse_query_terms(q: &str) -> Vec<QueryTerm> {
    let mut terms = Vec::new();
    for raw in q.split_whitespace() {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((k, v)) = token.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_lowercase();
            if !key.is_empty() && !val.is_empty() {
                terms.push(QueryTerm {
                    field: Some(key),
                    value_lower: val,
                });
                continue;
            }
        }

        terms.push(QueryTerm {
            field: None,
            value_lower: token.to_lowercase(),
        });
    }
    terms
}

#[derive(Debug, Deserialize)]
pub struct EventSearchQuery {
    #[serde(default)]
    pub from: Option<String>, // ISO 8601 timestamp
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // Reserved for future severity-based filtering
    pub severity: Option<String>,
    #[serde(default)]
    pub q: Option<String>, // Keyword search
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct EventSearchResponse {
    pub events: Vec<serde_json::Value>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct AlertsResponse {
    pub alerts: Vec<Alert>,
    pub total: usize,
}

#[derive(Debug, Deserialize)]
pub struct AlertsQuery {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: usize,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAlertStatusRequest {
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

fn parse_alert_status(s: &str) -> Option<percepta_server::alerts::AlertStatus> {
    use percepta_server::alerts::AlertStatus;
    match s.trim().to_lowercase().as_str() {
        "new" => Some(AlertStatus::New),
        "ack" | "acknowledged" => Some(AlertStatus::Acknowledged),
        "investigating" => Some(AlertStatus::Investigating),
        "resolved" => Some(AlertStatus::Resolved),
        "falsepositive" | "false_positive" | "fp" => Some(AlertStatus::FalsePositive),
        _ => None,
    }
}

fn require_alert_ops_role(user: &AuthedUser) -> Result<(), StatusCode> {
    if user.role == Role::Analyst || user.role == Role::Authority {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_events: usize,
    pub total_alerts: usize,
    pub alerts_by_severity: std::collections::HashMap<String, usize>,
    pub events_last_hour: usize,
    pub ingest_total_received: u64,
    pub ingest_total_acked: u64,
    pub connected_agents: usize,
    pub connected_agent_ids: Vec<String>,
}

/// GET /api/events - Search events with filters
pub async fn search_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchQuery>,
) -> impl IntoResponse {
    info!("Event search request: {:?}", query);

    // Parse time range
    let from = query
        .from
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let to = query
        .to
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    // Get events from storage
    {
        let mut events = state.storage_service.get_recent_events().await;
        // Apply filters
        if let Some(from_time) = from {
            events.retain(|e| {
                e.event_time
                    .as_ref()
                    .map(|t| {
                        DateTime::from_timestamp(t.seconds, 0).unwrap_or_else(Utc::now) >= from_time
                    })
                    .unwrap_or(false)
            });
        }

        events.retain(|e| {
            e.event_time
                .as_ref()
                .map(|t| DateTime::from_timestamp(t.seconds, 0).unwrap_or_else(Utc::now) <= to)
                .unwrap_or(true)
        });

        if let Some(agent_id) = &query.agent_id {
            events.retain(|e| {
                e.agent
                    .as_ref()
                    .map(|a| a.id.contains(agent_id))
                    .unwrap_or(false)
            });
        }

        if let Some(category) = &query.category {
            events.retain(|e| {
                e.event
                    .as_ref()
                    .map(|ev| format!("{:?}", ev.category).contains(category))
                    .unwrap_or(false)
            });
        }

        if let Some(keyword) = &query.q {
            let terms = parse_query_terms(keyword);
            events.retain(|e| {
                let matches_any_field = |needle_lower: &str| -> bool {
                    // IOC-friendly: summary/original/user/process/network/agent/host/file/registry/metadata/hashes.
                    let mut hit = false;

                    if let Some(ev) = e.event.as_ref() {
                        hit |= contains_ci(&ev.summary, needle_lower);
                        hit |= contains_ci(&ev.original_message, needle_lower);
                        hit |= contains_ci(&ev.provider, needle_lower);
                        hit |= contains_ci(&ev.action, needle_lower);
                        hit |= contains_ci(&ev.level, needle_lower);
                        hit |= contains_ci(&ev.event_id.to_string(), needle_lower);
                        hit |= contains_ci(&ev.record_id.to_string(), needle_lower);
                        hit |= contains_ci(&format!("{:?}", ev.category), needle_lower);
                        hit |= contains_ci(&format!("{:?}", ev.outcome), needle_lower);
                    }

                    if let Some(user) = e.user.as_ref() {
                        hit |= contains_ci(&user.name, needle_lower);
                        hit |= contains_ci(&user.domain, needle_lower);
                        hit |= contains_ci(&user.id, needle_lower);
                        for p in &user.privileges {
                            hit |= contains_ci(p, needle_lower);
                        }
                    }

                    if let Some(proc) = e.process.as_ref() {
                        hit |= contains_ci(&proc.name, needle_lower);
                        hit |= contains_ci(&proc.command_line, needle_lower);
                        hit |= contains_ci(&proc.pid.to_string(), needle_lower);
                        hit |= contains_ci(&proc.ppid.to_string(), needle_lower);
                        hit |= map_contains_ci(&proc.hash, needle_lower);
                    }

                    if let Some(net) = e.network.as_ref() {
                        hit |= contains_ci(&net.src_ip, needle_lower);
                        hit |= contains_ci(&net.dst_ip, needle_lower);
                        hit |= contains_ci(&net.src_port.to_string(), needle_lower);
                        hit |= contains_ci(&net.dst_port.to_string(), needle_lower);
                        hit |= contains_ci(&net.protocol, needle_lower);
                        hit |= contains_ci(&format!("{:?}", net.direction), needle_lower);
                        hit |= contains_ci(&net.tls_sni, needle_lower);
                        hit |= contains_ci(&net.ja3, needle_lower);
                        hit |= contains_ci(&net.ja3s, needle_lower);
                        hit |= contains_ci(&net.tls_cert_subject, needle_lower);
                        hit |= contains_ci(&net.tls_cert_issuer, needle_lower);
                    }

                    if let Some(agent) = e.agent.as_ref() {
                        hit |= contains_ci(&agent.id, needle_lower);
                        hit |= contains_ci(&agent.hostname, needle_lower);
                        hit |= contains_ci(&agent.ip, needle_lower);
                        hit |= contains_ci(&agent.mac, needle_lower);
                        if let Some(os) = agent.os.as_ref() {
                            hit |= contains_ci(&os.name, needle_lower);
                            hit |= contains_ci(&os.version, needle_lower);
                            hit |= contains_ci(&os.kernel, needle_lower);
                        }
                    }

                    if let Some(host) = e.host.as_ref() {
                        for ip in &host.ip {
                            hit |= contains_ci(ip, needle_lower);
                        }
                        for mac in &host.mac {
                            hit |= contains_ci(mac, needle_lower);
                        }
                    }

                    if let Some(file) = e.file.as_ref() {
                        hit |= contains_ci(&file.path, needle_lower);
                        hit |= contains_ci(&file.permissions, needle_lower);
                        hit |= contains_ci(&format!("{:?}", file.operation), needle_lower);
                        hit |= map_contains_ci(&file.hash, needle_lower);
                    }

                    if let Some(reg) = e.registry.as_ref() {
                        hit |= contains_ci(&reg.path, needle_lower);
                        hit |= contains_ci(&reg.value, needle_lower);
                    }

                    hit |= map_contains_ci(&e.metadata, needle_lower);

                    for t in &e.tags {
                        hit |= contains_ci(t, needle_lower);
                    }

                    hit |= contains_ci(&e.threat_indicator, needle_lower);
                    hit |= contains_ci(&e.threat_source, needle_lower);
                    hit |= contains_ci(&e.correlation_id, needle_lower);
                    hit |= contains_ci(&e.hash, needle_lower);

                    hit
                };

                let matches_field = |field: &str, needle_lower: &str| -> bool {
                    match field {
                        "ip" | "src_ip" | "dst_ip" => {
                            if let Some(net) = e.network.as_ref() {
                                if contains_ci(&net.src_ip, needle_lower) || contains_ci(&net.dst_ip, needle_lower) {
                                    return true;
                                }
                            }
                            if let Some(agent) = e.agent.as_ref() {
                                if contains_ci(&agent.ip, needle_lower) {
                                    return true;
                                }
                            }
                            if let Some(host) = e.host.as_ref() {
                                if host.ip.iter().any(|ip| contains_ci(ip, needle_lower)) {
                                    return true;
                                }
                            }
                            false
                        }
                        "user" => e
                            .user
                            .as_ref()
                            .map(|u| {
                                contains_ci(&u.name, needle_lower)
                                    || contains_ci(&u.domain, needle_lower)
                                    || contains_ci(&u.id, needle_lower)
                                    || u.privileges.iter().any(|p| contains_ci(p, needle_lower))
                            })
                            .unwrap_or(false),
                        "agent" => e
                            .agent
                            .as_ref()
                            .map(|a| {
                                contains_ci(&a.id, needle_lower)
                                    || contains_ci(&a.hostname, needle_lower)
                                    || contains_ci(&a.ip, needle_lower)
                                    || contains_ci(&a.mac, needle_lower)
                            })
                            .unwrap_or(false),
                        "hash" | "sha256" => {
                            if contains_ci(&e.hash, needle_lower) || contains_ci(&e.correlation_id, needle_lower) {
                                return true;
                            }
                            if let Some(file) = e.file.as_ref() {
                                if map_contains_ci(&file.hash, needle_lower) {
                                    return true;
                                }
                            }
                            if let Some(proc) = e.process.as_ref() {
                                if map_contains_ci(&proc.hash, needle_lower) {
                                    return true;
                                }
                            }
                            false
                        }
                        "proc" | "process" => e
                            .process
                            .as_ref()
                            .map(|p| contains_ci(&p.name, needle_lower) || contains_ci(&p.command_line, needle_lower))
                            .unwrap_or(false),
                        "file" => e
                            .file
                            .as_ref()
                            .map(|f| {
                                contains_ci(&f.path, needle_lower)
                                    || contains_ci(&f.permissions, needle_lower)
                                    || contains_ci(&format!("{:?}", f.operation), needle_lower)
                                    || map_contains_ci(&f.hash, needle_lower)
                            })
                            .unwrap_or(false),
                        "reg" | "registry" => e
                            .registry
                            .as_ref()
                            .map(|r| contains_ci(&r.path, needle_lower) || contains_ci(&r.value, needle_lower))
                            .unwrap_or(false),
                        "tag" => e.tags.iter().any(|t| contains_ci(t, needle_lower)),
                        "cve" => {
                            if let Some(ev) = e.event.as_ref() {
                                if contains_ci(&ev.summary, needle_lower) || contains_ci(&ev.original_message, needle_lower) {
                                    return true;
                                }
                            }
                            map_contains_ci(&e.metadata, needle_lower)
                        }
                        "provider" => e
                            .event
                            .as_ref()
                            .map(|ev| contains_ci(&ev.provider, needle_lower))
                            .unwrap_or(false),
                        "eid" | "eventid" | "event_id" => e
                            .event
                            .as_ref()
                            .map(|ev| {
                                contains_ci(&ev.event_id.to_string(), needle_lower)
                                    || contains_ci(&ev.record_id.to_string(), needle_lower)
                            })
                            .unwrap_or(false),
                        _ => matches_any_field(needle_lower),
                    }
                };

                // AND semantics across terms (SOC-friendly). Unknown fields fall back to any-field matching.
                terms.iter().all(|t| {
                    if t.value_lower.is_empty() {
                        return true;
                    }
                    if let Some(f) = t.field.as_deref() {
                        matches_field(f, &t.value_lower)
                    } else {
                        matches_any_field(&t.value_lower)
                    }
                })
            });
        }

        let total = events.len();
        let page = query.offset / query.limit;

        // Apply pagination
        let paginated: Vec<_> = events
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();

        let has_more = query.offset + query.limit < total;

        // Convert to JSON
        let events_json: Vec<serde_json::Value> = paginated
            .into_iter()
            .filter_map(|e| serde_json::to_value(&e).ok())
            .collect();

        let response = EventSearchResponse {
            events: events_json,
            total,
            page,
            per_page: query.limit,
            has_more,
        };

        (StatusCode::OK, Json(response))
    }
}

/// GET /api/alerts - Get alerts (supports ?limit=&offset= for UI responsiveness)
pub async fn get_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertsQuery>,
) -> impl IntoResponse {
    let mut alerts = state.alert_service.get_alerts().await;
    let total = alerts.len();

    // Prefer newest alerts first.
    alerts.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

    let alerts = if let Some(limit) = query.limit {
        alerts
            .into_iter()
            .skip(query.offset)
            .take(limit)
            .collect()
    } else {
        alerts
    };

    Json(AlertsResponse { alerts, total })
}

/// POST /api/alerts/:id/status  {"status":"resolved"}
pub async fn update_alert_status(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Path(id): Path<String>,
    Json(body): Json<UpdateAlertStatusRequest>,
) -> impl IntoResponse {
    if let Err(sc) = require_alert_ops_role(&user) {
        return (sc, Json(OkResponse { ok: false })).into_response();
    }

    let Some(status) = parse_alert_status(&body.status) else {
        return (StatusCode::BAD_REQUEST, Json(OkResponse { ok: false })).into_response();
    };

    match state.alert_service.update_alert_status(&id, status).await {
        Ok(()) => (StatusCode::OK, Json(OkResponse { ok: true })).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Json(OkResponse { ok: false })).into_response(),
    }
}

/// DELETE /api/alerts/:id
pub async fn delete_alert(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(sc) = require_alert_ops_role(&user) {
        return (sc, Json(OkResponse { ok: false })).into_response();
    }

    match state.alert_service.remove_alert(&id).await {
        Ok(()) => (StatusCode::OK, Json(OkResponse { ok: true })).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Json(OkResponse { ok: false })).into_response(),
    }
}

/// POST /api/alerts/clear
pub async fn clear_alerts(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    if let Err(sc) = require_alert_ops_role(&user) {
        return (sc, Json(OkResponse { ok: false })).into_response();
    }

    state.alert_service.clear_alerts().await;
    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}

/// GET /api/stats - Get SIEM statistics
pub async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    // Get events
    let events = state.storage_service.get_recent_events().await;
    let total_events = events.len();

    // Count events in last hour
    let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
    let events_last_hour = events
        .iter()
        .filter(|e| {
            e.event_time
                .as_ref()
                .and_then(|t| DateTime::from_timestamp(t.seconds, 0))
                .map(|dt| dt > one_hour_ago)
                .unwrap_or(false)
        })
        .count();

    // Get alerts
    let alerts = state.alert_service.get_alerts().await;
    let total_alerts = alerts.len();

    // Count alerts by severity
    let mut alerts_by_severity = std::collections::HashMap::new();
    for alert in &alerts {
        let severity = format!("{:?}", alert.severity);
        *alerts_by_severity.entry(severity).or_insert(0) += 1;
    }

    // Use live collector state for connected agents
    let connected_agents = GLOBAL_CONNECTED_AGENTS.load(Ordering::Relaxed) as usize;
    let connected_agent_ids = connected_agent_ids_snapshot().await;

    // Stable ingestion counters (monotonic) used by the dashboard counters.
    let ingest_total_received = GLOBAL_EVENTS_RECEIVED.load(Ordering::Relaxed);
    let ingest_total_acked = GLOBAL_EVENTS_ACKED.load(Ordering::Relaxed);

    Json(StatsResponse {
        total_events,
        total_alerts,
        alerts_by_severity,
        events_last_hour,
        ingest_total_received,
        ingest_total_acked,
        connected_agents,
        connected_agent_ids,
    })
}
