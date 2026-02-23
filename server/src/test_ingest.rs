//! Test ingestion endpoint for development/testing
//! Allows HTTP POST of events without mTLS for easy testing

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::enroll::AppState;
use crate::ingest_utils;
use crate::websocket::StreamMessage;
use percepta_server::percepta::Event;

/// POST /api/test/ingest - Accept test events via HTTP (no auth for testing)
pub async fn test_ingest_event(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    info!("📥 Test event received via HTTP");

    let normalized_payload = normalize_test_event_payload(payload);

    // Try to parse as protobuf Event
    let mut event: Event = match serde_json::from_value(normalized_payload) {
        Ok(e) => e,
        Err(err) => {
            warn!("Failed to parse test event: {}", err);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid event format",
                    "details": err.to_string()
                })),
            );
        }
    };

    ingest_utils::ensure_event_hash(&mut event);

    // If the caller didn't include an agent id, set a stable test id so rules can group-by.
    let hint = match event.agent.as_ref() {
        Some(agent) if !agent.id.is_empty() => None,
        _ => Some("test-agent"),
    };
    ingest_utils::enrich_event(&mut event, hint);

    if let Err(err) = ingest_utils::validate_event(&event) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid event",
                "details": err.to_string(),
            })),
        );
    }

    // Evaluate event against detection rules and broadcast alerts
    match state.rule_engine.evaluate_event(&event).await {
        Ok(alerts) => {
            for alert in alerts {
                let _ = state.event_broadcaster.send(StreamMessage::Alert(alert));
            }
        }
        Err(e) => warn!("Failed to evaluate test event against rules: {}", e),
    }

    // Store the event
    if let Err(e) = state.storage_service.store_event(&event).await {
        warn!("Failed to store test event: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "Failed to store event",
                "details": e.to_string()
            })),
        );
    }

    // Broadcast to WebSocket subscribers
    let _ = state.event_broadcaster.send(StreamMessage::Event(event.clone()));

    info!("✅ Test event stored and broadcast: {}", event.hash);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "event_id": event.hash,
            "message": "Event ingested successfully"
        })),
    )
}

fn normalize_test_event_payload(mut payload: Value) -> Value {
    if !payload.is_object() {
        return payload;
    }

    let ts = Utc::now().timestamp();
    let obj = payload.as_object_mut().expect("checked is_object");

    match obj.get("event_time") {
        Some(v) if v.is_number() => {}
        _ => {
            obj.insert("event_time".to_string(), json!(ts));
        }
    }
    match obj.get("ingest_time") {
        Some(v) if v.is_number() => {}
        _ => {
            obj.insert("ingest_time".to_string(), json!(ts));
        }
    }

    for key in ["network", "process", "file", "registry"] {
        if !obj.contains_key(key) {
            obj.insert(key.to_string(), Value::Null);
        }
    }

    // --- agent ---
    let agent_val = obj.entry("agent".to_string()).or_insert_with(|| json!({}));
    if !agent_val.is_object() {
        *agent_val = json!({});
    }
    if let Some(agent) = agent_val.as_object_mut() {
        for (k, default) in [
            ("id", "test-agent"),
            ("hostname", "test-host"),
            ("ip", "0.0.0.0"),
            ("mac", ""),
            ("version", ""),
        ] {
            match agent.get(k) {
                Some(v) if v.is_string() => {}
                _ => {
                    agent.insert(k.to_string(), json!(default));
                }
            }
        }
        if !agent.contains_key("os") {
            agent.insert("os".to_string(), Value::Null);
        }
    }

    // --- event details ---
    let event_val = obj.entry("event".to_string()).or_insert_with(|| json!({}));
    if !event_val.is_object() {
        *event_val = json!({});
    }
    if let Some(event) = event_val.as_object_mut() {
        for (k, default) in [
            ("summary", "Test event"),
            ("original_message", ""),
            ("action", "test"),
            ("level", "Info"),
            ("provider", "test"),
        ] {
            match event.get(k) {
                Some(v) if v.is_string() => {}
                _ => {
                    event.insert(k.to_string(), json!(default));
                }
            }
        }
        for (k, default) in [
            ("category", 0),
            ("outcome", 0),
            ("severity", 0),
            ("event_id", 0),
            ("record_id", 0),
        ] {
            match event.get(k) {
                Some(v) if v.is_number() => {}
                _ => {
                    event.insert(k.to_string(), json!(default));
                }
            }
        }
    }

    // --- user ---
    let user_val = obj.entry("user".to_string()).or_insert_with(|| json!({}));
    if !user_val.is_object() {
        *user_val = json!({});
    }
    if let Some(user) = user_val.as_object_mut() {
        for (k, default) in [("id", ""), ("name", ""), ("domain", "")] {
            match user.get(k) {
                Some(v) if v.is_string() => {}
                _ => {
                    user.insert(k.to_string(), json!(default));
                }
            }
        }
        match user.get("privileges") {
            Some(v) if v.is_array() => {}
            _ => {
                user.insert("privileges".to_string(), json!([]));
            }
        }
    }

    // --- host ---
    let host_val = obj.entry("host".to_string()).or_insert_with(|| json!({}));
    if !host_val.is_object() {
        *host_val = json!({});
    }
    if let Some(host) = host_val.as_object_mut() {
        // Allow "ip" to be either a string or array.
        match host.get_mut("ip") {
            Some(Value::Array(_)) => {}
            Some(Value::String(s)) => {
                let ip = std::mem::take(s);
                host.insert("ip".to_string(), json!([ip]));
            }
            _ => {
                host.insert("ip".to_string(), json!([]));
            }
        }

        match host.get("mac") {
            Some(v) if v.is_array() => {}
            _ => {
                host.insert("mac".to_string(), json!([]));
            }
        }
    }

    // --- metadata/tags ---
    match obj.get("metadata") {
        Some(v) if v.is_object() => {}
        _ => {
            obj.insert("metadata".to_string(), json!({}));
        }
    }

    match obj.get("tags") {
        Some(v) if v.is_array() => {}
        _ => {
            obj.insert("tags".to_string(), json!([]));
        }
    }

    for key in ["threat_indicator", "threat_source", "correlation_id", "hash"] {
        match obj.get(key) {
            Some(v) if v.is_string() => {}
            _ => {
                obj.insert(key.to_string(), json!(""));
            }
        }
    }

    payload
}
