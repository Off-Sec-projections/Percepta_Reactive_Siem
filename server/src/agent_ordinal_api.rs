use crate::api_response::api_error;
use crate::auth::AuthedUser;
use crate::enroll::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;

#[derive(Debug, Serialize)]
pub struct AgentOrdinalSnapshot {
    pub next: i64,
    pub by_key: HashMap<String, i64>,
    pub name_by_id: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct AgentOrdinalUpsertRequest {
    pub next: i64,
    pub by_key: HashMap<String, i64>,
    #[serde(default)]
    pub name_by_id: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

/// GET /api/agent_ordinals
pub async fn api_get_agent_ordinals(State(state): State<AppState>) -> impl IntoResponse {
    let (next, by_key, name_by_id) = state.agent_ordinals.snapshot().await;
    (
        StatusCode::OK,
        Json(AgentOrdinalSnapshot {
            next,
            by_key,
            name_by_id,
        }),
    )
        .into_response()
}

/// POST /api/agent_ordinals
pub async fn api_upsert_agent_ordinals(
    State(state): State<AppState>,
    axum::extract::Extension(_user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<AgentOrdinalUpsertRequest>,
) -> impl IntoResponse {
    if let Err(e) = state
        .agent_ordinals
        .bulk_upsert(body.next, body.by_key, body.name_by_id)
        .await
    {
        warn!("agent_ordinals upsert failed: {e:#}");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "upsert_failed",
            "failed to persist agent ordinals",
        )
        .into_response();
    }
    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}

/// POST /api/agent_ordinals/clear
pub async fn api_clear_agent_ordinals(
    State(state): State<AppState>,
    axum::extract::Extension(_user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    if let Err(e) = state.agent_ordinals.clear_all().await {
        warn!("agent_ordinals clear failed: {e:#}");
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "clear_failed",
            "failed to clear agent ordinals",
        )
        .into_response();
    }
    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}
