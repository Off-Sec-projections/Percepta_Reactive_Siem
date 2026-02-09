use crate::auth::{AuthedUser, Role};
use crate::enroll::AppState;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct DeviceLookupRequest {
    pub macs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DeviceLookupResponse {
    pub names: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct DeviceSetRequest {
    pub mac: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

fn require_device_ops_role(user: &AuthedUser) -> Result<(), StatusCode> {
    if user.role == Role::Analyst || user.role == Role::Authority {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

/// POST /api/device/lookup {"macs": ["aa:bb:cc:dd:ee:ff", ...]}
/// Public endpoint used by the dashboard to render stable names uniformly.
pub async fn device_lookup(
    State(state): State<AppState>,
    Json(body): Json<DeviceLookupRequest>,
) -> impl IntoResponse {
    let names = state.device_registry.lookup_many(&body.macs).await;
    (StatusCode::OK, Json(DeviceLookupResponse { names })).into_response()
}

/// POST /api/device/set {"mac": "aa:bb...", "name": "Agent 1 (alice)"}
/// Protected by session middleware; enforces Analyst/Authority role.
pub async fn device_set(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<DeviceSetRequest>,
) -> impl IntoResponse {
    if let Err(sc) = require_device_ops_role(&user) {
        return (sc, Json(OkResponse { ok: false })).into_response();
    }

    if body.mac.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(OkResponse { ok: false }),
        )
            .into_response();
    }

    if let Err(e) = state.device_registry.set(&body.mac, &body.name).await {
        warn!("device_set failed: {e:#}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OkResponse { ok: false }),
        )
            .into_response();
    }

    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}

/// POST /api/device/clear {"mac": "aa:bb..."}
/// Protected by session middleware.
pub async fn device_clear(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<DeviceSetRequest>,
) -> impl IntoResponse {
    if let Err(sc) = require_device_ops_role(&user) {
        return (sc, Json(OkResponse { ok: false })).into_response();
    }

    if body.mac.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(OkResponse { ok: false }),
        )
            .into_response();
    }

    if let Err(e) = state.device_registry.clear(&body.mac).await {
        warn!("device_clear failed: {e:#}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(OkResponse { ok: false }),
        )
            .into_response();
    }

    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}
