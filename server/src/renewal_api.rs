use crate::auth::{AuthedUser, Role};
use crate::enroll::AppState;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct IdentityInfo {
    pub primary_mac: String,
    pub first_user: String,
}

#[derive(Debug, Deserialize)]
pub struct RenewalRequestBody {
    pub csr: String,
    pub identity: IdentityInfo,
}

#[derive(Debug, Serialize)]
pub struct RenewalRequestResponse {
    pub ok: bool,
    pub request_id: String,
    pub pickup_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RenewalPickupQuery {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct RenewalPickupResponse {
    pub ok: bool,
    pub status: String,
    pub agent_cert: Option<String>,
    pub ca_cert: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ApproveBody {
    pub request_id: String,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
}

pub async fn renew_request(
    State(state): State<AppState>,
    Json(body): Json<RenewalRequestBody>,
) -> impl IntoResponse {
    // Derive agent_id from CSR CN for consistency and to prevent spoofed ids.
    let csr = match openssl::x509::X509Req::from_pem(body.csr.as_bytes()) {
        Ok(v) => v,
        Err(_e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(OkResponse { ok: false }),
            )
                .into_response();
        }
    };

    let subject = csr.subject_name();
    let cn = subject
        .entries()
        .find(|entry| entry.object().nid() == openssl::nid::Nid::COMMONNAME)
        .and_then(|entry| entry.data().as_utf8().ok())
        .map(|s| s.to_string());

    let Some(agent_id) = cn else {
        return (
            StatusCode::BAD_REQUEST,
            Json(OkResponse { ok: false }),
        )
            .into_response();
    };

    // Enforce permanent identity binding before accepting a renewal request.
    if let Err(e) = state
        .agent_identity
        .upsert_or_verify(&agent_id, &body.identity.primary_mac, &body.identity.first_user)
        .await
    {
        warn!("renew_request identity mismatch: {e:#}");
        return (
            StatusCode::FORBIDDEN,
            Json(OkResponse { ok: false }),
        )
            .into_response();
    }

    match state
        .renewals
        .create_request(
            &agent_id,
            &body.identity.primary_mac,
            &body.identity.first_user,
            &body.csr,
        )
        .await
    {
        Ok(created) => (
            StatusCode::OK,
            Json(RenewalRequestResponse {
                ok: true,
                request_id: created.request_id,
                pickup_token: created.pickup_token,
            }),
        )
            .into_response(),
        Err(e) => {
            warn!("renew_request failed: {e:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OkResponse { ok: false }),
            )
                .into_response()
        }
    }
}

pub async fn renew_pickup(
    State(state): State<AppState>,
    Query(q): Query<RenewalPickupQuery>,
) -> impl IntoResponse {
    match state.renewals.get_for_pickup(&q.token).await {
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(RenewalPickupResponse {
                ok: false,
                status: "invalid".to_string(),
                agent_cert: None,
                ca_cert: None,
            }),
        )
            .into_response(),
        Ok(Some((status, cert_opt))) => {
            if status == "approved" {
                let Some(cert) = cert_opt else {
                    return (
                        StatusCode::ACCEPTED,
                        Json(RenewalPickupResponse {
                            ok: true,
                            status: "pending".to_string(),
                            agent_cert: None,
                            ca_cert: None,
                        }),
                    )
                        .into_response();
                };

                let ca_cert = match state.ca_service.get_ca_certificate_pem() {
                    Ok(v) => v,
                    Err(_) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(RenewalPickupResponse {
                                ok: false,
                                status: "error".to_string(),
                                agent_cert: None,
                                ca_cert: None,
                            }),
                        )
                            .into_response();
                    }
                };

                return (
                    StatusCode::OK,
                    Json(RenewalPickupResponse {
                        ok: true,
                        status: "approved".to_string(),
                        agent_cert: Some(cert),
                        ca_cert: Some(ca_cert),
                    }),
                )
                    .into_response();
            }

            (
                StatusCode::ACCEPTED,
                Json(RenewalPickupResponse {
                    ok: true,
                    status,
                    agent_cert: None,
                    ca_cert: None,
                }),
            )
                .into_response()
        }
        Err(e) => {
            warn!("renew_pickup failed: {e:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(RenewalPickupResponse {
                    ok: false,
                    status: "error".to_string(),
                    agent_cert: None,
                    ca_cert: None,
                }),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RenewalListResponse {
    pub requests: Vec<crate::renewal_store::RenewalRequestRow>,
}

pub async fn renew_list(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, Json(OkResponse { ok: false })).into_response();
    }

    match state.renewals.list_recent(100).await {
        Ok(rows) => (StatusCode::OK, Json(RenewalListResponse { requests: rows })).into_response(),
        Err(e) => {
            warn!("renew_list failed: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(OkResponse { ok: false })).into_response()
        }
    }
}

pub async fn renew_approve(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<ApproveBody>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, Json(OkResponse { ok: false })).into_response();
    }

    let (agent_id, csr_pem) = match state.renewals.get_csr_and_agent_id(&body.request_id).await {
        Ok(v) => v,
        Err(e) => {
            warn!("renew_approve lookup failed: {e:#}");
            return (StatusCode::NOT_FOUND, Json(OkResponse { ok: false })).into_response();
        }
    };

    // Sign CSR for the same agent_id (CN is authoritative).
    let issued = match state
        .ca_service
        .sign_csr(csr_pem.as_bytes(), Some(agent_id))
        .await
    {
        Ok(v) => v,
        Err(e) => {
            warn!("renew_approve sign failed: {e:#}");
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(OkResponse { ok: false })).into_response();
        }
    };

    if let Err(e) = state
        .renewals
        .approve(&body.request_id, &user.username, &issued.certificate_pem)
        .await
    {
        warn!("renew_approve store failed: {e:#}");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(OkResponse { ok: false })).into_response();
    }

    (StatusCode::OK, Json(OkResponse { ok: true })).into_response()
}
