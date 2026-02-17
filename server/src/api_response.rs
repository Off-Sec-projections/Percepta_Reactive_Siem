use axum::{http::StatusCode, Json};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiErrorResponse {
    pub ok: bool,
    pub error_code: String,
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl ApiErrorResponse {
    pub fn new(error_code: impl Into<String>, error_message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error_code: error_code.into(),
            error_message: error_message.into(),
            trace_id: None,
        }
    }
}

pub fn api_error(
    status: StatusCode,
    error_code: impl Into<String>,
    error_message: impl Into<String>,
) -> (StatusCode, Json<ApiErrorResponse>) {
    (
        status,
        Json(ApiErrorResponse::new(error_code, error_message)),
    )
}
