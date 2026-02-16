//! Analyst Notes API — server-side persistence for the event drawer Notes tab.
//!
//! Notes are keyed by `(entity_type, entity_id)` where entity_type is typically
//! "event" or "alert" and entity_id is the event hash or alert UUID.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::auth::AuthedUser;
use crate::enroll::AppState;

#[derive(Debug, Deserialize)]
pub struct GetNoteQuery {
    pub entity_type: String,
    pub entity_id: String,
}

#[derive(Debug, Deserialize)]
pub struct SaveNoteBody {
    pub entity_type: String,
    pub entity_id: String,
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct NoteResponse {
    pub entity_type: String,
    pub entity_id: String,
    pub note: String,
    pub author: String,
    pub updated_at: i64,
}

/// GET /api/notes?entity_type=event&entity_id=abc123
pub async fn get_note(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    axum::extract::Query(q): axum::extract::Query<GetNoteQuery>,
) -> impl IntoResponse {
    let _ = &user; // accessed for auth only

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct NoteRow {
        note: String,
        author: String,
        updated_at: i64,
    }

    let client = state.db.client();
    let row = client
        .query(
            "SELECT argMax(note, updated_at) AS note, \
                    argMax(author, updated_at) AS author, \
                    max(updated_at) AS updated_at \
             FROM analyst_notes \
             WHERE entity_type = ? AND entity_id = ? \
             GROUP BY entity_type, entity_id",
        )
        .bind(&q.entity_type)
        .bind(&q.entity_id)
        .fetch_optional::<NoteRow>()
        .await;

    match row {
        Ok(Some(r)) => Json(NoteResponse {
            entity_type: q.entity_type,
            entity_id: q.entity_id,
            note: r.note,
            author: r.author,
            updated_at: r.updated_at,
        })
        .into_response(),
        Ok(None) => Json(NoteResponse {
            entity_type: q.entity_type,
            entity_id: q.entity_id,
            note: String::new(),
            author: String::new(),
            updated_at: 0,
        })
        .into_response(),
        Err(e) => {
            tracing::warn!("Failed to fetch note: {:#}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch note").into_response()
        }
    }
}

/// POST /api/notes — save or update a note
pub async fn save_note(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<SaveNoteBody>,
) -> impl IntoResponse {
    #[derive(clickhouse::Row, serde::Serialize)]
    struct NoteInsertRow<'a> {
        entity_id: &'a str,
        entity_type: &'a str,
        note: &'a str,
        author: &'a str,
        updated_at: i64,
    }

    let now = Utc::now().timestamp();
    let row = NoteInsertRow {
        entity_id: &body.entity_id,
        entity_type: &body.entity_type,
        note: &body.note,
        author: &user.username,
        updated_at: now,
    };

    let client = state.db.client();
    let result = async {
        let mut insert = client
            .insert("analyst_notes")
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        insert
            .write(&row)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        insert.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok::<_, anyhow::Error>(())
    }
    .await;

    match result {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => {
            tracing::warn!("Failed to save note: {:#}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save note").into_response()
        }
    }
}
