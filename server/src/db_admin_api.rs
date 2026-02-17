use crate::api_response::api_error;
use crate::auth::{AuthedUser, Role};
use crate::enroll::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::warn;

// ── Table listing ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub engine: String,
    pub total_rows: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct TablesResponse {
    pub database: String,
    pub tables: Vec<TableInfo>,
}

/// GET /api/db/tables
pub async fn api_list_tables(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "authority role required",
        )
        .into_response();
    }

    let db_name = percepta_server::db::clickhouse_db_name();

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct TableRow {
        name: String,
        engine: String,
        total_rows: Option<u64>,
        total_bytes: Option<u64>,
    }

    let result = state
        .db
        .client()
        .query(
            "SELECT name, engine, total_rows, total_bytes \
             FROM system.tables WHERE database = ? \
             ORDER BY name",
        )
        .bind(&db_name)
        .fetch_all::<TableRow>()
        .await;

    match result {
        Ok(rows) => {
            let tables = rows
                .into_iter()
                .map(|r| TableInfo {
                    name: r.name,
                    engine: r.engine,
                    total_rows: r.total_rows.unwrap_or(0),
                    total_bytes: r.total_bytes.unwrap_or(0),
                })
                .collect();
            (
                StatusCode::OK,
                Json(TablesResponse {
                    database: db_name,
                    tables,
                }),
            )
                .into_response()
        }
        Err(e) => {
            warn!("db/tables query failed: {e:#}");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_failed",
                "failed to list tables",
            )
            .into_response()
        }
    }
}

// ── Table schema ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ColumnInfo {
    pub name: String,
    pub r#type: String,
}

#[derive(Debug, Serialize)]
pub struct TableSchemaResponse {
    pub table: String,
    pub columns: Vec<ColumnInfo>,
}

#[derive(Debug, Deserialize)]
pub struct TableNameQuery {
    pub table: String,
}

/// GET /api/db/schema?table=events
pub async fn api_table_schema(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    axum::extract::Query(q): axum::extract::Query<TableNameQuery>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "authority role required",
        )
        .into_response();
    }

    let table = sanitize_identifier(&q.table);
    if table.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_table",
            "table name is required",
        )
        .into_response();
    }

    let db_name = percepta_server::db::clickhouse_db_name();

    #[derive(clickhouse::Row, serde::Deserialize)]
    struct ColRow {
        name: String,
        r#type: String,
    }

    let result = state
        .db
        .client()
        .query(
            "SELECT name, type FROM system.columns WHERE database = ? AND table = ? ORDER BY position",
        )
        .bind(&db_name)
        .bind(&table)
        .fetch_all::<ColRow>()
        .await;

    match result {
        Ok(rows) => {
            let columns = rows
                .into_iter()
                .map(|r| ColumnInfo {
                    name: r.name,
                    r#type: r.r#type,
                })
                .collect();
            (StatusCode::OK, Json(TableSchemaResponse { table, columns })).into_response()
        }
        Err(e) => {
            warn!("db/schema query failed: {e:#}");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "query_failed",
                "failed to query table schema",
            )
            .into_response()
        }
    }
}

// ── Read query ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct QueryRequest {
    pub sql: String,
    #[serde(default = "default_query_limit")]
    pub limit: usize,
}

fn default_query_limit() -> usize {
    200
}

#[derive(Debug, Serialize)]
pub struct QueryResponse {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<serde_json::Value>>,
    pub truncated: bool,
}

/// POST /api/db/query  { "sql": "SELECT ...", "limit": 200 }
/// Only SELECT queries allowed. Authority role required.
pub async fn api_query(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<QueryRequest>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "authority role required",
        )
        .into_response();
    }

    let sql = body.sql.trim().to_string();
    if sql.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_sql",
            "SQL query is required",
        )
        .into_response();
    }

    // Only allow SELECT/SHOW/DESCRIBE for read queries.
    let first_word = sql.split_whitespace().next().unwrap_or("").to_uppercase();
    if !["SELECT", "SHOW", "DESCRIBE", "DESC", "EXISTS", "EXPLAIN"].contains(&first_word.as_str()) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "read_only",
            "only SELECT/SHOW/DESCRIBE queries allowed here; use /api/db/execute for writes",
        )
        .into_response();
    }

    // Reject multi-statement payloads and comment-based bypasses.
    let upper = sql.to_uppercase();
    if sql.contains(';')
        || upper.contains("--")
        || upper.contains("/*")
        || upper.contains("INSERT")
        || upper.contains("UPDATE")
        || upper.contains("DELETE")
        || upper.contains("DROP")
        || upper.contains("ALTER")
        || upper.contains("TRUNCATE")
        || upper.contains("ATTACH")
        || upper.contains("DETACH")
        || upper.contains("GRANT")
        || upper.contains("REVOKE")
        || upper.contains("SYSTEM")
        || upper.contains("KILL")
        || upper.contains("CREATE")
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "blocked",
            "query contains blocked keywords or characters",
        )
        .into_response();
    }

    let limit = body.limit.clamp(1, 10_000);
    // Send the query directly — do not wrap in format!() to avoid injection.
    // Append LIMIT + FORMAT as ClickHouse query settings instead.
    let query_with_limit = format!("{sql}\n LIMIT {limit}\n FORMAT JSONCompact");

    let ch_url = if state.db.url().is_empty() {
        percepta_server::db::db_url_from_env()
            .unwrap_or_else(percepta_server::db::default_local_db_url)
    } else {
        state.db.url().to_string()
    };
    let db_name = if state.db.database().is_empty() {
        percepta_server::db::clickhouse_db_name()
    } else {
        state.db.database().to_string()
    };
    let ch_user = state.db.ch_user().to_string();
    let ch_pass = state.db.ch_password().to_string();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    let mut query_params: Vec<(&str, &str)> = vec![("database", &db_name)];
    if !ch_user.is_empty() {
        query_params.push(("user", &ch_user));
    }
    if !ch_pass.is_empty() {
        query_params.push(("password", &ch_pass));
    }

    let resp = match client
        .post(&ch_url)
        .query(&query_params)
        .body(query_with_limit)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("db/query HTTP error: {e:#}");
            return api_error(
                StatusCode::BAD_GATEWAY,
                "ch_unreachable",
                format!("ClickHouse unreachable: {e}"),
            )
            .into_response();
        }
    };

    if !resp.status().is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        warn!("db/query CH error: {body_text}");
        return api_error(
            StatusCode::BAD_REQUEST,
            "query_error",
            format!("Query failed: {body_text}"),
        )
        .into_response();
    }

    let json_body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            warn!("db/query parse error: {e:#}");
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "parse_error",
                "failed to parse ClickHouse response",
            )
            .into_response();
        }
    };

    // JSONCompact gives {"meta":[{"name":..,"type":..},...], "data":[[v,...],...],"rows":N}
    let columns: Vec<String> = json_body["meta"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m["name"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let data = json_body["data"].as_array();
    let total_rows = data.map(|d| d.len()).unwrap_or(0);
    let truncated = total_rows >= limit;

    let rows: Vec<Vec<serde_json::Value>> = data
        .map(|arr| {
            arr.iter()
                .map(|row| row.as_array().cloned().unwrap_or_default())
                .collect()
        })
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(QueryResponse {
            columns,
            rows,
            truncated,
        }),
    )
        .into_response()
}

// ── Write/execute ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ExecuteRequest {
    pub sql: String,
}

#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    pub ok: bool,
    pub message: String,
}

/// POST /api/db/execute  { "sql": "DELETE FROM events WHERE ..." }
/// Authority role required. Destructive operations allowed.
pub async fn api_execute(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<ExecuteRequest>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "authority role required",
        )
        .into_response();
    }

    let sql = body.sql.trim().to_string();
    if sql.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "empty_sql",
            "SQL statement is required",
        )
        .into_response();
    }

    // Block dangerous DDL that could break the server
    let upper = sql.to_uppercase();
    if upper.contains("DROP DATABASE")
        || upper.contains("DROP ALL")
        || upper.contains("SYSTEM SHUTDOWN")
        || upper.contains("SYSTEM KILL")
        || upper.contains("SYSTEM RELOAD")
        || upper.contains("ATTACH")
        || upper.contains("DETACH")
        || upper.contains("GRANT")
        || upper.contains("REVOKE")
        || upper.contains("CREATE USER")
        || upper.contains("DROP USER")
        || upper.contains("CREATE ROLE")
        || upper.contains("DROP ROLE")
    {
        return api_error(
            StatusCode::BAD_REQUEST,
            "blocked",
            "this statement is blocked for safety",
        )
        .into_response();
    }

    // Reject multi-statement payloads
    if sql.contains(';') {
        return api_error(
            StatusCode::BAD_REQUEST,
            "blocked",
            "multi-statement queries are not allowed",
        )
        .into_response();
    }

    let result = state.db.client().query(&sql).execute().await;

    match result {
        Ok(()) => (
            StatusCode::OK,
            Json(ExecuteResponse {
                ok: true,
                message: "Statement executed successfully.".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            warn!("db/execute failed: {e:#}");
            api_error(
                StatusCode::BAD_REQUEST,
                "execute_error",
                format!("Execution failed: {e}"),
            )
            .into_response()
        }
    }
}

// ── Truncate table ─────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct TruncateRequest {
    pub table: String,
}

/// POST /api/db/truncate  { "table": "events" }
pub async fn api_truncate_table(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<TruncateRequest>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return api_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "authority role required",
        )
        .into_response();
    }

    let table = sanitize_identifier(&body.table);
    if table.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "invalid_table",
            "table name is required",
        )
        .into_response();
    }

    let sql = format!("TRUNCATE TABLE {table}");
    let result = state.db.client().query(&sql).execute().await;

    match result {
        Ok(()) => (
            StatusCode::OK,
            Json(ExecuteResponse {
                ok: true,
                message: format!("Table '{table}' truncated."),
            }),
        )
            .into_response(),
        Err(e) => {
            warn!("db/truncate failed: {e:#}");
            api_error(
                StatusCode::BAD_REQUEST,
                "truncate_error",
                format!("Truncate failed: {e}"),
            )
            .into_response()
        }
    }
}

/// Sanitize a table/identifier name — only allow alphanumeric + underscores.
fn sanitize_identifier(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if cleaned.is_empty() || cleaned.len() > 128 {
        return String::new();
    }
    cleaned
}
