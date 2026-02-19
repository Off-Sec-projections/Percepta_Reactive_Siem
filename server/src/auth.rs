use crate::enroll::AppState;
use axum::extract::{Form, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

const SESSION_COOKIE: &str = "percepta_session";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Analyst,
    Authority,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub analyst_user: String,
    pub analyst_pass: String,
    pub admin_user: String,
    pub admin_pass: String,
}

impl AuthConfig {
    pub fn from_env_demo_defaults() -> Self {
        // Demo defaults (override via env vars):
        // - Analyst ("/login"): admin / Pass
        // - Authority ("/adminlogin"): soc / Pass
        let analyst_user =
            std::env::var("PERCEPTA_ANALYST_USER").unwrap_or_else(|_| "admin".to_string());
        let analyst_pass = std::env::var("PERCEPTA_ANALYST_PASS").unwrap_or_else(|_| "Pass".to_string());
        let admin_user = std::env::var("PERCEPTA_ADMIN_USER").unwrap_or_else(|_| "soc".to_string());
        let admin_pass = std::env::var("PERCEPTA_ADMIN_PASS").unwrap_or_else(|_| "Pass".to_string());

        if std::env::var("PERCEPTA_ANALYST_USER").is_err()
            || std::env::var("PERCEPTA_ANALYST_PASS").is_err()
            || std::env::var("PERCEPTA_ADMIN_USER").is_err()
            || std::env::var("PERCEPTA_ADMIN_PASS").is_err()
        {
            warn!(
                "Demo auth defaults are active (Analyst: admin/Pass, Authority: soc/Pass). Set PERCEPTA_ANALYST_USER/PASS and PERCEPTA_ADMIN_USER/PASS to override."
            );
        }

        Self {
            analyst_user,
            analyst_pass,
            admin_user,
            admin_pass,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthedUser {
    pub username: String,
    pub role: Role,
}

#[derive(Debug, Clone)]
pub(crate) struct Session {
    user: AuthedUser,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EscalationStatus {
    Open,
    Approved,
    Rejected,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Escalation {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub title: String,
    pub event_hash: Option<String>,
    pub description: String,
    pub status: EscalationStatus,
    pub decision_by: Option<String>,
    pub decision_at: Option<DateTime<Utc>>,
    pub decision_note: Option<String>,
}

pub type SessionStore = Arc<RwLock<HashMap<String, Session>>>;
pub type EscalationStore = Arc<RwLock<Vec<Escalation>>>;

pub fn init_session_store() -> SessionStore {
    Arc::new(RwLock::new(HashMap::new()))
}

pub fn init_escalation_store() -> EscalationStore {
    Arc::new(RwLock::new(Vec::new()))
}

fn parse_cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{}=", SESSION_COOKIE)) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn set_cookie_header(token: &str, max_age_secs: i64) -> String {
    // Demo-grade cookie. If you put this behind HTTPS, consider adding `Secure`.
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_COOKIE, token, max_age_secs
    )
}

fn clear_cookie_header() -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        SESSION_COOKIE
    )
}

fn login_html(title: &str, post_to: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; }}
    .wrap {{ min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px; }}
    .card {{ width:100%; max-width:420px; background:#111827; border:1px solid #1f2937; border-radius:12px; padding:22px; }}
    h1 {{ margin:0 0 12px 0; font-size:20px; }}
    label {{ display:block; font-size:13px; margin:12px 0 6px; color:#cbd5e1; }}
    input {{ width:100%; padding:10px 12px; border-radius:10px; border:1px solid #334155; background:#0b1220; color:#e2e8f0; }}
    button {{ width:100%; margin-top:14px; padding:10px 12px; border-radius:10px; border:0; background:#2563eb; color:white; font-weight:700; cursor:pointer; }}
    .hint {{ margin-top:12px; font-size:12px; color:#94a3b8; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>{title}</h1>
      <form method="post" action="{post_to}">
        <label>Username</label>
        <input name="username" autocomplete="username" />
        <label>Password</label>
        <input name="password" type="password" autocomplete="current-password" />
        <button type="submit">Login</button>
      </form>
                        <div class="hint">Single login. Role is selected by which credentials match. Demo defaults: Analyst = admin/Pass, Authority = soc/Pass. Override via PERCEPTA_ANALYST_USER/PASS and PERCEPTA_ADMIN_USER/PASS.</div>
    </div>
  </div>
</body>
</html>"#
    )
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

fn new_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn want_html(req: &axum::http::Request<axum::body::Body>) -> bool {
    req.headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false)
}

fn want_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

fn login_redirect_for(req: &axum::http::Request<axum::body::Body>) -> &'static str {
    let _path = req.uri().path();
    // Single login entrypoint: role is decided after password check.
    "/login"
}

/// Middleware: requires a valid session cookie and injects `AuthedUser` into request extensions.
pub async fn require_session(
    State(state): State<AppState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = match parse_cookie_token(req.headers()) {
        Some(t) => t,
        None => {
            if want_html(&req) {
                return Ok(Redirect::temporary(login_redirect_for(&req)).into_response());
            }
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let now = Utc::now();
    let session = {
        let sessions = state.sessions.read().await;
        sessions.get(&token).cloned()
    };

    let Some(session) = session else {
        if want_html(&req) {
            return Ok(Redirect::temporary(login_redirect_for(&req)).into_response());
        }
        return Err(StatusCode::UNAUTHORIZED);
    };

    if session.expires_at <= now {
        // Best-effort cleanup.
        state.sessions.write().await.remove(&token);
        if want_html(&req) {
            return Ok(Redirect::temporary(login_redirect_for(&req)).into_response());
        }
        return Err(StatusCode::UNAUTHORIZED);
    }

    req.extensions_mut().insert(session.user);
    Ok(next.run(req).await)
}

pub async fn login_page() -> Html<String> {
    Html(login_html("Login", "/login"))
}

pub async fn adminlogin_page() -> Html<String> {
    // Backward compatible alias: serve the same login page.
    Html(login_html("Login", "/login"))
}

pub async fn login_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Response {
    let is_authority = form.username == state.auth_config.admin_user
        && form.password == state.auth_config.admin_pass;
    let is_analyst = form.username == state.auth_config.analyst_user
        && form.password == state.auth_config.analyst_pass;

    if is_authority || is_analyst {
        let role = if is_authority { Role::Authority } else { Role::Analyst };
        let token = new_token();
        let expires_at = Utc::now() + Duration::hours(12);
        state.sessions.write().await.insert(
            token.clone(),
            Session {
                user: AuthedUser {
                    username: form.username,
                    role,
                },
                expires_at,
            },
        );

        let mut response = Redirect::to("/dashboard").into_response();
        response.headers_mut().insert(
            header::SET_COOKIE,
            set_cookie_header(&token, 12 * 60 * 60).parse().unwrap(),
        );
        return response;
    }

    (StatusCode::UNAUTHORIZED, Html(login_html("Login (invalid)", "/login"))).into_response()
}

pub async fn adminlogin_submit(
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> Response {
    // Backward compatible alias: submit handler is identical.
    login_submit(State(state), Form(form)).await
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = parse_cookie_token(&headers) {
        state.sessions.write().await.remove(&token);
    }

    let mut response = Redirect::to("/dashboard").into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_cookie_header().parse().unwrap());
    response
}

#[derive(Debug, Serialize)]
pub struct WhoAmIResponse {
    pub authenticated: bool,
    pub username: Option<String>,
    pub role: Option<Role>,
}

pub async fn whoami(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let token = match parse_cookie_token(&headers) {
        Some(t) => t,
        None => {
            return Json(WhoAmIResponse {
                authenticated: false,
                username: None,
                role: None,
            });
        }
    };

    let sessions = state.sessions.read().await;
    let session = match sessions.get(&token) {
        Some(s) => s,
        None => {
            return Json(WhoAmIResponse {
                authenticated: false,
                username: None,
                role: None,
            });
        }
    };

    // Expiration is enforced by middleware for protected routes; for the UI we treat
    // expired sessions as unauthenticated.
    if Utc::now() > session.expires_at {
        return Json(WhoAmIResponse {
            authenticated: false,
            username: None,
            role: None,
        });
    }

    Json(WhoAmIResponse {
        authenticated: true,
        username: Some(session.user.username.clone()),
        role: Some(session.user.role),
    })
}

pub async fn serve_analyst_page(
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> Response {
    if user.role != Role::Analyst {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let html = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Analyst</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background:#0b1220; color:#e5e7eb; margin:0; }}
    .top {{ padding:14px 18px; background:#0f172a; border-bottom:1px solid #1f2937; display:flex; justify-content:space-between; }}
    .wrap {{ padding:18px; max-width:900px; margin:0 auto; }}
    .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px; padding:16px; }}
    label {{ display:block; font-size:13px; margin:10px 0 6px; color:#cbd5e1; }}
    input, textarea {{ width:100%; padding:10px 12px; border-radius:10px; border:1px solid #334155; background:#0b1220; color:#e2e8f0; }}
    textarea {{ min-height:90px; }}
    button {{ margin-top:12px; padding:10px 12px; border-radius:10px; border:0; background:#22c55e; color:#052e16; font-weight:800; cursor:pointer; }}
    a {{ color:#60a5fa; text-decoration:none; }}
  </style>
</head>
<body>
  <div class="top">
    <div>Analyst: {username}</div>
    <div>
      <a href="/dashboard">Dashboard</a> · <a href="/logout">Logout</a>
    </div>
  </div>
  <div class="wrap">
    <div class="card">
      <h2 style="margin:0 0 8px 0;">Escalate to Authority</h2>
      <form method="post" action="/api/escalations">
        <label>Title</label>
        <input name="title" required />
        <label>Event hash (optional)</label>
        <input name="event_hash" />
        <label>Description</label>
        <textarea name="description" required></textarea>
        <button type="submit">Submit Escalation</button>
      </form>
      <p style="margin:12px 0 0; color:#94a3b8; font-size:12px;">Authority will review at /authority (requires /adminlogin).</p>
    </div>
  </div>
</body>
</html>"#
        .replace("{username}", &html_escape(&user.username));

    Html(html).into_response()
}

pub async fn serve_authority_page(
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> Response {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let html = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Authority</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; background:#0b1220; color:#e5e7eb; margin:0; }}
    .top {{ padding:14px 18px; background:#0f172a; border-bottom:1px solid #1f2937; display:flex; justify-content:space-between; }}
    .wrap {{ padding:18px; max-width:1100px; margin:0 auto; }}
    table {{ width:100%; border-collapse:collapse; background:#111827; border:1px solid #1f2937; border-radius:12px; overflow:hidden; }}
    th, td {{ padding:10px 12px; border-bottom:1px solid #1f2937; vertical-align:top; }}
    th {{ text-align:left; color:#cbd5e1; background:#0f172a; position:sticky; top:0; }}
    .actions button {{ margin-right:8px; padding:6px 10px; border-radius:10px; border:0; cursor:pointer; font-weight:700; }}
    .ok {{ background:#22c55e; color:#052e16; }}
    .bad {{ background:#ef4444; color:#450a0a; }}
    .neutral {{ background:#eab308; color:#422006; }}
    a {{ color:#60a5fa; text-decoration:none; }}
  </style>
</head>
<body>
  <div class="top">
    <div>Authority: {username}</div>
    <div>
      <a href="/dashboard">Dashboard</a> · <a href="/logout">Logout</a>
    </div>
  </div>
  <div class="wrap">
    <h2 style="margin:0 0 12px 0;">Escalations</h2>
    <table>
      <thead>
        <tr>
          <th>Created</th><th>By</th><th>Title</th><th>Event</th><th>Description</th><th>Status</th><th>Actions</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>

        <h2 style="margin:18px 0 12px 0;">Certificate Renewals</h2>
        <table>
            <thead>
                <tr>
                    <th>Created</th><th>Agent</th><th>MAC</th><th>First user</th><th>Status</th><th>Actions</th>
                </tr>
            </thead>
            <tbody id="renewalRows"></tbody>
        </table>
  </div>

<script>
async function load() {{
  const res = await fetch('/api/escalations', {{ headers: {{ 'Accept': 'application/json' }} }});
  if (!res.ok) return;
  const data = await res.json();
  const rows = document.getElementById('rows');
  rows.innerHTML = '';
  for (const e of data.escalations) {{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${new Date(e.created_at).toLocaleString()}</td>
      <td>${e.created_by}</td>
      <td>${e.title}</td>
      <td>${e.event_hash || ''}</td>
      <td style="white-space:pre-wrap; max-width:420px;">${e.description}</td>
      <td>${e.status}</td>
      <td class="actions">
        <button class="ok" onclick="decide('${e.id}','approve')">Approve</button>
        <button class="bad" onclick="decide('${e.id}','reject')">Reject</button>
        <button class="neutral" onclick="decide('${e.id}','close')">Close</button>
      </td>`;
    rows.appendChild(tr);
  }}
}}

async function loadRenewals() {{
    const res = await fetch('/api/renew/requests', {{ headers: {{ 'Accept': 'application/json' }} }});
    if (!res.ok) return;
    const data = await res.json();
    const rows = document.getElementById('renewalRows');
    rows.innerHTML = '';
    for (const r of (data.requests || [])) {{
        const tr = document.createElement('tr');
        const created = new Date((r.created_at_unix || 0) * 1000).toLocaleString();
        const status = r.status || '';
        const approveBtn = status === 'pending'
            ? `<button class="ok" onclick="approveRenewal('${r.id}')">Approve</button>`
            : '';
        tr.innerHTML = `
            <td>${created}</td>
            <td>${r.agent_id || ''}</td>
            <td>${r.primary_mac || ''}</td>
            <td>${r.first_user || ''}</td>
            <td>${status}</td>
            <td class="actions">${approveBtn}</td>`;
        rows.appendChild(tr);
    }}
}}

async function approveRenewal(id) {{
    const res = await fetch('/api/renew/approve', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ request_id: id }})
    }});
    if (res.ok) loadRenewals();
}}

async function decide(id, action) {{
  const form = new URLSearchParams();
  form.set('action', action);
  const res = await fetch(`/api/escalations/${id}/decision`, {{ method:'POST', body: form }});
  if (res.ok) load();
}}

load();
loadRenewals();
setInterval(load, 3000);
setInterval(loadRenewals, 3000);
</script>
</body>
</html>"#
        .replace("{username}", &html_escape(&user.username));

    Html(html).into_response()
}

#[derive(Deserialize)]
pub struct CreateEscalationForm {
    pub title: String,
    pub event_hash: Option<String>,
    pub description: String,
}

pub async fn create_escalation(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    headers: HeaderMap,
    Form(form): Form<CreateEscalationForm>,
) -> impl IntoResponse {
    // Demo-friendly: both Analyst and Authority may create escalations.
    // Authority still remains the only role allowed to approve/reject/close.
    if user.role != Role::Analyst && user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let escalation = Escalation {
        id: uuid::Uuid::new_v4().to_string(),
        created_at: Utc::now(),
        created_by: user.username,
        title: form.title,
        event_hash: form.event_hash.filter(|s| !s.trim().is_empty()),
        description: form.description,
        status: EscalationStatus::Open,
        decision_by: None,
        decision_at: None,
        decision_note: None,
    };

    let id = escalation.id.clone();
    state.escalations.write().await.push(escalation);

    if want_json(&headers) {
        return (
            StatusCode::CREATED,
            Json(serde_json::json!({ "ok": true, "id": id })),
        )
            .into_response();
    }

    // Keep existing browser behavior.
    if user.role == Role::Authority {
        Redirect::temporary("/authority").into_response()
    } else {
        Redirect::temporary("/analyst").into_response()
    }
}

#[derive(Serialize)]
pub struct EscalationsResponse {
    pub escalations: Vec<Escalation>,
}

pub async fn list_escalations(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let escalations = state.escalations.read().await.clone();
    Json(EscalationsResponse { escalations }).into_response()
}

#[derive(Deserialize)]
pub struct DecideForm {
    pub action: String,
}

pub async fn decide_escalation(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Path(id): Path<String>,
    Form(form): Form<DecideForm>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let mut escalations = state.escalations.write().await;
    let Some(item) = escalations.iter_mut().find(|e| e.id == id) else {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    };

    match form.action.as_str() {
        "approve" => item.status = EscalationStatus::Approved,
        "reject" => item.status = EscalationStatus::Rejected,
        "close" => item.status = EscalationStatus::Closed,
        _ => return (StatusCode::BAD_REQUEST, "Invalid action").into_response(),
    }

    item.decision_by = Some(user.username);
    item.decision_at = Some(Utc::now());

    (StatusCode::OK, "ok").into_response()
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
