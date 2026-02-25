//! Webhook Subscription System & API Key Authentication.
//!
//! - API key authentication for automation/integrations
//! - Webhook subscriptions for alert/case/compliance events
//! - Rate limiting per API key
//! - Async webhook delivery with retry

use crate::db::Db;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

// ── API Key Model ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyEntry {
    pub id: String,
    pub name: String,
    pub key_hash: String,
    pub prefix: String,  // First 8 chars for display
    pub role_id: String, // Maps to RBAC role
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rate_limit_per_min: u32,
    pub request_count: u64,
}

// ── Webhook Subscription ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: Vec<WebhookEvent>,
    pub enabled: bool,
    pub secret: String, // HMAC-SHA256 signature secret
    pub created_at: DateTime<Utc>,
    pub last_delivery: Option<DateTime<Utc>>,
    pub delivery_count: u64,
    pub failure_count: u64,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEvent {
    AlertCreated,
    AlertUpdated,
    AlertResolved,
    CaseCreated,
    CaseUpdated,
    CaseClosed,
    ComplianceViolation,
    DlpViolation,
    PlaybookExecuted,
    AgentConnected,
    AgentDisconnected,
    HealthDegraded,
}

// ── Stores ───────────────────────────────────────────────────────────────

pub type ApiKeyStoreHandle = Arc<RwLock<ApiKeyStore>>;
pub type WebhookStoreHandle = Arc<RwLock<WebhookStore>>;

pub struct ApiKeyStore {
    pub keys: HashMap<String, ApiKeyEntry>,    // key_hash -> entry
    pub prefix_index: HashMap<String, String>, // prefix -> key_hash
}

impl ApiKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            prefix_index: HashMap::new(),
        }
    }

    /// Generate a new API key. Returns the raw key (only shown once).
    pub fn create_key(
        &mut self,
        name: String,
        role_id: String,
        rate_limit_per_min: u32,
        expires_hours: Option<i64>,
    ) -> String {
        let raw_key = format!("psk_{}", generate_random_key(32));
        let prefix = raw_key[..12].to_string();
        let key_hash = hash_key(&raw_key);

        let entry = ApiKeyEntry {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            key_hash: key_hash.clone(),
            prefix: prefix.clone(),
            role_id,
            enabled: true,
            created_at: Utc::now(),
            last_used: None,
            expires_at: expires_hours.map(|h| Utc::now() + chrono::Duration::hours(h)),
            rate_limit_per_min: rate_limit_per_min.max(10),
            request_count: 0,
        };

        self.prefix_index.insert(prefix, key_hash.clone());
        self.keys.insert(key_hash, entry);
        raw_key
    }

    /// Validate an API key. Returns the entry if valid.
    #[allow(dead_code)]
    pub fn validate_key(&mut self, raw_key: &str) -> Option<&ApiKeyEntry> {
        let key_hash = hash_key(raw_key);
        if let Some(entry) = self.keys.get_mut(&key_hash) {
            if !entry.enabled {
                return None;
            }
            if let Some(expires) = entry.expires_at {
                if Utc::now() > expires {
                    return None;
                }
            }
            entry.last_used = Some(Utc::now());
            entry.request_count += 1;
            Some(entry)
        } else {
            None
        }
    }

    pub fn revoke_key(&mut self, id: &str) -> bool {
        if let Some(entry) = self.keys.values_mut().find(|e| e.id == id) {
            entry.enabled = false;
            true
        } else {
            false
        }
    }

    pub fn list_keys(&self) -> Vec<&ApiKeyEntry> {
        self.keys.values().collect()
    }
}

pub struct WebhookStore {
    pub subscriptions: Vec<WebhookSubscription>,
}

impl WebhookStore {
    pub fn new() -> Self {
        Self {
            subscriptions: Vec::new(),
        }
    }

    pub fn add(&mut self, sub: WebhookSubscription) {
        self.subscriptions.push(sub);
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let len = self.subscriptions.len();
        self.subscriptions.retain(|s| s.id != id);
        self.subscriptions.len() < len
    }

    pub fn get_subscribers(&self, event: &WebhookEvent) -> Vec<&WebhookSubscription> {
        self.subscriptions
            .iter()
            .filter(|s| {
                s.enabled
                    && s.events
                        .iter()
                        .any(|e| std::mem::discriminant(e) == std::mem::discriminant(event))
            })
            .collect()
    }
}

/// Dispatch webhook for an event.
pub async fn dispatch_webhook(
    webhook_store: &WebhookStoreHandle,
    event: WebhookEvent,
    payload: serde_json::Value,
) {
    let subscribers = {
        let store = webhook_store.read().await;
        store
            .get_subscribers(&event)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    };

    for sub in subscribers {
        let url = sub.url.clone();
        let secret = sub.secret.clone();
        let headers = sub.headers.clone();
        let payload = payload.clone();
        let event_name = format!("{:?}", event);

        // Validate URL safety (SSRF protection)
        if !is_safe_webhook_url(&url) {
            warn!("Webhook: Blocked unsafe URL: {}", url);
            continue;
        }

        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default();

            let body = serde_json::json!({
                "event": event_name,
                "timestamp": Utc::now().to_rfc3339(),
                "data": payload,
            });

            let body_str = serde_json::to_string(&body).unwrap_or_default();

            // Compute HMAC signature
            let signature = compute_hmac(&secret, &body_str);

            let mut req = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-Percepta-Signature", &signature)
                .header("X-Percepta-Event", &event_name);

            for (k, v) in &headers {
                req = req.header(k.as_str(), v.as_str());
            }

            match req.body(body_str).send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        warn!("Webhook delivery failed to {}: HTTP {}", url, resp.status());
                    }
                }
                Err(e) => warn!("Webhook delivery error to {}: {}", url, e),
            }
        });
    }
}

/// SSRF protection — delegate to the comprehensive implementation in playbooks.rs
/// which uses proper `std::net::IpAddr` parsing for private/reserved range checks.
fn is_safe_webhook_url(url: &str) -> bool {
    crate::playbooks::is_safe_webhook_url(url)
}

fn generate_random_key(len: usize) -> String {
    use rand::{rngs::OsRng, Rng};
    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| charset[OsRng.gen_range(0..charset.len())] as char)
        .collect()
}

fn hash_key(key: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"percepta_apikey_v1:");
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

fn compute_hmac(secret: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body.as_bytes());
    let result = mac.finalize();
    format!("sha256={}", hex::encode(result.into_bytes()))
}

pub fn init_api_key_store() -> ApiKeyStoreHandle {
    Arc::new(RwLock::new(ApiKeyStore::new()))
}

pub fn init_webhook_store() -> WebhookStoreHandle {
    Arc::new(RwLock::new(WebhookStore::new()))
}

// ── ClickHouse Persistence ───────────────────────────────────────────────

/// Persist an API key entry to ClickHouse.
pub async fn persist_api_key(db: &Db, entry: &ApiKeyEntry) {
    #[derive(clickhouse::Row, serde::Serialize)]
    struct Row {
        id: String,
        name: String,
        key_hash: String,
        prefix: String,
        role_id: String,
        enabled: u8,
        created_at: i64,
        expires_at: i64,
        updated_at: i64,
    }
    let row = Row {
        id: entry.id.clone(),
        name: entry.name.clone(),
        key_hash: entry.key_hash.clone(),
        prefix: entry.prefix.clone(),
        role_id: entry.role_id.clone(),
        enabled: if entry.enabled { 1 } else { 0 },
        created_at: entry.created_at.timestamp(),
        expires_at: entry.expires_at.map(|d| d.timestamp()).unwrap_or(0),
        updated_at: Utc::now().timestamp(),
    };
    if let Err(e) = db
        .retry_insert("persist_api_key", |cl| {
            let r = Row {
                id: row.id.clone(),
                name: row.name.clone(),
                key_hash: row.key_hash.clone(),
                prefix: row.prefix.clone(),
                role_id: row.role_id.clone(),
                enabled: row.enabled,
                created_at: row.created_at,
                expires_at: row.expires_at,
                updated_at: row.updated_at,
            };
            async move {
                let mut ins = cl
                    .insert("api_keys")
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.write(&r).await.map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
                Ok(())
            }
        })
        .await
    {
        warn!("Failed to persist API key '{}': {:#}", entry.name, e);
    }
}

/// Persist a webhook subscription to ClickHouse.
pub async fn persist_webhook(db: &Db, sub: &WebhookSubscription) {
    #[derive(clickhouse::Row, serde::Serialize)]
    struct Row {
        id: String,
        name: String,
        url: String,
        events: String,
        enabled: u8,
        secret: String,
        headers: String,
        created_at: i64,
        updated_at: i64,
    }
    let events_json = serde_json::to_string(&sub.events).unwrap_or_default();
    let headers_json = serde_json::to_string(&sub.headers).unwrap_or_default();
    let row = Row {
        id: sub.id.clone(),
        name: sub.name.clone(),
        url: sub.url.clone(),
        events: events_json,
        enabled: if sub.enabled { 1 } else { 0 },
        secret: sub.secret.clone(),
        headers: headers_json,
        created_at: sub.created_at.timestamp(),
        updated_at: Utc::now().timestamp(),
    };
    if let Err(e) = db
        .retry_insert("persist_webhook", |cl| {
            let r = Row {
                id: row.id.clone(),
                name: row.name.clone(),
                url: row.url.clone(),
                events: row.events.clone(),
                enabled: row.enabled,
                secret: row.secret.clone(),
                headers: row.headers.clone(),
                created_at: row.created_at,
                updated_at: row.updated_at,
            };
            async move {
                let mut ins = cl
                    .insert("webhooks")
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.write(&r).await.map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
                Ok(())
            }
        })
        .await
    {
        warn!("Failed to persist webhook '{}': {:#}", sub.name, e);
    }
}

/// Load API keys from ClickHouse on startup.
pub async fn load_api_keys_from_ch(db: &Db, store: &ApiKeyStoreHandle) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        id: String,
        name: String,
        key_hash: String,
        prefix: String,
        role_id: String,
        enabled: u8,
        created_at: i64,
        expires_at: i64,
    }
    let rows = match db.client()
        .query("SELECT id, argMax(name, updated_at) AS name, \
                argMax(key_hash, updated_at) AS key_hash, argMax(prefix, updated_at) AS prefix, \
                argMax(role_id, updated_at) AS role_id, argMax(enabled, updated_at) AS enabled, \
                argMax(created_at, updated_at) AS created_at, argMax(expires_at, updated_at) AS expires_at \
                FROM api_keys GROUP BY id")
        .fetch_all::<Row>().await
    {
        Ok(r) => r,
        Err(e) => { warn!("Failed to load API keys from ClickHouse: {:#}", e); return; }
    };
    if rows.is_empty() {
        return;
    }
    let mut s = store.write().await;
    for r in &rows {
        let entry = ApiKeyEntry {
            id: r.id.clone(),
            name: r.name.clone(),
            key_hash: r.key_hash.clone(),
            prefix: r.prefix.clone(),
            role_id: r.role_id.clone(),
            enabled: r.enabled != 0,
            created_at: DateTime::from_timestamp(r.created_at, 0)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            last_used: None,
            request_count: 0,
            expires_at: if r.expires_at == 0 {
                None
            } else {
                DateTime::from_timestamp(r.expires_at, 0).map(|d| d.with_timezone(&Utc))
            },
            rate_limit_per_min: 60,
        };
        s.prefix_index
            .insert(entry.prefix.clone(), entry.key_hash.clone());
        s.keys.insert(entry.key_hash.clone(), entry);
    }
    tracing::info!("Loaded {} API keys from ClickHouse", rows.len());
}

/// Load webhook subscriptions from ClickHouse on startup.
pub async fn load_webhooks_from_ch(db: &Db, store: &WebhookStoreHandle) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        id: String,
        name: String,
        url: String,
        events: String,
        enabled: u8,
        secret: String,
        headers: String,
        created_at: i64,
    }
    let rows = match db.client()
        .query("SELECT id, argMax(name, updated_at) AS name, \
                argMax(url, updated_at) AS url, argMax(events, updated_at) AS events, \
                argMax(enabled, updated_at) AS enabled, argMax(secret, updated_at) AS secret, \
                argMax(headers, updated_at) AS headers, argMax(created_at, updated_at) AS created_at \
                FROM webhooks GROUP BY id")
        .fetch_all::<Row>().await
    {
        Ok(r) => r,
        Err(e) => { warn!("Failed to load webhooks from ClickHouse: {:#}", e); return; }
    };
    if rows.is_empty() {
        return;
    }
    let mut s = store.write().await;
    for r in &rows {
        let events: Vec<WebhookEvent> = serde_json::from_str(&r.events).unwrap_or_default();
        let headers: HashMap<String, String> = serde_json::from_str(&r.headers).unwrap_or_default();
        s.subscriptions.push(WebhookSubscription {
            id: r.id.clone(),
            name: r.name.clone(),
            url: r.url.clone(),
            events,
            enabled: r.enabled != 0,
            secret: r.secret.clone(),
            created_at: DateTime::from_timestamp(r.created_at, 0)
                .map(|d| d.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            last_delivery: None,
            delivery_count: 0,
            failure_count: 0,
            headers,
        });
    }
    tracing::info!("Loaded {} webhooks from ClickHouse", rows.len());
}

// ── API Handlers ─────────────────────────────────────────────────────────

use crate::enroll::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

/// GET /api/api_keys — list API keys (hides actual key values).
pub async fn api_list_api_keys(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.api_key_store.read().await;
    let keys: Vec<serde_json::Value> = store
        .list_keys()
        .iter()
        .map(|k| {
            serde_json::json!({
                "id": k.id,
                "name": k.name,
                "prefix": k.prefix,
                "role_id": k.role_id,
                "enabled": k.enabled,
                "created_at": k.created_at,
                "last_used": k.last_used,
                "expires_at": k.expires_at,
                "request_count": k.request_count,
            })
        })
        .collect();
    Json(serde_json::json!({ "api_keys": keys }))
}

/// POST /api/api_keys — create a new API key. Returns the raw key once.
pub async fn api_create_api_key(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("Unnamed Key")
        .to_string();
    let role_id = body
        .get("role_id")
        .and_then(|v| v.as_str())
        .unwrap_or("analyst")
        .to_string();
    let rate_limit = body
        .get("rate_limit_per_min")
        .and_then(|v| v.as_u64())
        .unwrap_or(60) as u32;
    let expires_hours = body.get("expires_hours").and_then(|v| v.as_i64());

    let mut store = state.api_key_store.write().await;
    let raw_key = store.create_key(name, role_id, rate_limit, expires_hours);
    // Find the entry we just created and persist it
    let key_hash = hash_key(&raw_key);
    let entry = store.keys.get(&key_hash).cloned();
    drop(store);
    if let Some(e) = entry {
        persist_api_key(&state.db, &e).await;
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "api_key": raw_key,
            "note": "Save this key securely — it will not be shown again."
        })),
    )
        .into_response()
}

/// POST /api/api_keys/revoke — revoke an API key by ID.
pub async fn api_revoke_api_key(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let mut store = state.api_key_store.write().await;
    if store.revoke_key(id) {
        let entry = store.keys.values().find(|e| e.id == id).cloned();
        drop(store);
        if let Some(e) = entry {
            persist_api_key(&state.db, &e).await;
        }
        Json(serde_json::json!({"status": "revoked"})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "API key not found"})),
        )
            .into_response()
    }
}

/// GET /api/webhooks — list webhook subscriptions.
pub async fn api_list_webhooks(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.webhook_store.read().await;
    Json(serde_json::json!({ "webhooks": store.subscriptions }))
}

/// POST /api/webhooks — create a webhook subscription.
pub async fn api_create_webhook(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let url = body
        .get("url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if url.is_empty() || !is_safe_webhook_url(&url) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid or unsafe webhook URL. Must be HTTPS."})),
        )
            .into_response();
    }

    let events: Vec<WebhookEvent> = body
        .get("events")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_else(|| vec![WebhookEvent::AlertCreated]);

    let sub = WebhookSubscription {
        id: uuid::Uuid::new_v4().to_string(),
        name: body
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("Webhook")
            .into(),
        url,
        events,
        enabled: true,
        secret: generate_random_key(32),
        created_at: Utc::now(),
        last_delivery: None,
        delivery_count: 0,
        failure_count: 0,
        headers: HashMap::new(),
    };

    let id = sub.id.clone();
    let secret = sub.secret.clone();
    let sub_clone = sub.clone();
    let mut store = state.webhook_store.write().await;
    store.add(sub);
    drop(store);
    persist_webhook(&state.db, &sub_clone).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "secret": secret,
            "note": "Use this secret to verify webhook signatures (X-Percepta-Signature header)."
        })),
    )
        .into_response()
}

/// POST /api/webhooks/remove — remove a webhook subscription.
pub async fn api_remove_webhook(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let mut store = state.webhook_store.write().await;
    if store.remove(id) {
        Json(serde_json::json!({"status": "removed"})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Webhook not found"})),
        )
            .into_response()
    }
}
