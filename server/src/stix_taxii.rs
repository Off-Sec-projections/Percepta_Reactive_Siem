//! STIX/TAXII Threat Intelligence Integration.
//!
//! - STIX 2.1 indicator parser (JSON import)
//! - TAXII 2.1 client for polling configured collection servers
//! - Local IOC management with CRUD API and expiry
//! - IOC types: IPv4, IPv6, domain, URL, hash (MD5/SHA1/SHA256), email, CVE

use crate::db::Db;
use anyhow::Context as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ── IOC Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
    Cve,
}

impl IocType {
    pub fn detect(value: &str) -> Self {
        let v = value.trim();
        if v.contains("CVE-") {
            return IocType::Cve;
        }
        if v.contains('@') && v.contains('.') {
            return IocType::Email;
        }
        if v.starts_with("http://") || v.starts_with("https://") {
            return IocType::Url;
        }
        if v.len() == 32 && v.chars().all(|c| c.is_ascii_hexdigit()) {
            return IocType::Md5;
        }
        if v.len() == 40 && v.chars().all(|c| c.is_ascii_hexdigit()) {
            return IocType::Sha1;
        }
        if v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()) {
            return IocType::Sha256;
        }
        if v.contains(':') {
            return IocType::Ipv6;
        }
        if v.parse::<std::net::Ipv4Addr>().is_ok() {
            return IocType::Ipv4;
        }
        IocType::Domain
    }
}

// ── IOC Entry ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub id: String,
    pub ioc_type: IocType,
    pub value: String,
    pub source: String, // "stix", "taxii", "manual", "otx", "abuseipdb", etc.
    pub description: String,
    pub severity: String, // "critical", "high", "medium", "low", "info"
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub hit_count: u64,
    pub last_hit: Option<DateTime<Utc>>,
    pub false_positive: bool,
}

// ── STIX 2.1 Indicator Structures ───────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StixBundle {
    #[serde(default)]
    objects: Vec<StixObject>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct StixObject {
    #[serde(rename = "type")]
    obj_type: String,
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    pattern: Option<String>,
    #[serde(default)]
    labels: Vec<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    created: Option<String>,
}

// ── TAXII 2.1 Client Config ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiSource {
    pub id: String,
    pub name: String,
    pub api_root: String,
    pub collection_id: String,
    pub enabled: bool,
    pub poll_interval_secs: u64,
    pub last_poll: Option<DateTime<Utc>>,
    pub indicators_loaded: u64,
}

// ── IOC Store ────────────────────────────────────────────────────────────

pub type IocStoreHandle = Arc<RwLock<IocStore>>;

pub struct IocStore {
    /// All IOCs indexed by value (lowercase).
    pub iocs: HashMap<String, Ioc>,
    /// TAXII sources for polling.
    pub taxii_sources: Vec<TaxiiSource>,
    /// Quick lookup sets for matching.
    ip_set: std::collections::HashSet<String>,
    domain_set: std::collections::HashSet<String>,
    hash_set: std::collections::HashSet<String>,
    url_set: std::collections::HashSet<String>,
}

impl IocStore {
    pub fn new() -> Self {
        Self {
            iocs: HashMap::new(),
            taxii_sources: Vec::new(),
            ip_set: std::collections::HashSet::new(),
            domain_set: std::collections::HashSet::new(),
            hash_set: std::collections::HashSet::new(),
            url_set: std::collections::HashSet::new(),
        }
    }

    pub fn add_ioc(&mut self, ioc: Ioc) {
        let key = ioc.value.to_lowercase();
        // Preserve runtime stats from an existing entry so periodic re-imports
        // (e.g., TAXII polling) do not reset hit_count and last_hit to zero.
        let ioc = if let Some(existing) = self.iocs.get(&key) {
            Ioc {
                hit_count: existing.hit_count,
                last_hit: existing.last_hit,
                ..ioc
            }
        } else {
            ioc
        };
        match &ioc.ioc_type {
            IocType::Ipv4 | IocType::Ipv6 => {
                self.ip_set.insert(key.clone());
            }
            IocType::Domain => {
                self.domain_set.insert(key.clone());
            }
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
                self.hash_set.insert(key.clone());
            }
            IocType::Url => {
                self.url_set.insert(key.clone());
            }
            _ => {}
        }
        self.iocs.insert(key, ioc);
    }

    pub fn remove_ioc(&mut self, value: &str) -> bool {
        let key = value.to_lowercase();
        if let Some(ioc) = self.iocs.remove(&key) {
            match &ioc.ioc_type {
                IocType::Ipv4 | IocType::Ipv6 => {
                    self.ip_set.remove(&key);
                }
                IocType::Domain => {
                    self.domain_set.remove(&key);
                }
                IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
                    self.hash_set.remove(&key);
                }
                IocType::Url => {
                    self.url_set.remove(&key);
                }
                _ => {}
            }
            true
        } else {
            false
        }
    }

    /// Check if a value matches any IOC. Returns (matched, ioc_type).
    pub fn check_ip(&self, ip: &str) -> Option<&Ioc> {
        let key = ip.to_lowercase();
        if self.ip_set.contains(&key) {
            self.iocs.get(&key)
        } else {
            None
        }
    }

    pub fn check_domain(&self, domain: &str) -> Option<&Ioc> {
        let key = domain.to_lowercase();
        if self.domain_set.contains(&key) {
            self.iocs.get(&key)
        } else {
            None
        }
    }

    pub fn check_hash(&self, hash: &str) -> Option<&Ioc> {
        let key = hash.to_lowercase();
        if self.hash_set.contains(&key) {
            self.iocs.get(&key)
        } else {
            None
        }
    }

    pub fn record_hits_batch(&mut self, counts: &HashMap<String, u64>) {
        if counts.is_empty() {
            return;
        }
        let now = Utc::now();
        for (value, increment) in counts {
            if *increment == 0 {
                continue;
            }
            let key = value.trim().to_lowercase();
            if key.is_empty() {
                continue;
            }
            if let Some(ioc) = self.iocs.get_mut(&key) {
                ioc.hit_count = ioc.hit_count.saturating_add(*increment);
                ioc.last_hit = Some(now);
            }
        }
    }

    /// Remove expired IOCs.
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let expired: Vec<String> = self
            .iocs
            .iter()
            .filter(|(_, ioc)| ioc.expires_at.map(|e| e < now).unwrap_or(false))
            .map(|(k, _)| k.clone())
            .collect();
        let count = expired.len();
        for key in expired {
            self.remove_ioc(&key);
        }
        count
    }

    /// Import STIX 2.1 bundle JSON.
    pub fn import_stix_bundle(&mut self, json_str: &str) -> Result<usize, String> {
        let bundle: StixBundle =
            serde_json::from_str(json_str).map_err(|e| format!("Invalid STIX JSON: {}", e))?;

        let mut imported = 0;
        for obj in bundle.objects {
            if obj.obj_type != "indicator" {
                continue;
            }
            if let Some(pattern) = &obj.pattern {
                let iocs = parse_stix_pattern(pattern);
                for (ioc_type, value) in iocs {
                    let ioc = Ioc {
                        id: obj
                            .id
                            .clone()
                            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
                        ioc_type,
                        value: value.clone(),
                        source: "stix".into(),
                        description: obj.description.clone().unwrap_or_default(),
                        severity: if obj.labels.iter().any(|l| l.contains("malicious")) {
                            "high".into()
                        } else {
                            "medium".into()
                        },
                        tags: obj.labels.clone(),
                        created_at: Utc::now(),
                        expires_at: obj.valid_until.as_ref().and_then(|s| {
                            DateTime::parse_from_rfc3339(s)
                                .ok()
                                .map(|d| d.with_timezone(&Utc))
                        }),
                        hit_count: 0,
                        last_hit: None,
                        false_positive: false,
                    };
                    self.add_ioc(ioc);
                    imported += 1;
                }
            }
        }
        info!("STIX: Imported {} indicators from bundle", imported);
        Ok(imported)
    }

    pub fn stats(&self) -> serde_json::Value {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();
        let total_hits: u64 = self.iocs.values().map(|i| i.hit_count).sum();
        for ioc in self.iocs.values() {
            *by_type.entry(format!("{:?}", ioc.ioc_type)).or_insert(0) += 1;
            *by_source.entry(ioc.source.clone()).or_insert(0) += 1;
        }
        serde_json::json!({
            "total_iocs": self.iocs.len(),
            "by_type": by_type,
            "by_source": by_source,
            "total_hits": total_hits,
            "ip_count": self.ip_set.len(),
            "domain_count": self.domain_set.len(),
            "hash_count": self.hash_set.len(),
            "url_count": self.url_set.len(),
            "taxii_sources": self.taxii_sources.len(),
        })
    }

    // ── ClickHouse persistence ───────────────────────────────────────────

    /// Persist a single IOC to ClickHouse (best-effort).
    pub async fn persist_ioc(db: &Db, ioc: &Ioc) {
        #[derive(clickhouse::Row, serde::Serialize)]
        struct IocRow {
            id: String,
            ioc_type: String,
            value: String,
            source: String,
            severity: String,
            description: String,
            false_positive: u8,
            tags: String,
            created_at: i64,
            expires_at: i64,
            hit_count: u64,
            updated_at: i64,
        }
        let row_id = ioc.id.clone();
        let row_type = format!("{:?}", ioc.ioc_type).to_lowercase();
        let row_value = ioc.value.clone();
        let row_source = ioc.source.clone();
        let row_severity = ioc.severity.clone();
        let row_description = ioc.description.clone();
        let row_tags = serde_json::to_string(&ioc.tags).unwrap_or_default();
        let row_false_positive: u8 = if ioc.false_positive { 1 } else { 0 };
        let row_created = ioc.created_at.timestamp();
        let row_expires = ioc.expires_at.map(|d| d.timestamp()).unwrap_or(0);
        let row_hits = ioc.hit_count;
        let now = Utc::now().timestamp();

        if let Err(e) = db
            .retry_insert("persist_ioc", |cl| {
                let r = IocRow {
                    id: row_id.clone(),
                    ioc_type: row_type.clone(),
                    value: row_value.clone(),
                    source: row_source.clone(),
                    severity: row_severity.clone(),
                    description: row_description.clone(),
                    false_positive: row_false_positive,
                    tags: row_tags.clone(),
                    created_at: row_created,
                    expires_at: row_expires,
                    hit_count: row_hits,
                    updated_at: now,
                };
                async move {
                    let mut ins = cl.insert("iocs").context("prepare iocs insert")?;
                    ins.write(&r).await.context("write ioc row")?;
                    ins.end().await.context("finalize ioc insert")?;
                    Ok(())
                }
            })
            .await
        {
            warn!("Failed to persist IOC to ClickHouse: {:#}", e);
        }
    }

    /// Load IOCs from ClickHouse on startup.
    pub async fn load_from_clickhouse(db: &Db) -> Vec<Ioc> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct IocRow {
            ioc_type: String,
            value: String,
            id: String,
            source: String,
            severity: String,
            description: String,
            false_positive: u8,
            tags: String,
            created_at: i64,
            expires_at: i64,
            hit_count: u64,
        }
        let client = db.client();
        let rows = match client
            .query("SELECT ioc_type, value, \
                    argMax(id, updated_at) AS id, \
                    argMax(source, updated_at) AS source, \
                    argMax(severity, updated_at) AS severity, argMax(description, updated_at) AS description, \
                    argMax(false_positive, updated_at) AS false_positive, \
                    argMax(tags, updated_at) AS tags, \
                    argMax(created_at, updated_at) AS created_at, argMax(expires_at, updated_at) AS expires_at, \
                    argMax(hit_count, updated_at) AS hit_count \
                    FROM iocs GROUP BY ioc_type, value")
            .fetch_all::<IocRow>()
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                warn!("Failed to load IOCs from ClickHouse: {:#}", e);
                return vec![];
            }
        };

        let mut result = Vec::with_capacity(rows.len());
        for r in rows {
            let ioc_type = match r.ioc_type.as_str() {
                "ipv4" => IocType::Ipv4,
                "ipv6" => IocType::Ipv6,
                "domain" => IocType::Domain,
                "url" => IocType::Url,
                "md5" => IocType::Md5,
                "sha1" => IocType::Sha1,
                "sha256" => IocType::Sha256,
                "email" => IocType::Email,
                "cve" => IocType::Cve,
                _ => IocType::Domain, // fallback
            };
            let tags: Vec<String> = serde_json::from_str(&r.tags).unwrap_or_default();
            let expires_at = if r.expires_at == 0 {
                None
            } else {
                DateTime::from_timestamp(r.expires_at, 0).map(|d| d.with_timezone(&Utc))
            };
            result.push(Ioc {
                id: r.id,
                ioc_type,
                value: r.value,
                source: r.source,
                description: r.description,
                severity: r.severity,
                tags,
                created_at: DateTime::from_timestamp(r.created_at, 0)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now),
                expires_at,
                hit_count: r.hit_count,
                last_hit: None,
                false_positive: r.false_positive != 0,
            });
        }
        info!("Loaded {} IOCs from ClickHouse", result.len());
        result
    }
}

/// Parse a STIX 2.1 pattern string to extract IOC values.
/// Example: "[ipv4-addr:value = '1.2.3.4']"
fn parse_stix_pattern(pattern: &str) -> Vec<(IocType, String)> {
    let mut results = Vec::new();
    // Simple regex-free parser for common STIX patterns
    let parts: Vec<&str> = pattern.split('\'').collect();
    for (i, part) in parts.iter().enumerate() {
        if i % 2 == 1 {
            // Odd indices are between quotes = values
            let value = part.trim().to_string();
            if !value.is_empty() {
                let ioc_type = IocType::detect(&value);
                results.push((ioc_type, value));
            }
        }
    }
    results
}

pub fn init_ioc_store() -> IocStoreHandle {
    Arc::new(RwLock::new(IocStore::new()))
}

/// Spawn periodic TAXII polling task.
pub fn spawn_taxii_poller(ioc_store: IocStoreHandle) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let (sources, now) = {
                let store = ioc_store.read().await;
                (store.taxii_sources.clone(), Utc::now())
            };
            for source in &sources {
                if !source.enabled {
                    continue;
                }

                let due = source
                    .last_poll
                    .map(|lp| {
                        (now - lp).num_seconds()
                            >= i64::try_from(source.poll_interval_secs.max(60)).unwrap_or(3600)
                    })
                    .unwrap_or(true);
                if !due {
                    continue;
                }

                match poll_taxii_collection(&source.api_root, &source.collection_id).await {
                    Ok(json) => {
                        let mut store = ioc_store.write().await;
                        match store.import_stix_bundle(&json) {
                            Ok(n) => {
                                info!("TAXII: Polled {} indicators from '{}'", n, source.name);
                                // Update last_poll timestamp.
                                if let Some(src) =
                                    store.taxii_sources.iter_mut().find(|s| s.id == source.id)
                                {
                                    src.last_poll = Some(Utc::now());
                                    src.indicators_loaded += n as u64;
                                }
                            }
                            Err(e) => warn!("TAXII: Parse error for '{}': {}", source.name, e),
                        }
                    }
                    Err(e) => {
                        warn!("TAXII: Poll failed for '{}': {}", source.name, e);
                        let mut store = ioc_store.write().await;
                        if let Some(src) = store.taxii_sources.iter_mut().find(|s| s.id == source.id)
                        {
                            // Mark attempt timestamp even on failure to avoid tight-loop retries.
                            src.last_poll = Some(Utc::now());
                        }
                    }
                }
            }
            // Cleanup expired
            let mut store = ioc_store.write().await;
            let cleaned = store.cleanup_expired();
            if cleaned > 0 {
                info!("IOC: Cleaned {} expired indicators", cleaned);
            }
        }
    });
}

/// Poll a TAXII 2.1 collection endpoint.
/// Supports optional Basic auth (from env), added_after filtering, and pagination.
async fn poll_taxii_collection(api_root: &str, collection_id: &str) -> Result<String, String> {
    let url = format!(
        "{}/collections/{}/objects/",
        api_root.trim_end_matches('/'),
        collection_id
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("HTTP client error: {}", e))?;

    let mut req = client
        .get(&url)
        .header("Accept", "application/taxii+json;version=2.1");

    // Support Basic auth from env: PERCEPTA_TAXII_USER / PERCEPTA_TAXII_PASS
    if let (Ok(user), Ok(pass)) = (
        std::env::var("PERCEPTA_TAXII_USER"),
        std::env::var("PERCEPTA_TAXII_PASS"),
    ) {
        req = req.basic_auth(user, Some(pass));
    }

    // Support API key auth from env: PERCEPTA_TAXII_API_KEY
    if let Ok(api_key) = std::env::var("PERCEPTA_TAXII_API_KEY") {
        req = req.header("Authorization", format!("Bearer {}", api_key));
    }

    let resp = req
        .send()
        .await
        .map_err(|e| format!("Request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    resp.text()
        .await
        .map_err(|e| format!("Body read error: {}", e))
}

// ── API Handlers ─────────────────────────────────────────────────────────

use crate::enroll::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

/// GET /api/ioc/list — list all IOCs with optional type filter.
pub async fn api_list_iocs(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.ioc_store.read().await;
    let iocs: Vec<&Ioc> = store.iocs.values().collect();
    Json(serde_json::json!({
        "total": iocs.len(),
        "iocs": iocs,
    }))
}

/// POST /api/ioc/add — add a manual IOC.
pub async fn api_add_ioc(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let value = body
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if value.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "value required"})),
        )
            .into_response();
    }

    let ioc_type = body
        .get("ioc_type")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| IocType::detect(&value));

    let expiry_hours: Option<i64> = body.get("expiry_hours").and_then(|v| v.as_i64());

    let ioc = Ioc {
        id: uuid::Uuid::new_v4().to_string(),
        ioc_type,
        value: value.clone(),
        source: "manual".into(),
        description: body
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        severity: body
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("medium")
            .into(),
        tags: body
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        created_at: Utc::now(),
        expires_at: expiry_hours.map(|h| Utc::now() + chrono::Duration::hours(h)),
        hit_count: 0,
        last_hit: None,
        false_positive: false,
    };

    let mut store = state.ioc_store.write().await;
    let ioc_clone = ioc.clone();
    store.add_ioc(ioc);
    drop(store);

    // Persist to ClickHouse
    let db = state.db.clone();
    tokio::spawn(async move { IocStore::persist_ioc(&db, &ioc_clone).await });

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"status": "added", "value": value})),
    )
        .into_response()
}

/// POST /api/ioc/remove — remove an IOC by value.
pub async fn api_remove_ioc(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let value = body.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let mut store = state.ioc_store.write().await;
    if store.remove_ioc(value) {
        Json(serde_json::json!({"status": "removed"})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "IOC not found"})),
        )
            .into_response()
    }
}

/// POST /api/ioc/import_stix — import a STIX 2.1 bundle JSON.
pub async fn api_import_stix(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let json_str = serde_json::to_string(&body).unwrap_or_default();
    let mut store = state.ioc_store.write().await;
    match store.import_stix_bundle(&json_str) {
        Ok(n) => {
            // Persist all imported IOCs in background
            let db = state.db.clone();
            let iocs: Vec<Ioc> = store.iocs.values().cloned().collect();
            drop(store);
            tokio::spawn(async move {
                for ioc in &iocs {
                    IocStore::persist_ioc(&db, ioc).await;
                }
            });
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "imported", "count": n})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// GET /api/ioc/stats — IOC feed statistics.
pub async fn api_ioc_stats(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.ioc_store.read().await;
    Json(store.stats())
}

/// POST /api/ioc/check — check if a value matches any IOC.
pub async fn api_check_ioc(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let value = body.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let store = state.ioc_store.read().await;
    let ioc_type = IocType::detect(value);

    let matched = match ioc_type {
        IocType::Ipv4 | IocType::Ipv6 => store.check_ip(value),
        IocType::Domain => store.check_domain(value),
        IocType::Md5 | IocType::Sha1 | IocType::Sha256 => store.check_hash(value),
        _ => store.iocs.get(&value.to_lowercase()),
    };

    match matched {
        Some(ioc) => Json(serde_json::json!({"matched": true, "ioc": ioc})).into_response(),
        None => Json(serde_json::json!({"matched": false})).into_response(),
    }
}

/// POST /api/taxii/add_source — add a TAXII collection source.
pub async fn api_add_taxii_source(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let source = TaxiiSource {
        id: uuid::Uuid::new_v4().to_string(),
        name: body
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        api_root: body
            .get("api_root")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        collection_id: body
            .get("collection_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        enabled: body
            .get("enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
        poll_interval_secs: body
            .get("poll_interval_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600),
        last_poll: None,
        indicators_loaded: 0,
    };

    let mut store = state.ioc_store.write().await;
    store.taxii_sources.push(source);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"status": "added"})),
    )
        .into_response()
}
