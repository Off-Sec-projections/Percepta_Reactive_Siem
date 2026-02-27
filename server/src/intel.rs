use anyhow::Context;
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use once_cell::sync::Lazy;
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::enroll::AppState;

static DEFAULT_CONFIG_CANDIDATES: Lazy<Vec<PathBuf>> = Lazy::new(|| {
    vec![
        // Repo-root run
        PathBuf::from("server/config/apis.toml"),
        // Crate-relative
        PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/config/apis.toml")),
        // Also allow copying next to the binary
        PathBuf::from("apis.toml"),
    ]
});

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct OtxConfig {
    pub api_key: String,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AbuseIpDbConfig {
    pub api_key: String,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MalwareBazaarConfig {
    pub api_key: String,
    pub base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct KeylessConfig {
    pub cisa_kev_enabled: Option<bool>,
    pub cisa_kev_url: Option<String>,
    pub urlhaus_enabled: Option<bool>,
    pub urlhaus_base_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct IntelConfig {
    pub otx: Option<OtxConfig>,
    pub abuseipdb: Option<AbuseIpDbConfig>,
    pub malwarebazaar: Option<MalwareBazaarConfig>,
    pub keyless: Option<KeylessConfig>,
}

impl IntelConfig {
    pub fn load_best_effort() -> Self {
        let from_env = std::env::var("PERCEPTA_APIS_FILE").ok().map(PathBuf::from);
        let path = from_env
            .into_iter()
            .chain(DEFAULT_CONFIG_CANDIDATES.clone())
            .find(|p| p.exists());

        let mut cfg = if let Some(p) = path {
            match std::fs::read_to_string(&p)
                .with_context(|| format!("read {}", p.display()))
                .and_then(|s| toml::from_str::<IntelConfig>(&s).context("parse toml"))
            {
                Ok(c) => {
                    debug!("Loaded intel config from {}", p.display());
                    c
                }
                Err(e) => {
                    warn!("Intel config load failed: {:#}", e);
                    IntelConfig::default()
                }
            }
        } else {
            IntelConfig::default()
        };

        // Env overrides are preferred for demos/CI.
        if let Ok(v) = std::env::var("PERCEPTA_OTX_API_KEY") {
            cfg.otx.get_or_insert_with(Default::default).api_key = v;
        }
        if let Ok(v) = std::env::var("PERCEPTA_ABUSEIPDB_API_KEY") {
            cfg.abuseipdb.get_or_insert_with(Default::default).api_key = v;
        }
        if let Ok(v) = std::env::var("PERCEPTA_MALWAREBAZAAR_API_KEY") {
            cfg.malwarebazaar
                .get_or_insert_with(Default::default)
                .api_key = v;
        }

        cfg
    }

    fn otx_enabled(&self) -> bool {
        self.otx
            .as_ref()
            .map(|c| !c.api_key.trim().is_empty())
            .unwrap_or(false)
    }

    fn abuseipdb_enabled(&self) -> bool {
        self.abuseipdb
            .as_ref()
            .map(|c| !c.api_key.trim().is_empty())
            .unwrap_or(false)
    }

    fn malwarebazaar_enabled(&self) -> bool {
        self.malwarebazaar
            .as_ref()
            .map(|c| !c.api_key.trim().is_empty())
            .unwrap_or(false)
    }

    fn kev_enabled(&self) -> bool {
        self.keyless
            .as_ref()
            .and_then(|k| k.cisa_kev_enabled)
            .unwrap_or(true)
    }

    fn urlhaus_enabled(&self) -> bool {
        self.keyless
            .as_ref()
            .and_then(|k| k.urlhaus_enabled)
            .unwrap_or(true)
    }

    fn urlhaus_base_url(&self) -> String {
        self.keyless
            .as_ref()
            .and_then(|k| k.urlhaus_base_url.clone())
            .unwrap_or_else(|| "https://urlhaus-api.abuse.ch".to_string())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IntelStatus {
    pub otx: bool,
    pub abuseipdb: bool,
    pub malwarebazaar: bool,
    pub cisa_kev: bool,
    pub urlhaus: bool,
}

#[derive(Clone)]
pub struct IntelService {
    cfg: IntelConfig,
    http: reqwest::Client,

    // small TTL caches to keep demo keys within free limits
    ip_cache: Arc<RwLock<HashMap<String, (Instant, Value)>>>,
    hash_cache: Arc<RwLock<HashMap<String, (Instant, Value)>>>,

    kev_cache: Arc<RwLock<Option<(Instant, HashSet<String>)>>>,
}

impl IntelService {
    pub fn new(cfg: IntelConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(6))
            .user_agent("percepta-siem/0.1 (demo)")
            .build()
            .expect("reqwest client");

        Self {
            cfg,
            http,
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
            hash_cache: Arc::new(RwLock::new(HashMap::new())),
            kev_cache: Arc::new(RwLock::new(None)),
        }
    }

    pub fn status(&self) -> IntelStatus {
        IntelStatus {
            otx: self.cfg.otx_enabled(),
            abuseipdb: self.cfg.abuseipdb_enabled(),
            malwarebazaar: self.cfg.malwarebazaar_enabled(),
            cisa_kev: self.cfg.kev_enabled(),
            urlhaus: self.cfg.urlhaus_enabled(),
        }
    }

    pub async fn enrich_ip(&self, ip: &str) -> Value {
        let ip = ip.trim();
        if ip.is_empty() {
            return serde_json::json!({"ok": false, "error": "empty ip"});
        }

        // Cache: 10 minutes
        if let Some(v) = self.get_cached(&self.ip_cache, ip, Duration::from_secs(600)).await {
            return v;
        }

        let mut providers = serde_json::Map::new();
        let mut errors: Vec<String> = Vec::new();

        if self.cfg.abuseipdb_enabled() {
            match self.abuseipdb_check(ip).await {
                Ok(v) => {
                    providers.insert("abuseipdb".into(), v);
                }
                Err(e) => errors.push(format!("abuseipdb: {e}")),
            }
        } else {
            providers.insert("abuseipdb".into(), serde_json::json!({"configured": false}));
        }

        if self.cfg.otx_enabled() {
            match self.otx_ipv4_general(ip).await {
                Ok(v) => {
                    providers.insert("otx".into(), v);
                }
                Err(e) => errors.push(format!("otx: {e}")),
            }
        } else {
            providers.insert("otx".into(), serde_json::json!({"configured": false}));
        }

        if self.cfg.urlhaus_enabled() {
            match self.urlhaus_host_lookup(ip).await {
                Ok(v) => {
                    providers.insert("urlhaus".into(), v);
                }
                Err(e) => errors.push(format!("urlhaus: {e}")),
            }
        } else {
            providers.insert("urlhaus".into(), serde_json::json!({"configured": false}));
        }

        let out = serde_json::json!({
            "ok": errors.is_empty(),
            "ip": ip,
            "providers": providers,
            "errors": errors,
            "ts": chrono::Utc::now().to_rfc3339(),
        });

        self.put_cached(&self.ip_cache, ip, out.clone()).await;
        out
    }

    pub async fn enrich_hash(&self, sha256: &str) -> Value {
        let h = sha256.trim().to_lowercase();
        if h.is_empty() {
            return serde_json::json!({"ok": false, "error": "empty sha256"});
        }
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return serde_json::json!({"ok": false, "error": "sha256 must be 64 hex chars"});
        }

        // Cache: 30 minutes
        if let Some(v) = self
            .get_cached(&self.hash_cache, &h, Duration::from_secs(1800))
            .await
        {
            return v;
        }

        let mut providers = serde_json::Map::new();
        let mut errors: Vec<String> = Vec::new();

        if self.cfg.malwarebazaar_enabled() {
            match self.malwarebazaar_hash_info(&h).await {
                Ok(v) => {
                    providers.insert("malwarebazaar".into(), v);
                }
                Err(e) => errors.push(format!("malwarebazaar: {e}")),
            }
        } else {
            providers.insert(
                "malwarebazaar".into(),
                serde_json::json!({"configured": false}),
            );
        }

        if self.cfg.otx_enabled() {
            match self.otx_file_general(&h).await {
                Ok(v) => {
                    providers.insert("otx".into(), v);
                }
                Err(e) => errors.push(format!("otx: {e}")),
            }
        } else {
            providers.insert("otx".into(), serde_json::json!({"configured": false}));
        }

        let out = serde_json::json!({
            "ok": errors.is_empty(),
            "sha256": h,
            "providers": providers,
            "errors": errors,
            "ts": chrono::Utc::now().to_rfc3339(),
        });

        self.put_cached(&self.hash_cache, &h, out.clone()).await;
        out
    }

    pub async fn kev_contains(&self, cve: &str) -> Value {
        if !self.cfg.kev_enabled() {
            return serde_json::json!({"ok": false, "configured": false});
        }
        let id = cve.trim().to_uppercase();
        if !id.starts_with("CVE-") {
            return serde_json::json!({"ok": false, "error": "expected CVE-..."});
        }

        match self.load_kev_set().await {
            Ok(set) => {
                let present = set.contains(&id);
                serde_json::json!({"ok": true, "cve": id, "in_kev": present})
            }
            Err(e) => serde_json::json!({"ok": false, "cve": id, "error": e.to_string()}),
        }
    }

    async fn load_kev_set(&self) -> anyhow::Result<HashSet<String>> {
        // TTL: 12 hours
        {
            let r = self.kev_cache.read().await;
            if let Some((t, set)) = r.as_ref() {
                if t.elapsed() < Duration::from_secs(12 * 3600) {
                    return Ok(set.clone());
                }
            }
        }

        let url = self
            .cfg
            .keyless
            .as_ref()
            .and_then(|k| k.cisa_kev_url.clone())
            .unwrap_or_else(|| {
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                    .to_string()
            });

        let v: Value = self
            .http
            .get(&url)
            .send()
            .await
            .context("kev fetch")?
            .error_for_status()
            .context("kev status")?
            .json()
            .await
            .context("kev json")?;

        let mut set = HashSet::new();
        if let Some(arr) = v.get("vulnerabilities").and_then(|x| x.as_array()) {
            for it in arr {
                if let Some(c) = it.get("cveID").and_then(|x| x.as_str()) {
                    set.insert(c.to_string().to_uppercase());
                }
            }
        }

        let mut w = self.kev_cache.write().await;
        *w = Some((Instant::now(), set.clone()));
        Ok(set)
    }

    async fn get_cached(
        &self,
        cache: &Arc<RwLock<HashMap<String, (Instant, Value)>>>,
        key: &str,
        ttl: Duration,
    ) -> Option<Value> {
        let r = cache.read().await;
        r.get(key)
            .and_then(|(t, v)| if t.elapsed() < ttl { Some(v.clone()) } else { None })
    }

    async fn put_cached(
        &self,
        cache: &Arc<RwLock<HashMap<String, (Instant, Value)>>>,
        key: &str,
        val: Value,
    ) {
        let mut w = cache.write().await;
        if w.len() > 512 {
            // crude cap for demos
            let keys: Vec<String> = w.keys().take(64).cloned().collect();
            for k in keys {
                w.remove(&k);
            }
        }
        w.insert(key.to_string(), (Instant::now(), val));
    }

    async fn abuseipdb_check(&self, ip: &str) -> anyhow::Result<Value> {
        let cfg = self.cfg.abuseipdb.clone().unwrap_or_default();
        let base = cfg
            .base_url
            .unwrap_or_else(|| "https://api.abuseipdb.com".to_string());
        let url = format!("{}/api/v2/check", base.trim_end_matches('/'));

        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "Key",
            HeaderValue::from_str(cfg.api_key.trim()).context("abuseipdb key")?,
        );

        let v: Value = self
            .http
            .get(url)
            .headers(headers)
            .query(&[
                ("ipAddress", ip),
                ("maxAgeInDays", "90"),
                ("verbose", "true"),
            ])
            .send()
            .await
            .context("abuseipdb request")?
            .error_for_status()
            .context("abuseipdb status")?
            .json()
            .await
            .context("abuseipdb json")?;
        Ok(v)
    }

    async fn otx_ipv4_general(&self, ip: &str) -> anyhow::Result<Value> {
        let cfg = self.cfg.otx.clone().unwrap_or_default();
        let base = cfg
            .base_url
            .unwrap_or_else(|| "https://otx.alienvault.com".to_string());
        let url = format!(
            "{}/api/v1/indicators/IPv4/{}/general",
            base.trim_end_matches('/'),
            ip
        );

        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "X-OTX-API-KEY",
            HeaderValue::from_str(cfg.api_key.trim()).context("otx key")?,
        );

        let v: Value = self
            .http
            .get(url)
            .headers(headers)
            .send()
            .await
            .context("otx request")?
            .error_for_status()
            .context("otx status")?
            .json()
            .await
            .context("otx json")?;
        Ok(v)
    }

    async fn otx_file_general(&self, sha256: &str) -> anyhow::Result<Value> {
        let cfg = self.cfg.otx.clone().unwrap_or_default();
        let base = cfg
            .base_url
            .unwrap_or_else(|| "https://otx.alienvault.com".to_string());
        // OTX uses "file/<hash>"; SHA256 is accepted.
        let url = format!(
            "{}/api/v1/indicators/file/{}/general",
            base.trim_end_matches('/'),
            sha256
        );

        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        headers.insert(
            "X-OTX-API-KEY",
            HeaderValue::from_str(cfg.api_key.trim()).context("otx key")?,
        );

        let v: Value = self
            .http
            .get(url)
            .headers(headers)
            .send()
            .await
            .context("otx request")?
            .error_for_status()
            .context("otx status")?
            .json()
            .await
            .context("otx json")?;
        Ok(v)
    }

    async fn malwarebazaar_hash_info(&self, sha256: &str) -> anyhow::Result<Value> {
        let cfg = self.cfg.malwarebazaar.clone().unwrap_or_default();
        let base = cfg
            .base_url
            .unwrap_or_else(|| "https://mb-api.abuse.ch".to_string());
        let url = format!("{}/api/v1/", base.trim_end_matches('/'));

        let mut headers = HeaderMap::new();
        headers.insert("Accept", HeaderValue::from_static("application/json"));
        if !cfg.api_key.trim().is_empty() {
            headers.insert(
                "Auth-Key",
                HeaderValue::from_str(cfg.api_key.trim()).context("malwarebazaar key")?,
            );
        }

        // MalwareBazaar expects form-encoded POST.
        let v: Value = self
            .http
            .post(url)
            .headers(headers)
            .form(&[("query", "get_info"), ("hash", sha256)])
            .send()
            .await
            .context("malwarebazaar request")?
            .error_for_status()
            .context("malwarebazaar status")?
            .json()
            .await
            .context("malwarebazaar json")?;
        Ok(v)
    }

    async fn urlhaus_host_lookup(&self, host_or_ip: &str) -> anyhow::Result<Value> {
        let base = self.cfg.urlhaus_base_url();
        let url = format!("{}/v1/host/", base.trim_end_matches('/'));

        let v: Value = self
            .http
            .post(url)
            .form(&[("host", host_or_ip)])
            .send()
            .await
            .context("urlhaus request")?
            .error_for_status()
            .context("urlhaus status")?
            .json()
            .await
            .context("urlhaus json")?;
        Ok(v)
    }
}

#[derive(Debug, Deserialize)]
pub struct IpReq {
    pub ip: String,
}

#[derive(Debug, Deserialize)]
pub struct HashReq {
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
pub struct KevReq {
    pub cve: String,
}

pub async fn intel_status(State(state): State<AppState>) -> impl IntoResponse {
    let s = state.intel.status();
    (StatusCode::OK, Json(s))
}

pub async fn intel_ip(State(state): State<AppState>, Json(req): Json<IpReq>) -> impl IntoResponse {
    let v = state.intel.enrich_ip(&req.ip).await;
    (StatusCode::OK, Json(v))
}

pub async fn intel_hash(
    State(state): State<AppState>,
    Json(req): Json<HashReq>,
) -> impl IntoResponse {
    let v = state.intel.enrich_hash(&req.sha256).await;
    (StatusCode::OK, Json(v))
}

pub async fn intel_kev(State(state): State<AppState>, Json(req): Json<KevReq>) -> impl IntoResponse {
    let v = state.intel.kev_contains(&req.cve).await;
    (StatusCode::OK, Json(v))
}
