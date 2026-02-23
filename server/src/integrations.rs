//! Generic API Integration Hub
//!
//! Allows operators to add any external threat-intel / enrichment API
//! via the dashboard UI without Rust code changes or rebuilds.
//!
//! Each integration record stores:
//!  - name, base_url, auth method, api_key (in-memory only, never persisted to disk)
//!  - endpoint templates per trigger type (ip, hash, domain, url)
//!  - rate-limit (req/min), enabled flag
//!
//! At enrichment time the pipeline iterates all enabled integrations that match
//! the event's artifact type, performs the HTTP lookup, and merges the result
//! into the event's metadata under `integration.<name>.*`.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::auth::{AuthedUser, Role};
use crate::enroll::AppState;

// ── Data Model ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    /// API key sent as a request header (most common: x-apikey, Authorization, etc.)
    #[default]
    Header,
    /// API key appended as a URL query parameter (?apikey=...)
    QueryParam,
    /// Bearer token in Authorization header
    Bearer,
    /// HTTP Basic auth (username:password)
    Basic,
    /// No auth — public/keyless endpoints
    None,
}

/// One endpoint pattern for a specific artifact trigger type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationEndpoint {
    /// What artifact triggers this endpoint: "ip" | "hash" | "domain" | "url" | "cve"
    pub trigger: String,
    /// URL path template. Use `{value}` as placeholder for the artifact.
    /// Example: "/files/{value}" — will be appended to base_url.
    pub path: String,
    /// Optional dot-path into the JSON response to extract as the summary value.
    /// Example: "data.attributes.last_analysis_stats"
    /// If empty, the raw response JSON is stored.
    #[serde(default)]
    pub response_field: String,
    /// Optional HTTP method. Defaults to GET.
    #[serde(default = "default_method")]
    pub method: String,
    /// Optional JSON body template for POST requests. Use {value} as placeholder.
    #[serde(default)]
    pub body_template: String,
}

fn default_method() -> String {
    "GET".to_string()
}

/// A registered external API integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integration {
    /// Unique slug — used as metadata key prefix (e.g. "virustotal")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Base URL (no trailing slash). Example: "https://www.virustotal.com/api/v3"
    pub base_url: String,
    /// Auth method
    #[serde(default)]
    pub auth_type: AuthType,
    /// Header/parameter name for the API key.
    /// For Header/Bearer: the header name (e.g. "x-apikey", "Authorization")
    /// For QueryParam: the query param name (e.g. "apikey", "key")
    /// For Basic: the username (password stored in api_key)
    #[serde(default)]
    pub auth_key_name: String,
    /// The actual API key / secret. Stored only in-memory, never written to disk.
    #[serde(default)]
    pub api_key: String,
    /// Endpoint definitions per trigger type
    #[serde(default)]
    pub endpoints: Vec<IntegrationEndpoint>,
    /// Max requests per minute (0 = unlimited)
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_min: u32,
    /// Whether this integration is active
    #[serde(default = "bool_true")]
    pub enabled: bool,
    /// Brief description shown in UI
    #[serde(default)]
    pub description: String,
    /// Optional documentation URL
    #[serde(default)]
    pub docs_url: String,
}

fn default_rate_limit() -> u32 {
    60
}

fn bool_true() -> bool {
    true
}

// ── Store ─────────────────────────────────────────────────────────────────────

/// Sliding-window log for per-integration rate limiting.
/// Stores the timestamp of each request made within the last 60 seconds.
/// On every check, stale entries are pruned from the front, then the
/// remaining length is compared against the configured per-minute limit.
/// This is the sliding-window log algorithm: it allows exactly `limit`
/// requests per any rolling 60-second period, with no boundary bursts.
#[derive(Debug, Clone)]
struct RateState {
    /// Timestamps of requests made within the current 60-second window.
    /// Front = oldest, back = newest.
    log: VecDeque<Instant>,
}

pub struct IntegrationStore {
    integrations: HashMap<String, Integration>,
    /// Per-integration sliding-window rate-limit state.
    rate_state: HashMap<String, RateState>,
}

impl IntegrationStore {
    pub fn new() -> Self {
        let mut store = Self {
            integrations: HashMap::new(),
            rate_state: HashMap::new(),
        };
        // Pre-load built-in templates as disabled stubs
        for tpl in builtin_templates() {
            store.integrations.insert(tpl.id.clone(), tpl);
        }
        store
    }

    pub fn list(&self) -> Vec<&Integration> {
        let mut v: Vec<&Integration> = self.integrations.values().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn get(&self, id: &str) -> Option<&Integration> {
        self.integrations.get(id)
    }

    pub fn upsert(&mut self, integration: Integration) -> Result<(), String> {
        let id = integration.id.trim().to_string();
        if id.is_empty() {
            return Err("Integration id must not be empty".into());
        }
        // Sanitize: id must be slug-safe
        if !id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err("Integration id must be alphanumeric/underscore/hyphen only".into());
        }
        self.integrations.insert(id, integration);
        Ok(())
    }

    pub fn delete(&mut self, id: &str) -> bool {
        self.integrations.remove(id).is_some()
    }

    pub fn toggle(&mut self, id: &str, enabled: bool) -> bool {
        if let Some(i) = self.integrations.get_mut(id) {
            i.enabled = enabled;
            true
        } else {
            false
        }
    }

    pub fn snapshot_owned(&self) -> Vec<Integration> {
        let mut out: Vec<Integration> = self.integrations.values().cloned().collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Check and update rate limit using the sliding-window log algorithm.
    /// Returns true if request is allowed, false if rate limit is exceeded.
    ///
    /// Pruning older-than-60s timestamps on every call ensures that the
    /// window always reflects exactly the last 60 seconds, so there are
    /// no boundary bursts regardless of timing.
    fn check_rate(&mut self, id: &str, limit: u32) -> bool {
        if limit == 0 {
            return true; // No rate limit configured
        }

        let now = Instant::now();
        let window = Duration::from_secs(60);
        let state = self.rate_state.entry(id.to_string()).or_insert(RateState {
            log: VecDeque::new(),
        });

        // Prune requests older than 60 seconds from the front of the log.
        while let Some(&front) = state.log.front() {
            if now.duration_since(front) >= window {
                state.log.pop_front();
            } else {
                break;
            }
        }

        // Deny if we've already issued `limit` requests in the rolling window.
        if state.log.len() as u32 >= limit {
            return false;
        }

        state.log.push_back(now);
        true
    }
}

pub type IntegrationStoreHandle = Arc<RwLock<IntegrationStore>>;

pub fn new_store() -> IntegrationStoreHandle {
    Arc::new(RwLock::new(IntegrationStore::new()))
}

// ── Persistence (ClickHouse app_config) ─────────────────────────────────────

pub async fn persist_integrations_to_ch(
    db: &crate::db::Db,
    integrations: &[Integration],
) {
    let content = match serde_json::to_string(integrations) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to serialize integrations for persistence: {}", e);
            return;
        }
    };

    #[derive(clickhouse::Row, serde::Serialize)]
    struct CfgRow<'a> {
        k: &'a str,
        v: &'a str,
        updated_at: i64,
    }

    let row = CfgRow {
        k: "integrations_config_v1",
        v: &content,
        updated_at: chrono::Utc::now().timestamp(),
    };

    let _ = db
        .client()
        .query(
            "CREATE TABLE IF NOT EXISTS app_config \
             (k String, v String, updated_at Int64) \
             ENGINE = ReplacingMergeTree(updated_at) ORDER BY k",
        )
        .execute()
        .await;

    if let Err(e) = async {
        let mut ins = db
            .client()
            .insert("app_config")
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        ins.write(&row).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
        Ok::<_, anyhow::Error>(())
    }
    .await
    {
        warn!("Failed to persist integrations to ClickHouse: {:#}", e);
    }
}

pub async fn load_integrations_from_ch(
    db: &crate::db::Db,
    store: &IntegrationStoreHandle,
) {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct CfgRow {
        v: String,
    }

    let row = match db
        .client()
        .query(
            "SELECT argMax(v, updated_at) AS v \
             FROM app_config WHERE k = 'integrations_config_v1' GROUP BY k",
        )
        .fetch_one::<CfgRow>()
        .await
    {
        Ok(r) => r,
        Err(_) => return,
    };

    let saved = match serde_json::from_str::<Vec<Integration>>(&row.v) {
        Ok(v) => v,
        Err(e) => {
            warn!("Failed to deserialize persisted integrations: {}", e);
            return;
        }
    };

    // Build a lookup of current builtin templates.
    // For any saved integration that matches a builtin ID, we refresh its structural
    // configuration (endpoints, auth method, auth_key_name, base_url) from the
    // current builtin while preserving the user-configured fields (api_key, enabled,
    // rate_limit_per_min). This ensures stored configs stay current when a builtin
    // template changes — e.g. when ThreatFox added the Auth-Key requirement.
    let builtins: HashMap<String, Integration> = builtin_templates()
        .into_iter()
        .map(|t| (t.id.clone(), t))
        .collect();

    let mut guard = store.write().await;
    for saved_integration in saved {
        let migrated = if let Some(builtin) = builtins.get(&saved_integration.id) {
            // If the builtin now requires auth but the saved config has no api_key,
            // force-disable the integration so the user knows to add a key.
            let keep_enabled = if saved_integration.api_key.is_empty()
                && builtin.auth_type != AuthType::None
            {
                false
            } else {
                saved_integration.enabled
            };
            Integration {
                api_key: saved_integration.api_key,
                enabled: keep_enabled,
                rate_limit_per_min: saved_integration.rate_limit_per_min,
                id: builtin.id.clone(),
                name: builtin.name.clone(),
                base_url: builtin.base_url.clone(),
                auth_type: builtin.auth_type.clone(),
                auth_key_name: builtin.auth_key_name.clone(),
                description: builtin.description.clone(),
                docs_url: builtin.docs_url.clone(),
                endpoints: builtin.endpoints.clone(),
            }
        } else {
            saved_integration
        };
        let _ = guard.upsert(migrated);
    }
    debug!("Loaded persisted integrations from ClickHouse");
}

// ── Built-in Templates ─────────────────────────────────────────────────────────

fn builtin_templates() -> Vec<Integration> {
    vec![
        Integration {
            id: "virustotal".to_string(),
            name: "VirusTotal".to_string(),
            base_url: "https://www.virustotal.com/api/v3".to_string(),
            auth_type: AuthType::Header,
            auth_key_name: "x-apikey".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "File/URL/IP/domain reputation. Free: 4 req/min, 500 req/day.".to_string(),
            docs_url: "https://developers.virustotal.com/reference".to_string(),
            rate_limit_per_min: 4,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "hash".to_string(),
                    path: "/files/{value}".to_string(),
                    response_field: "data.attributes.last_analysis_stats".to_string(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: "/ip_addresses/{value}".to_string(),
                    response_field: "data.attributes".to_string(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
                IntegrationEndpoint {
                    trigger: "domain".to_string(),
                    path: "/domains/{value}".to_string(),
                    response_field: "data.attributes".to_string(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
                IntegrationEndpoint {
                    trigger: "url".to_string(),
                    path: "/urls/{value}".to_string(),
                    response_field: "data.attributes.last_analysis_stats".to_string(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
            ],
        },
        Integration {
            id: "greynoise".to_string(),
            name: "GreyNoise".to_string(),
            base_url: "https://api.greynoise.io/v3".to_string(),
            auth_type: AuthType::Header,
            auth_key_name: "key".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "Internet scanner noise reduction. Free community: 25 IPs/day. Reduces FP on mass-scanner traffic.".to_string(),
            docs_url: "https://docs.greynoise.io".to_string(),
            rate_limit_per_min: 60,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: "/community/{value}".to_string(),
                    response_field: String::new(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
            ],
        },
        Integration {
            id: "shodan".to_string(),
            name: "Shodan".to_string(),
            base_url: "https://api.shodan.io".to_string(),
            auth_type: AuthType::QueryParam,
            auth_key_name: "key".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "Internet-connected device data. Free: 100 queries/month.".to_string(),
            docs_url: "https://developer.shodan.io/api".to_string(),
            rate_limit_per_min: 3,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: "/shodan/host/{value}".to_string(),
                    response_field: String::new(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
            ],
        },
        Integration {
            id: "pulsedive".to_string(),
            name: "Pulsedive".to_string(),
            base_url: "https://pulsedive.com/api".to_string(),
            auth_type: AuthType::QueryParam,
            auth_key_name: "key".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "IP/domain/URL threat scoring. Free: 30 req/min.".to_string(),
            docs_url: "https://pulsedive.com/api/".to_string(),
            rate_limit_per_min: 30,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: "/info.php?indicator={value}&pretty=1".to_string(),
                    response_field: String::new(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
                IntegrationEndpoint {
                    trigger: "domain".to_string(),
                    path: "/info.php?indicator={value}&pretty=1".to_string(),
                    response_field: String::new(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
            ],
        },
        Integration {
            id: "threatfox".to_string(),
            name: "ThreatFox (Abuse.ch)".to_string(),
            base_url: "https://threatfox-api.abuse.ch/api/v1".to_string(),
            // ThreatFox now requires an Auth-Key header for all requests.
            // Free key available at https://auth.abuse.ch/
            auth_type: AuthType::Header,
            auth_key_name: "Auth-Key".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "Malware C2/IOC feed by Abuse.ch. Free Auth-Key required: https://auth.abuse.ch/".to_string(),
            docs_url: "https://threatfox.abuse.ch/api/".to_string(),
            rate_limit_per_min: 60,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: "/".to_string(),
                    response_field: "data".to_string(),
                    method: "POST".to_string(),
                    // Use exact_match:true for precise IOC searches per official API docs
                    body_template: r#"{"query":"search_ioc","search_term":"{value}","exact_match":true}"#.to_string(),
                },
                IntegrationEndpoint {
                    trigger: "hash".to_string(),
                    path: "/".to_string(),
                    response_field: "data".to_string(),
                    method: "POST".to_string(),
                    // Hash lookups use the dedicated search_hash query per official API docs
                    body_template: r#"{"query":"search_hash","hash":"{value}"}"#.to_string(),
                },
                IntegrationEndpoint {
                    trigger: "domain".to_string(),
                    path: "/".to_string(),
                    response_field: "data".to_string(),
                    method: "POST".to_string(),
                    body_template: r#"{"query":"search_ioc","search_term":"{value}","exact_match":true}"#.to_string(),
                },
            ],
        },
        Integration {
            id: "opencti".to_string(),
            name: "OpenCTI (Self-hosted)".to_string(),
            base_url: "https://YOUR-OPENCTI-INSTANCE/graphql".to_string(),
            auth_type: AuthType::Bearer,
            auth_key_name: "Authorization".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "Open Cyber Threat Intelligence platform. Self-hosted. Uses GraphQL API with Bearer token.".to_string(),
            docs_url: "https://docs.opencti.io/latest/deployment/connectors/".to_string(),
            rate_limit_per_min: 60,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: String::new(),
                    response_field: "data.stixCyberObservables.edges".to_string(),
                    method: "POST".to_string(),
                    body_template: r#"{"query":"query{stixCyberObservables(filters:{mode:and,filters:[{key:value,values:[\"' + {value} + '\"]}],filterGroups:[]}){edges{node{entity_type,observable_value}}}}"}"#.to_string(),
                },
            ],
        },
        Integration {
            id: "abuseipdb".to_string(),
            name: "AbuseIPDB".to_string(),
            base_url: "https://api.abuseipdb.com/api/v2".to_string(),
            auth_type: AuthType::Header,
            auth_key_name: "Key".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "IP reputation database. Free: 1000 checks/day. Reports & checks malicious IPs.".to_string(),
            docs_url: "https://docs.abuseipdb.com/".to_string(),
            rate_limit_per_min: 60,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: "/check?ipAddress={value}&maxAgeInDays=90&verbose".to_string(),
                    response_field: "data".to_string(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
            ],
        },
        Integration {
            id: "alienvault-otx".to_string(),
            name: "AlienVault OTX".to_string(),
            base_url: "https://otx.alienvault.com/api/v1".to_string(),
            auth_type: AuthType::Header,
            auth_key_name: "X-OTX-API-KEY".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "Open Threat Exchange. Free community API for IP/domain/hash indicators.".to_string(),
            docs_url: "https://otx.alienvault.com/api".to_string(),
            rate_limit_per_min: 60,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: "/indicators/IPv4/{value}/general".to_string(),
                    response_field: String::new(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
                IntegrationEndpoint {
                    trigger: "domain".to_string(),
                    path: "/indicators/domain/{value}/general".to_string(),
                    response_field: String::new(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
                IntegrationEndpoint {
                    trigger: "hash".to_string(),
                    path: "/indicators/file/{value}/general".to_string(),
                    response_field: String::new(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
            ],
        },
        Integration {
            id: "malwarebazaar".to_string(),
            name: "MalwareBazaar".to_string(),
            base_url: "https://mb-api.abuse.ch/api/v1".to_string(),
            auth_type: AuthType::None,
            auth_key_name: String::new(),
            api_key: String::new(),
            enabled: false,
            description: "Free malware sample database by Abuse.ch. Hash lookups, no key required.".to_string(),
            docs_url: "https://bazaar.abuse.ch/api/".to_string(),
            rate_limit_per_min: 60,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "hash".to_string(),
                    path: "/".to_string(),
                    response_field: "data".to_string(),
                    method: "POST".to_string(),
                    body_template: r#"{"query":"get_info","hash":"{value}"}"#.to_string(),
                },
            ],
        },
        Integration {
            id: "misp".to_string(),
            name: "MISP (Self-hosted)".to_string(),
            base_url: "https://YOUR-MISP-INSTANCE".to_string(),
            auth_type: AuthType::Header,
            auth_key_name: "Authorization".to_string(),
            api_key: String::new(),
            enabled: false,
            description: "Malware Information Sharing Platform. Self-hosted. REST API with API key header.".to_string(),
            docs_url: "https://www.misp-project.org/openapi/".to_string(),
            rate_limit_per_min: 60,
            endpoints: vec![
                IntegrationEndpoint {
                    trigger: "ip".to_string(),
                    path: "/attributes/restSearch/json?value={value}&last=7d".to_string(),
                    response_field: "response.Attribute".to_string(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
                IntegrationEndpoint {
                    trigger: "hash".to_string(),
                    path: "/attributes/restSearch/json?value={value}".to_string(),
                    response_field: "response.Attribute".to_string(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
                IntegrationEndpoint {
                    trigger: "domain".to_string(),
                    path: "/attributes/restSearch/json?value={value}&last=7d".to_string(),
                    response_field: "response.Attribute".to_string(),
                    method: "GET".to_string(),
                    body_template: String::new(),
                },
            ],
        },
    ]
}

// ── HTTP Lookup Engine ─────────────────────────────────────────────────────────

static HTTP_CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();

fn get_http_client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("percepta-siem/1.0 integration-hub")
            .build()
            .unwrap_or_default()
    })
}

/// Perform a single integration lookup for (trigger_type, value).
/// Returns the integration id and the response JSON value on success.
pub async fn lookup_one(
    store: &mut IntegrationStore,
    integration_id: &str,
    trigger: &str,
    value: &str,
) -> Option<(String, serde_json::Value)> {
    let integration = match store.get(integration_id) {
        Some(i) if i.enabled => i.clone(),
        _ => return None,
    };

    let endpoint = match integration
        .endpoints
        .iter()
        .find(|e| e.trigger == trigger)
    {
        Some(e) => e.clone(),
        None => return None,
    };

    // Rate limiting
    if !store.check_rate(&integration.id, integration.rate_limit_per_min) {
        debug!("Rate limit reached for integration {}", integration.id);
        return None;
    }

    // VirusTotal URL lookups require url-safe base64 (no padding) as identifier.
    // Other integrations should keep the raw value semantics.
    let value_for_path = if integration.id == "virustotal" && endpoint.trigger == "url" {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes())
    } else {
        value.to_string()
    };
    let value_encoded = urlencoding::encode(&value_for_path).into_owned();
    let path = endpoint.path.replace("{value}", &value_encoded);
    let url = format!("{}{}", integration.base_url.trim_end_matches('/'), path);

    // JSON-escape the raw value for safe insertion into body templates.
    // Prevents JSON injection from values containing backslashes or double-quotes.
    let value_json_safe = value.replace('\\', "\\\\").replace('"', "\\\"");

    let client = get_http_client();

    let req = match endpoint.method.to_uppercase().as_str() {
        "POST" => {
            let body = endpoint
                .body_template
                .replace("{value}", &value_json_safe)
                .replace("{value_encoded}", &value_encoded);
            client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body)
        }
        _ => client.get(&url),
    };

    // Apply authentication
    let req = match integration.auth_type {
        AuthType::Header => req.header(&integration.auth_key_name, &integration.api_key),
        AuthType::Bearer => req.header(
            "Authorization",
            format!("Bearer {}", integration.api_key),
        ),
        AuthType::QueryParam => {
            // Already in URL for QueryParam (some APIs), or add as explicit param
            // If not in path, add it
            if !path.contains(&format!("{}=", integration.auth_key_name)) {
                let sep = if url.contains('?') { "&" } else { "?" };
                let new_url = format!(
                    "{}{}{}{}={}",
                    integration.base_url.trim_end_matches('/'),
                    path,
                    sep,
                    integration.auth_key_name,
                    integration.api_key
                );
                let req2 = match endpoint.method.to_uppercase().as_str() {
                    "POST" => {
                        let body = endpoint.body_template.replace("{value}", &value_json_safe);
                        client
                            .post(&new_url)
                            .header("Content-Type", "application/json")
                            .body(body)
                    }
                    _ => client.get(&new_url),
                };
                match req2.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.json::<serde_json::Value>().await {
                            Ok(v) => {
                                let extracted = extract_field(&v, &endpoint.response_field);
                                return Some((integration.id.clone(), extracted));
                            }
                            Err(e) => {
                                warn!("Integration {} response parse failed: {}", integration.id, e);
                                return None;
                            }
                        }
                    }
                    Ok(resp) => {
                        debug!("Integration {} returned HTTP {}", integration.id, resp.status());
                        return None;
                    }
                    Err(e) => {
                        warn!("Integration {} request failed: {}", integration.id, e);
                        return None;
                    }
                }
            }
            req
        }
        AuthType::Basic => req.basic_auth(&integration.auth_key_name, Some(&integration.api_key)),
        AuthType::None => req,
    };

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>().await {
                Ok(v) => {
                    let extracted = extract_field(&v, &endpoint.response_field);
                    Some((integration.id.clone(), extracted))
                }
                Err(e) => {
                    warn!("Integration {} response parse failed: {}", integration.id, e);
                    None
                }
            }
        }
        Ok(resp) => {
            debug!("Integration {} HTTP {}", integration.id, resp.status());
            None
        }
        Err(e) => {
            warn!("Integration {} request error: {}", integration.id, e);
            None
        }
    }
}

/// Extract a dot-path field from a JSON value.
fn extract_field(v: &serde_json::Value, field_path: &str) -> serde_json::Value {
    if field_path.is_empty() {
        return v.clone();
    }
    let mut current = v;
    for part in field_path.split('.') {
        match current.get(part) {
            Some(next) => current = next,
            None => return v.clone(), // fallback: return full response
        }
    }
    current.clone()
}

// ── REST API Handlers ─────────────────────────────────────────────────────────

/// GET /api/integrations
pub async fn api_integrations_list(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"authority required"}))).into_response();
    }
    let store = state.integration_store.read().await;
    let list: Vec<IntegrationPublic> = store.list().into_iter().map(IntegrationPublic::from).collect();
    (StatusCode::OK, Json(serde_json::json!({ "integrations": list }))).into_response()
}

/// POST /api/integrations  (upsert)
pub async fn api_integrations_upsert(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<Integration>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"authority required"}))).into_response();
    }

    let mut incoming = body;

    // ── Input validation ──
    if incoming.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"name is required"}))).into_response();
    }
    let base = incoming.base_url.trim();
    if base.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"base_url is required"}))).into_response();
    }
    if !base.starts_with("https://") && !base.starts_with("http://") {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"base_url must use http:// or https:// scheme"}))).into_response();
    }
    if incoming.rate_limit_per_min < 1 || incoming.rate_limit_per_min > 1000 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"rate_limit_per_min must be between 1 and 1000"}))).into_response();
    }
    let valid_triggers = ["ip", "hash", "domain", "url"];
    for ep in &incoming.endpoints {
        if !valid_triggers.contains(&ep.trigger.as_str()) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("invalid trigger '{}'; must be one of: ip, hash, domain, url", ep.trigger)}))).into_response();
        }
    }
    if !incoming.auth_key_name.is_empty() {
        let valid_key = incoming.auth_key_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid_key {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"auth_key_name may only contain letters, digits, hyphens, and underscores"}))).into_response();
        }
    }

    let mut store = state.integration_store.write().await;
    // Keep existing API key/auth key/endpoints when edit submits blanks.
    if let Some(existing) = store.get(&incoming.id).cloned() {
        if incoming.api_key.trim().is_empty() {
            incoming.api_key = existing.api_key;
        }
        if incoming.auth_key_name.trim().is_empty() {
            incoming.auth_key_name = existing.auth_key_name;
        }
        if incoming.endpoints.is_empty() {
            incoming.endpoints = existing.endpoints;
        }
    }

    match store.upsert(incoming) {
        Ok(()) => {
            let snapshot = store.snapshot_owned();
            drop(store);
            let db = state.db.clone();
            tokio::spawn(async move {
                persist_integrations_to_ch(&db, &snapshot).await;
            });
            (StatusCode::OK, Json(serde_json::json!({"ok":true}))).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

/// DELETE /api/integrations/:id
pub async fn api_integrations_delete(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"authority required"}))).into_response();
    }
    let mut store = state.integration_store.write().await;
    let deleted = store.delete(&id);
    if deleted {
        let snapshot = store.snapshot_owned();
        drop(store);
        let db = state.db.clone();
        tokio::spawn(async move {
            persist_integrations_to_ch(&db, &snapshot).await;
        });
    }
    let status = if deleted { StatusCode::OK } else { StatusCode::NOT_FOUND };
    (status, Json(serde_json::json!({"ok": deleted}))).into_response()
}

#[derive(Deserialize)]
pub struct ToggleBody {
    pub enabled: bool,
}

/// POST /api/integrations/:id/toggle
pub async fn api_integrations_toggle(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<ToggleBody>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"authority required"}))).into_response();
    }
    let mut store = state.integration_store.write().await;
    let ok = store.toggle(&id, body.enabled);
    if ok {
        let snapshot = store.snapshot_owned();
        drop(store);
        let db = state.db.clone();
        tokio::spawn(async move {
            persist_integrations_to_ch(&db, &snapshot).await;
        });
    }
    let status = if ok { StatusCode::OK } else { StatusCode::NOT_FOUND };
    (status, Json(serde_json::json!({"ok": ok}))).into_response()
}

#[derive(Deserialize)]
pub struct TestBody {
    pub integration_id: String,
    pub trigger: String,
    pub value: String,
}

/// POST /api/integrations/test  — live test with a single value
pub async fn api_integrations_test(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
    Json(body): Json<TestBody>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"authority required"}))).into_response();
    }
    let mut store = state.integration_store.write().await;
    match lookup_one(&mut store, &body.integration_id, &body.trigger, &body.value).await {
        Some((id, v)) => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": true, "integration": id, "result": v })),
        )
            .into_response(),
        None => (
            StatusCode::OK,
            Json(serde_json::json!({ "ok": false, "error": "No result — check API key, rate limit, or endpoint path." })),
        )
            .into_response(),
    }
}

/// GET /api/integrations/templates  — list built-in templates without api keys
pub async fn api_integrations_templates(
    axum::extract::Extension(user): axum::extract::Extension<AuthedUser>,
) -> impl IntoResponse {
    if user.role != Role::Authority {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"authority required"}))).into_response();
    }
    let templates: Vec<IntegrationPublic> = builtin_templates()
        .into_iter()
        .map(|t| IntegrationPublic::from(&t))
        .collect();
    (StatusCode::OK, Json(serde_json::json!({ "templates": templates }))).into_response()
}

// ── Public (scrubbed) view — never exposes api_key ───────────────────────────

#[derive(Debug, Serialize)]
pub struct IntegrationPublic {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub auth_type: AuthType,
    pub auth_key_name: String,
    /// Whether an API key is set (boolean — key itself is never returned)
    pub has_api_key: bool,
    pub endpoints: Vec<IntegrationEndpoint>,
    pub rate_limit_per_min: u32,
    pub enabled: bool,
    pub description: String,
    pub docs_url: String,
}

impl From<&Integration> for IntegrationPublic {
    fn from(i: &Integration) -> Self {
        Self {
            id: i.id.clone(),
            name: i.name.clone(),
            base_url: i.base_url.clone(),
            auth_type: i.auth_type.clone(),
            auth_key_name: i.auth_key_name.clone(),
            has_api_key: !i.api_key.trim().is_empty(),
            endpoints: i.endpoints.clone(),
            rate_limit_per_min: i.rate_limit_per_min,
            enabled: i.enabled,
            description: i.description.clone(),
            docs_url: i.docs_url.clone(),
        }
    }
}
