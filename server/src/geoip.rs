use axum::{extract::State, Json};
use maxminddb::geoip2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::warn;

use crate::enroll::AppState;

#[derive(Clone)]
pub struct GeoIpService {
    reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    external: Option<IpApiClient>,
}

impl GeoIpService {
    pub fn from_env_or_default() -> Self {
        let path = std::env::var("PERCEPTA_GEOIP_DB")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "server/geoip/GeoLite2-City.mmdb".to_string());

        let reader = std::fs::read(&path)
            .ok()
            .and_then(|bytes| maxminddb::Reader::from_source(bytes).ok())
            .map(|r| Arc::new(r));

        // Optional external fallback (demo-friendly) — ip-api.com (no key).
        // Privacy note: enabling this sends IPs to a third-party.
        // Default behavior:
        // - If MaxMind DB is present: do NOT use external.
        // - If MaxMind DB is missing: external is enabled unless explicitly disabled.
        let allow_external = std::env::var("PERCEPTA_GEOIP_ALLOW_EXTERNAL")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(reader.is_none());
        let external = if allow_external && reader.is_none() {
            warn!("GeoIP MaxMind DB not found; enabling external GeoIP fallback (ip-api.com). Set PERCEPTA_GEOIP_ALLOW_EXTERNAL=0 to disable.");
            Some(IpApiClient::from_env())
        } else {
            None
        };

        Self { reader, external }
    }

    pub fn available(&self) -> bool {
        self.reader.is_some() || self.external.is_some()
    }

    pub fn lookup_city(&self, ip: IpAddr) -> Option<GeoPoint> {
        let reader = self.reader.as_ref()?;
        let city: geoip2::City = reader.lookup(ip).ok()?;
        let loc = city.location?;
        let lat = loc.latitude?;
        let lon = loc.longitude?;

        let country = city
            .country
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string());
        let city_name = city
            .city
            .and_then(|c| c.names)
            .and_then(|names| names.get("en").map(|s| s.to_string()));

        Some(GeoPoint {
            lat,
            lon,
            country,
            city: city_name,
        })
    }

    pub async fn lookup_batch(&self, ips: &[String]) -> HashMap<String, GeoPoint> {
        let mut results = HashMap::new();

        // Prefer MaxMind if present.
        if self.reader.is_some() {
            for ip_str in ips.iter().take(200) {
                let ip = match ip_str.parse::<IpAddr>() {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if ip.is_loopback() {
                    continue;
                }
                if let Some(point) = self.lookup_city(ip) {
                    results.insert(ip_str.clone(), point);
                }
            }
            return results;
        }

        // Fall back to external provider if enabled.
        if let Some(ext) = self.external.as_ref() {
            return ext.lookup_batch(ips).await;
        }

        results
    }
}

#[derive(Clone)]
struct IpApiClient {
    http: reqwest::Client,
    base_url: String,
    cache: Arc<RwLock<HashMap<String, (Instant, GeoPoint)>>>,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct IpApiResp {
    status: String,
    #[serde(default)]
    #[allow(dead_code)]
    message: Option<String>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    lat: Option<f64>,
    #[serde(default)]
    lon: Option<f64>,
    #[serde(default)]
    countryCode: Option<String>,
    #[serde(default)]
    city: Option<String>,
}

impl IpApiClient {
    fn from_env() -> Self {
        let base_url = std::env::var("PERCEPTA_GEOIP_IPAPI_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "http://ip-api.com".to_string());

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .user_agent("percepta-siem/0.1 (geoip)")
            .build()
            .expect("reqwest geoip client");

        Self {
            http,
            base_url,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn lookup_batch(&self, ips: &[String]) -> HashMap<String, GeoPoint> {
        let mut out = HashMap::new();

        // TTL: 24 hours for demo.
        let ttl = Duration::from_secs(24 * 3600);

        // Pull from cache first.
        let mut missing: Vec<String> = Vec::new();
        {
            let r = self.cache.read().await;
            for ip in ips.iter().take(200) {
                if let Some((t, gp)) = r.get(ip) {
                    if t.elapsed() < ttl {
                        out.insert(ip.clone(), gp.clone());
                        continue;
                    }
                }
                missing.push(ip.clone());
            }
        }

        if missing.is_empty() {
            return out;
        }

        // ip-api batch supports arrays; keep small for safety.
        // Fields: keep minimal to avoid extra data.
        let url = format!(
            "{}/batch?fields=status,message,query,lat,lon,countryCode,city",
            self.base_url.trim_end_matches('/')
        );

        // ip-api may reject private/invalid; that's OK.
        let req_ips: Vec<String> = missing
            .into_iter()
            .filter(|ip| ip.parse::<IpAddr>().is_ok())
            .filter(|ip| {
                // Skip loopback.
                ip.parse::<IpAddr>().map(|v| !v.is_loopback()).unwrap_or(false)
            })
            .take(100)
            .collect();

        if req_ips.is_empty() {
            return out;
        }

        let resp = self
            .http
            .post(url)
            .json(&req_ips)
            .send()
            .await;

        let resp = match resp {
            Ok(r) => r,
            Err(_) => return out,
        };

        let resp = match resp.error_for_status() {
            Ok(r) => r,
            Err(_) => return out,
        };

        let rows: Vec<IpApiResp> = match resp.json().await {
            Ok(v) => v,
            Err(_) => return out,
        };

        let mut w = self.cache.write().await;
        for row in rows {
            if row.status != "success" {
                continue;
            }
            let ip = match row.query {
                Some(q) => q,
                None => continue,
            };
            let lat = match row.lat {
                Some(v) => v,
                None => continue,
            };
            let lon = match row.lon {
                Some(v) => v,
                None => continue,
            };

            let gp = GeoPoint {
                lat,
                lon,
                country: row.countryCode,
                city: row.city,
            };
            w.insert(ip.clone(), (Instant::now(), gp.clone()));
            out.insert(ip, gp);
        }

        // Soft cap.
        if w.len() > 2000 {
            let keys: Vec<String> = w.keys().take(200).cloned().collect();
            for k in keys {
                w.remove(&k);
            }
        }

        out
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GeoIpBatchRequest {
    pub ips: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct GeoIpBatchResponse {
    pub available: bool,
    pub results: HashMap<String, GeoPoint>,
}

pub async fn geoip_batch(
    State(state): State<AppState>,
    Json(req): Json<GeoIpBatchRequest>,
) -> Json<GeoIpBatchResponse> {
    let svc = match state.geoip.as_ref() {
        Some(s) => s.clone(),
        None => {
            return Json(GeoIpBatchResponse {
                available: false,
                results: HashMap::new(),
            })
        }
    };

    if !svc.available() {
        return Json(GeoIpBatchResponse {
            available: false,
            results: HashMap::new(),
        });
    }

    let ips: Vec<String> = req.ips.into_iter().take(200).collect();
    let results = svc.lookup_batch(&ips).await;

    Json(GeoIpBatchResponse {
        available: true,
        results,
    })
}
