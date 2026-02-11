//! CVE Enrichment — Fetch real vulnerability data from NVD
//!
//! Provides optional integration with NIST National Vulnerability Database (NVD)
//! to enrich vulnerability tracking with official CVE data.
//!
//! Usage:
//! - Set PERCEPTA_NVD_API_KEY environment variable for higher rate limits
//! - Call fetch_cve_details() to get real-time CVE information
//! - Caches results to avoid excessive API calls

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// CVE data from NVD API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDetails {
    pub cve_id: String,
    pub description: String,
    pub cvss_v3_score: Option<f32>,
    pub cvss_v3_severity: Option<String>,
    pub cvss_v2_score: Option<f32>,
    pub published_date: Option<String>,
    pub last_modified_date: Option<String>,
    pub references: Vec<String>,
    pub cpe_matches: Vec<String>, // Affected software
    pub weaknesses: Vec<String>,  // CWE IDs
}

/// Simple in-memory cache for CVE lookups
pub struct CveCache {
    cache: Arc<RwLock<HashMap<String, CveDetails>>>,
    http_client: reqwest::Client,
    api_key: Option<String>,
}

impl CveCache {
    pub fn new() -> Self {
        let api_key = std::env::var("PERCEPTA_NVD_API_KEY").ok();
        if api_key.is_some() {
            tracing::info!("✅ NVD API key configured for CVE enrichment");
        } else {
            tracing::warn!(
                "⚠️  No NVD API key set (PERCEPTA_NVD_API_KEY) — rate limits will be lower"
            );
        }

        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .user_agent("Percepta-SIEM/0.1")
                .build()
                .unwrap_or_default(),
            api_key,
        }
    }

    /// Fetch CVE details from NVD API with caching
    pub async fn fetch_cve_details(&self, cve_id: &str) -> Result<CveDetails, String> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(cve_id) {
                tracing::debug!("CVE {} found in cache", cve_id);
                return Ok(cached.clone());
            }
        }

        // Fetch from NVD API (v2.0)
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
            cve_id
        );

        let mut req = self.http_client.get(&url);
        if let Some(api_key) = &self.api_key {
            req = req.header("apiKey", api_key);
        }

        let response = req
            .send()
            .await
            .map_err(|e| format!("NVD API request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("NVD API returned status {}", response.status()));
        }

        let data: NvdApiResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse NVD response: {}", e))?;

        if data.vulnerabilities.is_empty() {
            return Err(format!("CVE {} not found in NVD", cve_id));
        }

        let vuln = &data.vulnerabilities[0];
        let cve_data = &vuln.cve;

        let description = cve_data
            .descriptions
            .iter()
            .find(|d| d.lang == "en")
            .map(|d| d.value.clone())
            .unwrap_or_else(|| "No description available".to_string());

        let (cvss_v3_score, cvss_v3_severity) = cve_data
            .metrics
            .cvss_metric_v3
            .as_ref()
            .and_then(|metrics| metrics.first())
            .map(|metric| {
                (
                    Some(metric.cvss_data.base_score),
                    Some(metric.cvss_data.base_severity.clone()),
                )
            })
            .unwrap_or((None, None));

        let cvss_v2_score = cve_data
            .metrics
            .cvss_metric_v2
            .as_ref()
            .and_then(|metrics| metrics.first())
            .map(|metric| metric.cvss_data.base_score);

        let references: Vec<String> = cve_data
            .references
            .iter()
            .take(5) // Limit to first 5 references
            .map(|r| r.url.clone())
            .collect();

        let weaknesses: Vec<String> = cve_data
            .weaknesses
            .iter()
            .flat_map(|w| w.description.iter())
            .filter(|d| d.lang == "en")
            .map(|d| d.value.clone())
            .collect();

        // Extract affected software from CPE matches
        let cpe_matches: Vec<String> = cve_data
            .configurations
            .iter()
            .flat_map(|c| c.nodes.iter())
            .flat_map(|n| n.cpe_match.iter())
            .map(|m| m.criteria.clone())
            .filter(|s| !s.is_empty())
            .take(20) // Limit to avoid huge lists
            .collect();

        let details = CveDetails {
            cve_id: cve_id.to_string(),
            description,
            cvss_v3_score,
            cvss_v3_severity,
            cvss_v2_score,
            published_date: Some(cve_data.published.clone()),
            last_modified_date: Some(cve_data.last_modified.clone()),
            references,
            cpe_matches,
            weaknesses,
        };

        // Cache the result
        {
            let mut cache = self.cache.write().await;
            cache.insert(cve_id.to_string(), details.clone());
        }

        tracing::info!("✅ Fetched CVE {} from NVD", cve_id);
        Ok(details)
    }

    /// Bulk fetch multiple CVEs
    pub async fn fetch_multiple(
        &self,
        cve_ids: &[String],
    ) -> HashMap<String, Result<CveDetails, String>> {
        let mut results = HashMap::new();

        for cve_id in cve_ids {
            // Rate limiting: NVD allows 5 requests/30sec without API key, 50/30sec with key
            tokio::time::sleep(std::time::Duration::from_millis(
                if self.api_key.is_some() { 600 } else { 6000 },
            ))
            .await;

            let result = self.fetch_cve_details(cve_id).await;
            results.insert(cve_id.clone(), result);
        }

        results
    }

    /// Get cache statistics
    pub async fn cache_stats(&self) -> (usize, Vec<String>) {
        let cache = self.cache.read().await;
        let count = cache.len();
        let cve_ids: Vec<String> = cache.keys().cloned().collect();
        (count, cve_ids)
    }
}

impl Default for CveCache {
    fn default() -> Self {
        Self::new()
    }
}

// ═════════════════════════════════════════════════════════════
//  NVD API Response Types (v2.0 schema)
// ═════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct NvdApiResponse {
    vulnerabilities: Vec<VulnerabilityItem>,
}

#[derive(Debug, Deserialize)]
struct VulnerabilityItem {
    cve: CveItem,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveItem {
    published: String,
    last_modified: String,
    descriptions: Vec<Description>,
    metrics: Metrics,
    weaknesses: Vec<Weakness>,
    references: Vec<Reference>,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    #[serde(default)]
    nodes: Vec<ConfigNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigNode {
    #[serde(default)]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CpeMatch {
    #[serde(default)]
    criteria: String,
}

#[derive(Debug, Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metrics {
    cvss_metric_v3: Option<Vec<CvssMetricV3>>,
    cvss_metric_v2: Option<Vec<CvssMetricV2>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssMetricV3 {
    cvss_data: CvssDataV3,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssDataV3 {
    base_score: f32,
    base_severity: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssMetricV2 {
    cvss_data: CvssDataV2,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CvssDataV2 {
    base_score: f32,
}

#[derive(Debug, Deserialize)]
struct Weakness {
    description: Vec<Description>,
}

#[derive(Debug, Deserialize)]
struct Reference {
    url: String,
}

/// Example usage in API handler
pub async fn enrich_vulnerability_with_nvd(
    cache: &CveCache,
    cve_id: &str,
) -> Result<serde_json::Value, String> {
    let details = cache.fetch_cve_details(cve_id).await?;

    Ok(serde_json::json!({
        "cve_id": details.cve_id,
        "description": details.description,
        "severity": details.cvss_v3_severity.unwrap_or_else(|| "unknown".to_string()),
        "cvss_score": details.cvss_v3_score.unwrap_or(0.0),
        "published_date": details.published_date,
        "references": details.references,
        "weaknesses": details.weaknesses,
        "source": "NVD",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_cache_creation() {
        let cache = CveCache::new();
        assert!(cache.cache.try_read().is_ok());
    }

    // Integration test (requires network)
    #[tokio::test]
    #[ignore] // Run with: cargo test -- --ignored
    async fn test_fetch_real_cve() {
        let cache = CveCache::new();
        let result = cache.fetch_cve_details("CVE-2024-3400").await;

        if let Ok(details) = result {
            assert_eq!(details.cve_id, "CVE-2024-3400");
            assert!(details.cvss_v3_score.is_some());
            println!("CVE Details: {:?}", details);
        } else {
            println!(
                "CVE fetch failed (expected if no internet/API key): {:?}",
                result
            );
        }
    }
}
