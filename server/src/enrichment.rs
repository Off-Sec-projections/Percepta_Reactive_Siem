//! Unified Enrichment Pipeline
//!
//! Orchestrates all enrichment operations for incoming events:
//! - GeoIP lookups
//! - Threat intelligence
//! - MITRE ATT&CK mapping
//! - Community ID calculation
//! - Hash extraction
//!
//! This module fills the gaps identified in the SIEM workflow analysis.

use percepta_server::percepta::Event;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::geoip::GeoIpService;
use crate::intel::IntelService;

/// Enrichment orchestrator that coordinates all enrichment operations
#[derive(Clone)]
pub struct EnrichmentOrchestrator {
    geoip: Option<Arc<GeoIpService>>,
    intel: Option<Arc<IntelService>>,
    cache: Arc<tokio::sync::RwLock<EnrichmentCache>>,
    intel_timeout: std::time::Duration,
    intel_semaphore: Arc<Semaphore>,
    inflight_ttl: std::time::Duration,
    health: Arc<tokio::sync::RwLock<EnrichmentHealth>>,
}

#[derive(Debug, Clone)]
struct EnrichmentHealth {
    intel_failures: u64,
    intel_window_start: std::time::Instant,
    intel_disabled_until: Option<std::time::Instant>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IntelCircuitBreakerStatus {
    pub active: bool,
    pub failures_in_window: u64,
    pub retry_after_seconds: u64,
}

struct EnrichmentCache {
    geoip_cache: HashMap<String, CachedGeo>,
    intel_cache: HashMap<String, CachedIntel>,
    intel_inflight: HashMap<String, std::time::Instant>,
    max_entries: usize,
}

#[derive(Clone)]
struct CachedGeo {
    country: Option<String>,
    city: Option<String>,
    lat: f64,
    lon: f64,
    expires_at: std::time::Instant,
}

#[derive(Clone)]
struct CachedIntel {
    threat_level: Option<String>,
    categories: Vec<String>,
    expires_at: std::time::Instant,
}

impl EnrichmentOrchestrator {
    pub fn new(geoip: Option<Arc<GeoIpService>>, intel: Option<Arc<IntelService>>) -> Self {
        Self {
            geoip,
            intel,
            cache: Arc::new(tokio::sync::RwLock::new(EnrichmentCache {
                geoip_cache: HashMap::new(),
                intel_cache: HashMap::new(),
                intel_inflight: HashMap::new(),
                max_entries: 10_000,
            })),
            intel_timeout: std::time::Duration::from_millis(1200),
            intel_semaphore: Arc::new(Semaphore::new(2)),
            inflight_ttl: std::time::Duration::from_secs(60),
            health: Arc::new(tokio::sync::RwLock::new(EnrichmentHealth {
                intel_failures: 0,
                intel_window_start: std::time::Instant::now(),
                intel_disabled_until: None,
            })),
        }
    }

    async fn intel_allowed(&self) -> bool {
        let now = std::time::Instant::now();
        let h = self.health.read().await;
        match h.intel_disabled_until {
            Some(until) => now >= until,
            None => true,
        }
    }

    pub async fn intel_circuit_breaker_status(&self) -> IntelCircuitBreakerStatus {
        let now = std::time::Instant::now();
        let h = self.health.read().await;
        let retry_after_seconds = h
            .intel_disabled_until
            .and_then(|until| {
                if until > now {
                    Some(until.duration_since(now).as_secs())
                } else {
                    None
                }
            })
            .unwrap_or(0);

        IntelCircuitBreakerStatus {
            active: retry_after_seconds > 0,
            failures_in_window: h.intel_failures,
            retry_after_seconds,
        }
    }

    /// Enrich a single event with all available data
    pub async fn enrich_event(&self, event: &mut Event) {
        // Stage 1: GeoIP enrichment for all IPs
        self.enrich_geoip(event).await;

        // Stage 2: Threat intel lookups for IOCs
        self.enrich_threat_intel(event).await;

        // Stage 3: Network enrichment
        self.enrich_network(event);

        // Stage 4: MITRE ATT&CK mapping
        self.enrich_mitre_attack(event);

        // Stage 5: Hash extraction and validation
        self.enrich_hashes(event);

        // Stage 6: Process lineage context
        self.enrich_process_context(event);

        // Stage 7: Session and identity context
        self.enrich_session_context(event);
    }

    /// Add process lineage context (suspicious parent-child relationships, admin processes).
    fn enrich_process_context(&self, event: &mut Event) {
        if let Some(proc) = event.process.as_ref() {
            let name_lower = proc.name.to_lowercase();
            let cmd_lower = proc.command_line.to_lowercase();

            // Tag suspicious interpreter chains
            let is_script_engine = matches!(
                name_lower.as_str(),
                "powershell.exe"
                    | "pwsh.exe"
                    | "cmd.exe"
                    | "wscript.exe"
                    | "cscript.exe"
                    | "mshta.exe"
                    | "bash"
                    | "sh"
                    | "python"
                    | "python3"
                    | "perl"
            );
            if is_script_engine {
                event
                    .metadata
                    .insert("process.is_script_engine".to_string(), "true".to_string());
            }

            // Tag LOLBin processes
            let is_lolbin = matches!(
                name_lower.as_str(),
                "certutil.exe"
                    | "bitsadmin.exe"
                    | "rundll32.exe"
                    | "regsvr32.exe"
                    | "mshta.exe"
                    | "wmic.exe"
                    | "cmstp.exe"
                    | "msiexec.exe"
                    | "installutil.exe"
                    | "regasm.exe"
                    | "regsvcs.exe"
            );
            if is_lolbin {
                event
                    .metadata
                    .insert("process.is_lolbin".to_string(), "true".to_string());
            }

            // Detect download + execute patterns
            if cmd_lower.contains("http://") || cmd_lower.contains("https://") {
                event
                    .metadata
                    .insert("process.has_url".to_string(), "true".to_string());
            }

            // System vs user process
            if proc.pid < 10 || name_lower == "system" || name_lower == "system idle process" {
                event
                    .metadata
                    .insert("process.is_system".to_string(), "true".to_string());
            }
        }
    }

    /// Add session and identity context for correlation.
    fn enrich_session_context(&self, event: &mut Event) {
        // Compute stable session key for correlation
        let agent_id = event.agent.as_ref().map(|a| a.id.as_str()).unwrap_or("");
        let user = event.user.as_ref().map(|u| u.name.as_str()).unwrap_or("");
        let src_ip = event
            .network
            .as_ref()
            .map(|n| n.src_ip.as_str())
            .unwrap_or("");

        if !agent_id.is_empty() && !user.is_empty() {
            event
                .metadata
                .entry("session.key".to_string())
                .or_insert_with(|| format!("{}:{}", agent_id, user));
        }

        if !src_ip.is_empty() && !user.is_empty() {
            event
                .metadata
                .entry("session.user_ip".to_string())
                .or_insert_with(|| format!("{}@{}", user, src_ip));
        }

        // Tag admin-like users
        if let Some(u) = event.user.as_ref() {
            let name_lower = u.name.to_lowercase();
            if name_lower == "administrator"
                || name_lower == "admin"
                || name_lower == "root"
                || name_lower == "system"
                || name_lower.starts_with("svc_")
            {
                event
                    .metadata
                    .insert("user.is_privileged".to_string(), "true".to_string());
            }

            let has_admin_priv = u.privileges.iter().any(|p| {
                let pl = p.to_lowercase();
                pl.contains("admin")
                    || pl.contains("sebackup")
                    || pl.contains("sedebug")
                    || pl.contains("seimpersonate")
                    || pl.contains("seassignprimarytoken")
            });
            if has_admin_priv {
                event
                    .metadata
                    .insert("user.has_admin_privs".to_string(), "true".to_string());
            }
        }
    }

    /// Enrich GeoIP data for source and destination IPs
    async fn enrich_geoip(&self, event: &mut Event) {
        let geoip = match self.geoip.as_ref() {
            Some(g) if g.available() => g,
            _ => return,
        };

        let mut ips_to_lookup = Vec::new();

        // Collect IPs from event
        if let Some(net) = event.network.as_ref() {
            if !net.src_ip.is_empty() {
                ips_to_lookup.push(("src", net.src_ip.clone()));
            }
            if !net.dst_ip.is_empty() {
                ips_to_lookup.push(("dst", net.dst_ip.clone()));
            }
        }

        // Also check metadata for normalized IPs
        for key in ["norm.src_ip", "norm.dst_ip", "norm.host_ip"] {
            if let Some(ip_str) = event.metadata.get(key) {
                if !ip_str.is_empty() {
                    let prefix = if key.contains("src") {
                        "src"
                    } else if key.contains("dst") {
                        "dst"
                    } else {
                        "host"
                    };
                    ips_to_lookup.push((prefix, ip_str.clone()));
                }
            }
        }

        // Check cache first
        let mut cache = self.cache.write().await;
        let now = std::time::Instant::now();

        for (prefix, ip_str) in ips_to_lookup {
            if let Some(cached) = cache.geoip_cache.get(&ip_str) {
                if cached.expires_at > now {
                    // Use cached data
                    self.apply_geoip_to_event(event, prefix, cached);
                    continue;
                }
            }

            // Parse IP
            let ip: IpAddr = match ip_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };

            // For private/loopback IPs, resolve via the server's public IP so we
            // still get a GeoIP location (the network's egress point).
            let lookup_ip: IpAddr = if ip.is_loopback() || ip.is_unspecified() || is_private_ip(&ip) {
                let pub_host = std::env::var("PERCEPTA_PUBLIC_HOST").unwrap_or_default();
                match pub_host.parse::<IpAddr>() {
                    Ok(pub_ip) if !pub_ip.is_loopback() && !pub_ip.is_unspecified() && !is_private_ip(&pub_ip) => pub_ip,
                    _ => continue, // no usable public IP configured — skip
                }
            } else {
                ip
            };

            // Lookup
            if let Some(geo) = geoip.lookup_city(lookup_ip) {
                let cached = CachedGeo {
                    country: geo.country.clone(),
                    city: geo.city.clone(),
                    lat: geo.lat,
                    lon: geo.lon,
                    expires_at: now + std::time::Duration::from_secs(3600 * 24), // 24h TTL
                };

                self.apply_geoip_to_event(event, prefix, &cached);
                cache.geoip_cache.insert(ip_str.clone(), cached);
            }
        }

        // Prune cache if too large
        if cache.geoip_cache.len() > cache.max_entries {
            let keys: Vec<String> = cache
                .geoip_cache
                .iter()
                .filter(|(_, v)| v.expires_at < now)
                .map(|(k, _)| k.clone())
                .take(1000)
                .collect();
            for k in keys {
                cache.geoip_cache.remove(&k);
            }
        }
    }

    fn apply_geoip_to_event(&self, event: &mut Event, prefix: &str, geo: &CachedGeo) {
        if let Some(country) = &geo.country {
            event
                .metadata
                .insert(format!("geo.{}.country", prefix), country.clone());
        }
        if let Some(city) = &geo.city {
            event
                .metadata
                .insert(format!("geo.{}.city", prefix), city.clone());
        }
        event.metadata.insert(
            format!("geo.{}.lat_lon", prefix),
            format!("{},{}", geo.lat, geo.lon),
        );
    }

    /// Enrich threat intelligence data
    async fn enrich_threat_intel(&self, event: &mut Event) {
        let intel = match self.intel.as_ref() {
            Some(i) if i.enabled() => i,
            _ => return,
        };

        if !self.intel_allowed().await {
            event
                .metadata
                .entry("intel.skipped".to_string())
                .or_insert_with(|| "circuit_breaker".to_string());
            return;
        }

        let mut iocs = self.extract_iocs(event);
        if iocs.is_empty() {
            return;
        }

        let now = std::time::Instant::now();

        for (ioc_type, ioc_value) in iocs.drain(..) {
            // Check cache
            let cache_key = format!("{}:{}", ioc_type, ioc_value);
            {
                let cache = self.cache.read().await;
                if let Some(cached) = cache.intel_cache.get(&cache_key) {
                    if cached.expires_at > now {
                        self.apply_intel_to_event(event, &ioc_type, &ioc_value, cached);
                        continue;
                    }
                }
            }

            let should_schedule = {
                let mut w = self.cache.write().await;
                let now = std::time::Instant::now();
                let expired: Vec<String> = w
                    .intel_inflight
                    .iter()
                    .filter(|(_, t)| now.duration_since(**t) > self.inflight_ttl)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in expired {
                    w.intel_inflight.remove(&k);
                }
                if w.intel_inflight.contains_key(&cache_key) {
                    false
                } else {
                    w.intel_inflight.insert(cache_key.clone(), now);
                    true
                }
            };

            if should_schedule {
                let intel = intel.clone();
                let cache = self.cache.clone();
                let sem = self.intel_semaphore.clone();
                let timeout_dur = self.intel_timeout;
                let ioc_type = ioc_type.clone();
                let ioc_value = ioc_value.clone();
                let cache_key = cache_key.clone();
                let health = self.health.clone();
                tokio::spawn(async move {
                    let permit = match sem.acquire().await {
                        Ok(p) => p,
                        Err(_) => return,
                    };

                    let resp = if ioc_type == "ip" {
                        timeout(timeout_dur, intel.enrich_ip(&ioc_value)).await
                    } else if ioc_type.starts_with("hash_") && ioc_value.len() == 64 {
                        timeout(timeout_dur, intel.enrich_hash(&ioc_value)).await
                    } else {
                        drop(permit);
                        let mut w = cache.write().await;
                        w.intel_inflight.remove(&cache_key);
                        return;
                    };
                    drop(permit);

                    let cached = match resp {
                        Ok(val) => {
                            let c =
                                EnrichmentOrchestrator::cached_intel_from_response(&ioc_type, &val);
                            if c.is_some() {
                                let mut h = health.write().await;
                                h.intel_failures = 0;
                                h.intel_disabled_until = None;
                            }
                            c
                        }
                        Err(_) => {
                            let mut h = health.write().await;
                            let now = std::time::Instant::now();
                            if now.duration_since(h.intel_window_start).as_secs() > 300 {
                                h.intel_window_start = now;
                                h.intel_failures = 0;
                            }
                            h.intel_failures = h.intel_failures.saturating_add(1);
                            if h.intel_failures >= 5 {
                                h.intel_disabled_until =
                                    Some(now + std::time::Duration::from_secs(300));
                            }
                            None
                        }
                    };

                    let mut w = cache.write().await;
                    if let Some(cached) = cached {
                        w.intel_cache.insert(cache_key.clone(), cached);
                    }
                    w.intel_inflight.remove(&cache_key);

                    // Prune expired intel cache entries if over limit
                    if w.intel_cache.len() > w.max_entries {
                        let now = std::time::Instant::now();
                        w.intel_cache.retain(|_, v| v.expires_at > now);
                        // If still over limit, evict oldest half
                        if w.intel_cache.len() > w.max_entries {
                            let remove_count = w.intel_cache.len() / 2;
                            let keys: Vec<String> =
                                w.intel_cache.keys().take(remove_count).cloned().collect();
                            for k in keys {
                                w.intel_cache.remove(&k);
                            }
                        }
                    }
                });
            }

            event
                .metadata
                .entry(format!("intel.{}.checked", ioc_type))
                .or_insert_with(|| "true".to_string());
        }
    }

    fn cached_intel_from_response(ioc_type: &str, v: &Value) -> Option<CachedIntel> {
        let providers = v.get("providers")?.as_object()?;
        let mut categories: Vec<String> = Vec::new();
        let mut threat_level: Option<String> = None;

        if let Some(otx) = providers.get("otx") {
            let pulses = otx
                .get("pulse_info")
                .and_then(|p| p.get("count"))
                .and_then(|c| c.as_u64())
                .unwrap_or(0);
            if pulses > 0 {
                categories.push("otx_pulse".to_string());
                threat_level.get_or_insert_with(|| "medium".to_string());
            }
        }

        if let Some(abuse) = providers.get("abuseipdb") {
            let score = abuse
                .get("data")
                .and_then(|d| d.get("abuseConfidenceScore"))
                .and_then(|s| s.as_i64())
                .unwrap_or(0);
            if score > 0 {
                categories.push("abuseipdb".to_string());
                let lvl = if score >= 50 { "high" } else { "medium" };
                threat_level = Some(lvl.to_string());
            }
        }

        if let Some(urlhaus) = providers.get("urlhaus") {
            if urlhaus
                .get("query_status")
                .and_then(|s| s.as_str())
                .map(|s| s == "ok")
                .unwrap_or(false)
            {
                categories.push("urlhaus".to_string());
                threat_level.get_or_insert_with(|| "medium".to_string());
            }
        }

        if let Some(mbz) = providers.get("malwarebazaar") {
            let ok = mbz
                .get("query_status")
                .and_then(|s| s.as_str())
                .map(|s| s == "ok")
                .unwrap_or(false);
            let has_data = mbz
                .get("data")
                .and_then(|d| d.as_array())
                .map(|d| !d.is_empty())
                .unwrap_or(false);
            if ok || has_data {
                categories.push("malwarebazaar".to_string());
                threat_level.get_or_insert_with(|| "high".to_string());
            }
        }

        if categories.is_empty() {
            return None;
        }

        let ttl = if ioc_type == "ip" {
            std::time::Duration::from_secs(600)
        } else {
            std::time::Duration::from_secs(1800)
        };

        Some(CachedIntel {
            threat_level,
            categories,
            expires_at: std::time::Instant::now() + ttl,
        })
    }

    fn extract_iocs(&self, event: &Event) -> Vec<(String, String)> {
        let mut iocs = Vec::new();

        // Extract IP IOCs
        if let Some(net) = event.network.as_ref() {
            if !net.src_ip.is_empty() && self.is_public_ip(&net.src_ip) {
                iocs.push(("ip".to_string(), net.src_ip.clone()));
            }
            if !net.dst_ip.is_empty() && self.is_public_ip(&net.dst_ip) {
                iocs.push(("ip".to_string(), net.dst_ip.clone()));
            }
        }

        // Extract hash IOCs
        if let Some(proc) = event.process.as_ref() {
            for (hash_type, hash_value) in &proc.hash {
                if hash_value.len() >= 32 {
                    iocs.push((format!("hash_{}", hash_type), hash_value.clone()));
                }
            }
        }

        // Extract domain IOCs from metadata
        if let Some(domain) = event.metadata.get("dns.query") {
            if !domain.is_empty() {
                iocs.push(("domain".to_string(), domain.clone()));
            }
        }

        iocs
    }

    fn is_public_ip(&self, ip_str: &str) -> bool {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            !ip.is_loopback() && !ip.is_unspecified() && !is_private_ip(&ip)
        } else {
            false
        }
    }

    fn apply_intel_to_event(
        &self,
        event: &mut Event,
        ioc_type: &str,
        _ioc_value: &str,
        intel: &CachedIntel,
    ) {
        if let Some(threat_level) = &intel.threat_level {
            event
                .metadata
                .insert(format!("threat.{}.level", ioc_type), threat_level.clone());
        }
        if !intel.categories.is_empty() {
            event.metadata.insert(
                format!("threat.{}.categories", ioc_type),
                intel.categories.join(","),
            );
            event.tags.push("threat_match".to_string());
        }
    }

    /// Enrich network context
    fn enrich_network(&self, event: &mut Event) {
        if let Some(net) = event.network.as_mut() {
            // Calculate community ID for correlation
            if !net.src_ip.is_empty()
                && !net.dst_ip.is_empty()
                && net.src_port > 0
                && net.dst_port > 0
            {
                if let Some(community_id) = calculate_community_id(
                    &net.src_ip,
                    net.src_port,
                    &net.dst_ip,
                    net.dst_port,
                    &net.protocol,
                ) {
                    event
                        .metadata
                        .insert("network.community_id".to_string(), community_id);
                }
            }

            // Classify network direction
            if net.direction == 0 {
                // DirUnknown
                net.direction = self.infer_direction(&net.src_ip, &net.dst_ip);
            }

            // Decode protocol numbers
            if net.protocol.is_empty() {
                if let Some(proto_num) = event.metadata.get("protocol_number") {
                    if let Ok(num) = proto_num.parse::<u8>() {
                        net.protocol = protocol_number_to_name(num);
                    }
                }
            }
        }
    }

    fn infer_direction(&self, src_ip: &str, dst_ip: &str) -> i32 {
        // Simple heuristic: if source is private and dest is public, it's outbound
        let src_private = src_ip
            .parse::<IpAddr>()
            .map(|ip| is_private_ip(&ip))
            .unwrap_or(false);
        let dst_private = dst_ip
            .parse::<IpAddr>()
            .map(|ip| is_private_ip(&ip))
            .unwrap_or(false);

        use percepta_server::percepta::event::NetworkDirection;
        if src_private && !dst_private {
            NetworkDirection::Outbound as i32
        } else if !src_private && dst_private {
            NetworkDirection::Inbound as i32
        } else {
            NetworkDirection::DirUnknown as i32
        }
    }

    /// Add MITRE ATT&CK technique mapping
    fn enrich_mitre_attack(&self, event: &mut Event) {
        // Map event characteristics to MITRE techniques
        let techniques = self.map_to_mitre_techniques(event);
        if !techniques.is_empty() {
            let tactics = Self::derive_mitre_tactics(&techniques);
            event
                .metadata
                .insert("mitre.techniques".to_string(), techniques.join(","));
            // Canonical compatibility keys used by alerting/reporting/UX paths.
            event
                .metadata
                .insert("mitre_attack".to_string(), techniques.join(","));
            event
                .metadata
                .insert("mitre_techniques".to_string(), techniques.join(","));
            if !tactics.is_empty() {
                event
                    .metadata
                    .insert("mitre.tactics".to_string(), tactics.join(","));
                event
                    .metadata
                    .insert("mitre_tactics".to_string(), tactics.join(","));
            }
        }
    }

    fn derive_mitre_tactics(techniques: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut push = |name: &str| {
            if !out.iter().any(|x| x == name) {
                out.push(name.to_string());
            }
        };

        for t in techniques {
            if t.starts_with("T1059") || t == "T1047" {
                push("execution");
            }
            if t == "T1027" || t.starts_with("T1218") {
                push("defense-evasion");
            }
            if t == "T1078" {
                push("persistence");
                push("privilege-escalation");
            }
            if t.starts_with("T1053") || t.starts_with("T1543") {
                push("persistence");
            }
            if t.starts_with("T1003") {
                push("credential-access");
            }
            if t.starts_with("T1021") {
                push("lateral-movement");
            }
        }
        out
    }

    fn map_to_mitre_techniques(&self, event: &Event) -> Vec<String> {
        let mut techniques = Vec::new();

        let action = event
            .event
            .as_ref()
            .map(|e| e.action.as_str())
            .unwrap_or("");
        let category = event.event.as_ref().map(|e| e.category).unwrap_or(0);
        let summary_lc = event
            .event
            .as_ref()
            .map(|e| e.summary.to_lowercase())
            .unwrap_or_default();

        use percepta_server::percepta::event::EventCategory;

        // Process creation with suspicious patterns
        if category == EventCategory::Process as i32 {
            if let Some(proc) = event.process.as_ref() {
                let cmd = proc.command_line.to_lowercase();
                let name = proc.name.to_lowercase();
                if cmd.contains("powershell") && cmd.contains("-enc") {
                    techniques.push("T1059.001".to_string()); // PowerShell
                    techniques.push("T1027".to_string()); // Obfuscated Files or Information
                }
                if cmd.contains("wmic") {
                    techniques.push("T1047".to_string()); // Windows Management Instrumentation
                }
                if cmd.contains("rundll32") {
                    techniques.push("T1218.011".to_string()); // Rundll32
                }
                if cmd.contains("mshta") {
                    techniques.push("T1218.005".to_string()); // Mshta
                }
                if cmd.contains("certutil") && (cmd.contains("-urlcache") || cmd.contains("-decode")) {
                    techniques.push("T1140".to_string()); // Deobfuscate/Decode Files
                }
                if cmd.contains("bitsadmin") && cmd.contains("/transfer") {
                    techniques.push("T1197".to_string()); // BITS Jobs
                }
                if cmd.contains("reg ") && (cmd.contains("add") || cmd.contains("export")) {
                    techniques.push("T1112".to_string()); // Modify Registry
                }
                if name == "cmd.exe" || name == "bash" || name == "sh" {
                    techniques.push("T1059.003".to_string()); // Windows Command Shell / Unix Shell
                }
                if cmd.contains("cscript") || cmd.contains("wscript") {
                    techniques.push("T1059.005".to_string()); // Visual Basic
                }
                if cmd.contains("python") || cmd.contains("python3") {
                    techniques.push("T1059.006".to_string()); // Python
                }
                if cmd.contains("net user") || cmd.contains("net localgroup") {
                    techniques.push("T1136.001".to_string()); // Create Account: Local
                }
                if cmd.contains("whoami") || cmd.contains("net user") || cmd.contains("id ") {
                    techniques.push("T1033".to_string()); // System Owner/User Discovery
                }
                if cmd.contains("ipconfig") || cmd.contains("ifconfig") || cmd.contains("hostname") {
                    techniques.push("T1016".to_string()); // System Network Configuration Discovery
                }
                if cmd.contains("tasklist") || cmd.contains("ps aux") || cmd.contains("ps -e") {
                    techniques.push("T1057".to_string()); // Process Discovery
                }
                if cmd.contains("net share") || cmd.contains("smbclient") {
                    techniques.push("T1135".to_string()); // Network Share Discovery
                }
            }
        }

        // File events — suspicious file modifications
        if category == EventCategory::File as i32 {
            if let Some(file) = event.file.as_ref() {
                let path = file.path.to_lowercase();
                if path.contains("startup") || path.contains("autorun") {
                    techniques.push("T1547.001".to_string()); // Boot or Logon Autostart: Registry Run Keys
                }
                if path.contains(".lnk") {
                    techniques.push("T1547.009".to_string()); // Shortcut Modification
                }
            }
        }

        // Privilege escalation
        if action == "privilege_escalation" || action == "privilege_assignment" {
            techniques.push("T1078".to_string()); // Valid Accounts
        }

        // Authentication events
        if action.contains("logon_failure") || action.contains("auth_fail") {
            techniques.push("T1110".to_string()); // Brute Force
        }

        // Scheduled tasks
        if action.contains("scheduled_task") {
            techniques.push("T1053".to_string()); // Scheduled Task/Job
        }

        // Service installation
        if action.contains("service_install") {
            techniques.push("T1543.003".to_string()); // Windows Service
        }

        // Credential access
        if action.contains("password") || action.contains("credential") {
            techniques.push("T1003".to_string()); // OS Credential Dumping
        }

        // Honeypot trap events — reconnaissance / initial access
        if event.tags.iter().any(|t| t == "honeypot") {
            techniques.push("T1595".to_string()); // Active Scanning
            if summary_lc.contains("login") || summary_lc.contains("credential") {
                techniques.push("T1078".to_string()); // Valid Accounts
            }
        }

        // DNS events — potential exfiltration or C2
        if (action.contains("dns") || category == EventCategory::Network as i32)
            && summary_lc.contains("dns") && summary_lc.contains("txt")
        {
            techniques.push("T1071.004".to_string()); // Application Layer Protocol: DNS
        }

        // Network connections to suspicious ports
        if let Some(net) = event.network.as_ref() {
            if net.dst_port == 445 || net.dst_port == 139 {
                techniques.push("T1021.002".to_string()); // SMB/Windows Admin Shares
            }
            if net.dst_port == 3389 {
                techniques.push("T1021.001".to_string()); // Remote Desktop Protocol
            }
            if net.dst_port == 22 {
                techniques.push("T1021.004".to_string()); // SSH
            }
            if net.dst_port == 5985 || net.dst_port == 5986 {
                techniques.push("T1021.006".to_string()); // Windows Remote Management
            }
        }

        techniques.sort();
        techniques.dedup();
        techniques
    }

    /// Validate and extract file hashes
    fn enrich_hashes(&self, event: &mut Event) {
        // Validate process hashes
        if let Some(proc) = event.process.as_mut() {
            proc.hash.retain(|k, v| is_valid_hash(k, v));
        }

        // Extract hashes from metadata if present
        if let Some(hashes_str) = event.metadata.get("Hashes").cloned() {
            let mut proc_hash = HashMap::new();
            parse_sysmon_hashes(&hashes_str, &mut proc_hash);

            if !proc_hash.is_empty() {
                if let Some(proc) = event.process.as_mut() {
                    for (k, v) in proc_hash {
                        proc.hash.entry(k).or_insert(v);
                    }
                } else {
                    event.process = Some(percepta_server::percepta::event::Process {
                        pid: 0,
                        ppid: 0,
                        name: String::new(),
                        command_line: String::new(),
                        hash: proc_hash,
                    });
                }
            }
        }
    }
}

/// Check if IP is in private range (RFC 1918)
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            octets[0] == 10
                || (octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31))
                || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(_) => false, // Simplified
    }
}

/// Calculate community ID for network flow correlation
/// Based on: https://github.com/corelight/community-id-spec
fn calculate_community_id(
    src_ip: &str,
    src_port: u32,
    dst_ip: &str,
    dst_port: u32,
    protocol: &str,
) -> Option<String> {
    use openssl::sha::sha1;

    let proto_num = match protocol.to_lowercase().as_str() {
        "tcp" => 6u8,
        "udp" => 17u8,
        "icmp" => 1u8,
        _ => return None,
    };

    let src: IpAddr = src_ip.parse().ok()?;
    let dst: IpAddr = dst_ip.parse().ok()?;

    // Create ordered tuple (lower IP/port first for bidirectional matching)
    let (ip1, port1, ip2, port2) = if src < dst || (src == dst && src_port < dst_port) {
        (src, src_port as u16, dst, dst_port as u16)
    } else {
        (dst, dst_port as u16, src, src_port as u16)
    };

    // Build hash input per https://github.com/corelight/community-id-spec:
    //   seed(2B) || src_ip || dst_ip || proto(1B) || pad(1B) || src_port(2B BE) || dst_port(2B BE)
    let mut input = Vec::new();
    input.extend_from_slice(&[0u8, 0u8]); // seed (2 bytes, zeroed)

    match (ip1, ip2) {
        (IpAddr::V4(ip1), IpAddr::V4(ip2)) => {
            input.extend_from_slice(&ip1.octets());
            input.extend_from_slice(&ip2.octets());
        }
        (IpAddr::V6(ip1), IpAddr::V6(ip2)) => {
            input.extend_from_slice(&ip1.octets());
            input.extend_from_slice(&ip2.octets());
        }
        _ => return None, // Mixed v4/v6
    }

    input.push(proto_num); // proto after IPs
    input.push(0u8);       // padding byte
    input.extend_from_slice(&port1.to_be_bytes());
    input.extend_from_slice(&port2.to_be_bytes());

    let hash = sha1(&input);
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);

    Some(format!("1:{}", b64))
}

/// Map protocol number to name
fn protocol_number_to_name(num: u8) -> String {
    match num {
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        47 => "gre".to_string(),
        50 => "esp".to_string(),
        51 => "ah".to_string(),
        58 => "icmpv6".to_string(),
        132 => "sctp".to_string(),
        _ => format!("proto_{}", num),
    }
}

/// Validate hash format
fn is_valid_hash(hash_type: &str, hash_value: &str) -> bool {
    let expected_len = match hash_type.to_lowercase().as_str() {
        "md5" => 32,
        "sha1" => 40,
        "sha256" => 64,
        "sha512" => 128,
        "imphash" => 32,
        _ => return hash_value.len() >= 32, // Unknown type, allow if reasonable length
    };

    hash_value.len() == expected_len && hash_value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse Sysmon-style hash string (SHA256=...,MD5=...,etc)
fn parse_sysmon_hashes(hashes: &str, target: &mut HashMap<String, String>) {
    for part in hashes.split([',', ';']) {
        if let Some((key, value)) = part.split_once('=') {
            let k = key.trim().to_lowercase();
            let v = value.trim().to_lowercase();
            if !k.is_empty() && !v.is_empty() && is_valid_hash(&k, &v) {
                target.insert(k, v);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_community_id_calculation() {
        let cid = calculate_community_id("192.168.1.100", 54321, "8.8.8.8", 53, "udp");
        assert!(cid.is_some());
        assert!(cid.unwrap().starts_with("1:"));
    }

    #[test]
    fn test_hash_validation() {
        assert!(is_valid_hash("sha256", "a".repeat(64).as_str()));
        assert!(is_valid_hash("md5", "a".repeat(32).as_str()));
        assert!(!is_valid_hash("sha256", "invalid"));
        assert!(!is_valid_hash("sha256", "a".repeat(63).as_str()));
    }

    #[test]
    fn test_parse_sysmon_hashes() {
        let mut hashes = HashMap::new();
        parse_sysmon_hashes(
            "SHA256=1234567890123456789012345678901234567890123456789012345678901234,MD5=12345678901234567890123456789012",
            &mut hashes,
        );
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains_key("sha256"));
        assert!(hashes.contains_key("md5"));
    }

    #[test]
    fn test_mitre_mapping() {
        let orchestrator = EnrichmentOrchestrator::new(None, None);
        let mut event = Event::default();
        event.event = Some(percepta_server::percepta::event::EventDetails {
            action: "process_create".to_string(),
            category: percepta_server::percepta::event::EventCategory::Process as i32,
            ..Default::default()
        });
        event.process = Some(percepta_server::percepta::event::Process {
            command_line: "powershell.exe -enc base64data".to_string(),
            ..Default::default()
        });

        let techniques = orchestrator.map_to_mitre_techniques(&event);
        assert!(techniques.contains(&"T1059.001".to_string())); // PowerShell
        assert!(techniques.contains(&"T1027".to_string())); // Obfuscation
    }
}
