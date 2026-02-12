use anyhow::{Context, Result};
use percepta_server::percepta::event::{EventCategory, EventOutcome, NetworkDirection};
use percepta_server::percepta::{event::EventDetails, Event};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct WindowsEventMappings {
    security: HashMap<u64, HashMap<String, String>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ParsersFile {
    parsers: Vec<ParserDef>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct ParserDef {
    id: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    #[allow(dead_code)]
    channel: Option<String>,
    #[serde(default)]
    field_mappings: HashMap<u64, HashMap<String, String>>,
}

impl WindowsEventMappings {
    #[allow(dead_code)]
    pub async fn load_from_file(path: &Path) -> Result<Self> {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read parsers file: {}", path.display()))?;
        let parsed: ParsersFile = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse parsers file: {}", path.display()))?;

        let mut out = WindowsEventMappings::default();

        for p in parsed.parsers {
            if !p.enabled {
                continue;
            }
            if p.id != "windows_security" {
                continue;
            }
            // Treat channel as informational; we key by event_id.
            out.security = p.field_mappings;
        }

        Ok(out)
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.security.is_empty()
    }

    pub fn apply(&self, event: &mut Event) {
        let Some(event_id) = event_id_from_event(event) else {
            return;
        };
        let Some(map) = self.security.get(&event_id) else {
            return;
        };

        for (field, rule) in map {
            if let Some((kind, arg)) = parse_rule_value(rule) {
                match kind {
                    RuleKind::Const => {
                        apply_constant(event, field, arg, event_id);
                    }
                    RuleKind::Extract => {
                        if let Some(v) = extract_winlog_event_data(event, arg) {
                            apply_extracted(event, field, &v, event_id, rule);
                        }
                    }
                    RuleKind::ExtractList => {
                        if let Some(v) = extract_winlog_event_data(event, arg) {
                            apply_extracted_list(event, field, &v, event_id, rule);
                        }
                    }
                }
            }
        }

        // Convenience keys for correlation: normalize principals in metadata.
        // These are additive and never overwrite existing values.
        postprocess_windows_metadata(event);

        // Backfill canonical norm.user / norm.src_ip from Windows-specific fields for dashboard/reactive extraction.
        backfill_canonical_fields(event);
    }
}

fn postprocess_windows_metadata(event: &mut Event) {
    fn principal_short(s: &str) -> String {
        let t = s.trim();
        if t.is_empty() {
            return String::new();
        }
        if let Some((_, last)) = t.rsplit_once('\\') {
            last.trim().to_string()
        } else {
            t.to_string()
        }
    }

    if let Some(v) = event.metadata.get("metadata.target_user").cloned() {
        let short = principal_short(&v);
        if !short.is_empty() {
            event
                .metadata
                .entry("metadata.target_user_short".to_string())
                .or_insert(short);
        }
    }
    if let Some(v) = event.metadata.get("metadata.member").cloned() {
        let short = principal_short(&v);
        if !short.is_empty() {
            event
                .metadata
                .entry("metadata.member_short".to_string())
                .or_insert(short);
        }
    }
}

/// Backfill canonical norm.user/norm.src_ip from Windows-specific intermediate fields.
/// Dashboard and reactive extraction rely on these canonical keys; Windows events populate
/// norm.target_user / norm.subject_user / norm.logon_user / etc instead of norm.user directly.
/// This ensures the canonical keys are always populated for consistent extraction.
fn backfill_canonical_fields(event: &mut Event) {
    // Backfill norm.user from Windows-specific user fields (prefer target_user, fallback to subject_user).
    if !event.metadata.contains_key("norm.user") {
        let fallback = event
            .metadata
            .get("norm.target_user")
            .or_else(|| event.metadata.get("norm.subject_user"))
            .or_else(|| event.metadata.get("norm.logon_user"))
            .cloned();
        if let Some(user) = fallback {
            event.metadata.insert("norm.user".to_string(), user);
        }
    }

    // Backfill norm.src_ip from Windows-specific IP fields (IpAddress, WorkstationName as IP, etc).
    if !event.metadata.contains_key("norm.src_ip") {
        let fallback = event
            .metadata
            .get("winlog.event_data.IpAddress")
            .or_else(|| event.metadata.get("norm.workstation_ip"))
            .cloned();
        if let Some(ip) = fallback {
            event.metadata.insert("norm.src_ip".to_string(), ip);
        }
    }

    // Backfill norm.dst_ip from Windows-specific destination fields if missing.
    if !event.metadata.contains_key("norm.dst_ip") {
        if let Some(ip) = event.metadata.get("norm.target_ip").cloned() {
            event.metadata.insert("norm.dst_ip".to_string(), ip);
        }
    }

    // Backfill norm.user_domain from Windows-specific domain fields.
    if !event.metadata.contains_key("norm.user_domain") {
        let fallback = event
            .metadata
            .get("norm.target_domain")
            .or_else(|| event.metadata.get("norm.subject_domain"))
            .cloned();
        if let Some(domain) = fallback {
            event
                .metadata
                .insert("norm.user_domain".to_string(), domain);
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RuleKind {
    Const,
    Extract,
    ExtractList,
}

fn parse_rule_value(rule: &str) -> Option<(RuleKind, &str)> {
    let t = rule.trim();
    if let Some(inner) = t.strip_prefix("extract(").and_then(|s| s.strip_suffix(')')) {
        return Some((RuleKind::Extract, inner.trim()));
    }
    if let Some(inner) = t
        .strip_prefix("extract_list(")
        .and_then(|s| s.strip_suffix(')'))
    {
        return Some((RuleKind::ExtractList, inner.trim()));
    }
    Some((RuleKind::Const, t))
}

fn event_id_from_event(event: &Event) -> Option<u64> {
    if let Some(d) = event.event.as_ref() {
        if d.event_id != 0 {
            return Some(d.event_id);
        }
    }
    if let Some(s) = event.metadata.get("winlog.event_id") {
        return s.trim().parse::<u64>().ok();
    }
    None
}

fn extract_winlog_event_data(event: &Event, key: &str) -> Option<String> {
    let k = key.trim();
    if k.is_empty() {
        return None;
    }

    // Prefer normalized winlog keys.
    let primary = format!("winlog.event_data.{k}");
    if let Some(v) = event.metadata.get(&primary) {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }

    if let Some(v) = event.metadata.get(k) {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }

    let keyword = format!("winlog.event_data.{k}.keyword");
    if let Some(v) = event.metadata.get(&keyword) {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }

    None
}

fn set_provenance(metadata: &mut HashMap<String, String>, field: &str, event_id: u64, rule: &str) {
    // Keep this compact: allows tuning and debugging without bloating every event.
    // Example key: norm.source.user.name
    let k = format!("norm.source.{field}");
    if let std::collections::hash_map::Entry::Vacant(e) = metadata.entry(k) {
        let v = format!("windows_security:{event_id}:{rule}");
        e.insert(v);
    }
}

fn apply_constant(event: &mut Event, field: &str, value: &str, event_id: u64) {
    match field {
        "event.category" => {
            let mut did_set = false;
            {
                let details = event.event.get_or_insert_with(|| EventDetails {
                    summary: String::new(),
                    original_message: String::new(),
                    category: EventCategory::CategoryUnknown as i32,
                    action: String::new(),
                    outcome: EventOutcome::OutcomeUnknown as i32,
                    level: String::new(),
                    severity: 0,
                    provider: String::new(),
                    event_id: 0,
                    record_id: 0,
                });
                if details.category == EventCategory::CategoryUnknown as i32 {
                    if let Some(c) = parse_event_category(value) {
                        details.category = c as i32;
                        did_set = true;
                    }
                }
            }
            if did_set {
                set_provenance(&mut event.metadata, field, event_id, value);
            }
        }
        "event.outcome" => {
            let mut did_set = false;
            {
                let details = event.event.get_or_insert_with(|| EventDetails {
                    summary: String::new(),
                    original_message: String::new(),
                    category: EventCategory::CategoryUnknown as i32,
                    action: String::new(),
                    outcome: EventOutcome::OutcomeUnknown as i32,
                    level: String::new(),
                    severity: 0,
                    provider: String::new(),
                    event_id: 0,
                    record_id: 0,
                });
                if details.outcome == EventOutcome::OutcomeUnknown as i32 {
                    if let Some(o) = parse_event_outcome(value) {
                        details.outcome = o as i32;
                        did_set = true;
                    }
                }
            }
            if did_set {
                set_provenance(&mut event.metadata, field, event_id, value);
            }
        }
        "event.action" => {
            let mut did_set = false;
            {
                let details = event.event.get_or_insert_with(|| EventDetails {
                    summary: String::new(),
                    original_message: String::new(),
                    category: EventCategory::CategoryUnknown as i32,
                    action: String::new(),
                    outcome: EventOutcome::OutcomeUnknown as i32,
                    level: String::new(),
                    severity: 0,
                    provider: String::new(),
                    event_id: 0,
                    record_id: 0,
                });
                if details.action.trim().is_empty() {
                    details.action = value.to_string();
                    did_set = true;
                }
            }
            if did_set {
                set_provenance(&mut event.metadata, field, event_id, value);
            }
        }
        "network.direction" => {
            // Direction is part of Event.Network; set it if missing.
            let mut did_set = false;
            let network = event.network.get_or_insert_with(Default::default);
            if network.direction == NetworkDirection::DirUnknown as i32 {
                if let Some(d) = parse_network_direction(value) {
                    network.direction = d as i32;
                    did_set = true;
                }
            }
            if did_set {
                set_provenance(&mut event.metadata, field, event_id, value);
            }
        }
        // For unknown constant fields, store in metadata only (non-destructive).
        _ => {
            event
                .metadata
                .entry(field.to_string())
                .or_insert_with(|| value.to_string());
            set_provenance(&mut event.metadata, field, event_id, value);
        }
    }
}

fn apply_extracted(event: &mut Event, field: &str, value: &str, event_id: u64, rule: &str) {
    match field {
        "user.name" => {
            let user = event.user.get_or_insert_with(Default::default);
            if user.name.trim().is_empty() {
                user.name = value.to_string();
                set_provenance(&mut event.metadata, field, event_id, rule);
            }
        }
        "user.domain" => {
            let user = event.user.get_or_insert_with(Default::default);
            if user.domain.trim().is_empty() {
                user.domain = value.to_string();
                set_provenance(&mut event.metadata, field, event_id, rule);
            }
        }
        "user.id" => {
            let user = event.user.get_or_insert_with(Default::default);
            if user.id.trim().is_empty() {
                user.id = value.to_string();
                set_provenance(&mut event.metadata, field, event_id, rule);
            }
        }
        "network.src_ip" => {
            let network = event.network.get_or_insert_with(Default::default);
            if network.src_ip.trim().is_empty() {
                if let Some(ip) = parse_valid_ip(value) {
                    network.src_ip = ip;
                    set_provenance(&mut event.metadata, field, event_id, rule);
                }
            }
        }
        "network.src_port" => {
            let network = event.network.get_or_insert_with(Default::default);
            if network.src_port == 0 {
                if let Ok(p) = value.trim().parse::<u32>() {
                    if (1..=65535).contains(&p) {
                        network.src_port = p;
                        set_provenance(&mut event.metadata, field, event_id, rule);
                    }
                }
            }
        }
        "process.pid" => {
            let process = event.process.get_or_insert_with(Default::default);
            if process.pid == 0 {
                if let Ok(p) = value.trim().parse::<u32>() {
                    if p > 0 {
                        process.pid = p;
                        set_provenance(&mut event.metadata, field, event_id, rule);
                    }
                }
            }
        }
        "process.ppid" => {
            let process = event.process.get_or_insert_with(Default::default);
            if process.ppid == 0 {
                if let Ok(p) = value.trim().parse::<u32>() {
                    if p > 0 {
                        process.ppid = p;
                        set_provenance(&mut event.metadata, field, event_id, rule);
                    }
                }
            }
        }
        "process.name" => {
            let process = event.process.get_or_insert_with(Default::default);
            if process.name.trim().is_empty() {
                process.name = value.to_string();
                set_provenance(&mut event.metadata, field, event_id, rule);
            }
        }
        "process.command_line" => {
            let process = event.process.get_or_insert_with(Default::default);
            if process.command_line.trim().is_empty() {
                process.command_line = value.to_string();
                set_provenance(&mut event.metadata, field, event_id, rule);
            }
        }
        "event.provider" => {
            let mut did_set = false;
            {
                let details = event.event.get_or_insert_with(|| EventDetails {
                    summary: String::new(),
                    original_message: String::new(),
                    category: EventCategory::CategoryUnknown as i32,
                    action: String::new(),
                    outcome: EventOutcome::OutcomeUnknown as i32,
                    level: String::new(),
                    severity: 0,
                    provider: String::new(),
                    event_id: 0,
                    record_id: 0,
                });
                if details.provider.trim().is_empty() {
                    details.provider = value.to_string();
                    did_set = true;
                }
            }
            if did_set {
                set_provenance(&mut event.metadata, field, event_id, rule);
            }
        }
        // Unknown extract targets go to metadata only.
        _ => {
            if !value.trim().is_empty() {
                event
                    .metadata
                    .entry(field.to_string())
                    .or_insert_with(|| value.to_string());
                set_provenance(&mut event.metadata, field, event_id, rule);
            }
        }
    }
}

fn apply_extracted_list(event: &mut Event, field: &str, value: &str, event_id: u64, rule: &str) {
    // Currently only used for user.privileges in parsers.yaml; store in structured User if available.
    if field == "user.privileges" {
        let user = event.user.get_or_insert_with(Default::default);
        if user.privileges.is_empty() {
            let parts: Vec<String> = value
                .split([',', ';'])
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
            if !parts.is_empty() {
                user.privileges = parts;
                set_provenance(&mut event.metadata, field, event_id, rule);
            }
        }
        return;
    }

    // Otherwise, store as comma-separated metadata.
    if !value.trim().is_empty() {
        event
            .metadata
            .entry(field.to_string())
            .or_insert_with(|| value.to_string());
        set_provenance(&mut event.metadata, field, event_id, rule);
    }
}

fn parse_event_category(s: &str) -> Option<EventCategory> {
    match s.trim().to_uppercase().as_str() {
        "AUTH" => Some(EventCategory::Auth),
        "NETWORK" => Some(EventCategory::Network),
        "FILE" => Some(EventCategory::File),
        "PROCESS" => Some(EventCategory::Process),
        "REGISTRY" => Some(EventCategory::Registry),
        "SYSTEM" => Some(EventCategory::System),
        "OTHER" => Some(EventCategory::Other),
        _ => None,
    }
}

fn parse_event_outcome(s: &str) -> Option<EventOutcome> {
    match s.trim().to_uppercase().as_str() {
        "SUCCESS" | "ALLOW" | "ALLOWED" | "ACCEPT" | "PERMIT" => Some(EventOutcome::Success),
        "FAILURE" | "FAIL" | "ERROR" => Some(EventOutcome::Failure),
        "BLOCKED" | "BLOCK" | "DENY" | "DENIED" | "DROP" | "DROPPED" => Some(EventOutcome::Blocked),
        _ => None,
    }
}

fn parse_network_direction(s: &str) -> Option<NetworkDirection> {
    match s.trim().to_uppercase().as_str() {
        "INBOUND" | "IN" | "INGRESS" => Some(NetworkDirection::Inbound),
        "OUTBOUND" | "OUT" | "EGRESS" => Some(NetworkDirection::Outbound),
        "LATERAL" | "INTERNAL" => Some(NetworkDirection::Lateral),
        _ => None,
    }
}

fn parse_valid_ip(s: &str) -> Option<String> {
    let t = s.trim();
    if t.is_empty() || t == "-" || t.eq_ignore_ascii_case("unknown") {
        return None;
    }
    let ip: IpAddr = t.parse().ok()?;
    if ip.is_unspecified() || ip.is_loopback() {
        return None;
    }
    Some(t.to_string())
}

/// Load Windows event mappings from the standard candidate locations.
///
/// Best-effort: missing/invalid files should not prevent startup.
#[allow(dead_code)]
pub async fn load_best_effort() -> std::sync::Arc<WindowsEventMappings> {
    use std::path::PathBuf;
    use std::sync::Arc;

    let candidates: [PathBuf; 3] = [
        PathBuf::from("parsers.yaml"),
        PathBuf::from("server/parsers.yaml"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("parsers.yaml"),
    ];

    for path in candidates {
        if tokio::fs::try_exists(&path).await.unwrap_or(false) {
            match WindowsEventMappings::load_from_file(&path).await {
                Ok(m) => {
                    tracing::info!(
                        "Loaded Windows event mappings from {} (empty={})",
                        path.display(),
                        m.is_empty()
                    );
                    return Arc::new(m);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to load Windows event mappings from {}: {:#}",
                        path.display(),
                        e
                    );
                }
            }
        }
    }

    Arc::new(WindowsEventMappings::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use percepta_server::alerts::AlertService;
    use percepta_server::percepta::event::Agent;
    use percepta_server::rule_engine::RuleEngine;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn mk_event(event_id: u64, kv: &[(&str, &str)]) -> Event {
        let mut e = Event::default();
        e.event = Some(EventDetails {
            summary: String::new(),
            original_message: String::new(),
            category: EventCategory::CategoryUnknown as i32,
            action: String::new(),
            outcome: EventOutcome::OutcomeUnknown as i32,
            level: String::new(),
            severity: 0,
            provider: "Microsoft-Windows-Security-Auditing".to_string(),
            event_id,
            record_id: 1,
        });
        for (k, v) in kv {
            e.metadata.insert((*k).to_string(), (*v).to_string());
        }
        e
    }

    #[test]
    fn applies_4625_user_and_src_ip() {
        let mut m = WindowsEventMappings::default();
        m.security.insert(
            4625,
            HashMap::from([
                ("event.category".to_string(), "AUTH".to_string()),
                ("event.action".to_string(), "logon".to_string()),
                ("event.outcome".to_string(), "FAILURE".to_string()),
                (
                    "user.name".to_string(),
                    "extract(TargetUserName)".to_string(),
                ),
                (
                    "network.src_ip".to_string(),
                    "extract(IpAddress)".to_string(),
                ),
            ]),
        );

        let mut e = mk_event(
            4625,
            &[
                ("winlog.event_data.TargetUserName", "bob"),
                ("winlog.event_data.IpAddress", "10.1.2.3"),
            ],
        );

        m.apply(&mut e);

        let d = e.event.as_ref().unwrap();
        assert_eq!(d.category, EventCategory::Auth as i32);
        assert_eq!(d.outcome, EventOutcome::Failure as i32);
        assert_eq!(d.action, "logon");
        assert_eq!(e.user.as_ref().unwrap().name, "bob");
        assert_eq!(e.network.as_ref().unwrap().src_ip, "10.1.2.3");
        assert!(e.metadata.contains_key("norm.source.user.name"));
        assert!(e.metadata.contains_key("norm.source.network.src_ip"));
    }

    #[test]
    fn applies_4624_target_user_and_src_port() {
        let mut m = WindowsEventMappings::default();
        m.security.insert(
            4624,
            HashMap::from([
                ("event.category".to_string(), "AUTH".to_string()),
                ("event.action".to_string(), "logon".to_string()),
                ("event.outcome".to_string(), "SUCCESS".to_string()),
                (
                    "user.name".to_string(),
                    "extract(TargetUserName)".to_string(),
                ),
                (
                    "user.domain".to_string(),
                    "extract(TargetDomainName)".to_string(),
                ),
                (
                    "network.src_ip".to_string(),
                    "extract(IpAddress)".to_string(),
                ),
                (
                    "network.src_port".to_string(),
                    "extract(IpPort)".to_string(),
                ),
            ]),
        );

        let mut event = Event::default();
        event.metadata.insert(
            "winlog.event_data.TargetUserName".to_string(),
            "alice".to_string(),
        );
        event.metadata.insert(
            "winlog.event_data.TargetDomainName".to_string(),
            "CONTOSO".to_string(),
        );
        event.metadata.insert(
            "winlog.event_data.IpAddress".to_string(),
            "10.0.0.5".to_string(),
        );
        event
            .metadata
            .insert("winlog.event_data.IpPort".to_string(), "49673".to_string());
        event.event = Some(EventDetails {
            event_id: 4624,
            ..Default::default()
        });

        m.apply(&mut event);

        assert_eq!(event.user.as_ref().unwrap().name, "alice");
        assert_eq!(event.user.as_ref().unwrap().domain, "CONTOSO");
        assert_eq!(event.network.as_ref().unwrap().src_ip, "10.0.0.5");
        assert_eq!(event.network.as_ref().unwrap().src_port, 49673);
        assert_eq!(
            event.event.as_ref().unwrap().outcome,
            EventOutcome::Success as i32
        );
    }

    #[test]
    fn applies_4688_process_fields() {
        let mut m = WindowsEventMappings::default();
        m.security.insert(
            4688,
            HashMap::from([
                ("event.category".to_string(), "PROCESS".to_string()),
                ("event.action".to_string(), "process_create".to_string()),
                ("event.outcome".to_string(), "SUCCESS".to_string()),
                (
                    "process.name".to_string(),
                    "extract(NewProcessName)".to_string(),
                ),
                (
                    "process.command_line".to_string(),
                    "extract(CommandLine)".to_string(),
                ),
                (
                    "process.pid".to_string(),
                    "extract(NewProcessId)".to_string(),
                ),
                ("process.ppid".to_string(), "extract(ProcessId)".to_string()),
            ]),
        );

        let mut event = Event::default();
        event.metadata.insert(
            "winlog.event_data.NewProcessName".to_string(),
            "C:\\Windows\\System32\\cmd.exe".to_string(),
        );
        event.metadata.insert(
            "winlog.event_data.CommandLine".to_string(),
            "cmd.exe /c whoami".to_string(),
        );
        event.metadata.insert(
            "winlog.event_data.NewProcessId".to_string(),
            "4242".to_string(),
        );
        event.metadata.insert(
            "winlog.event_data.ProcessId".to_string(),
            "1234".to_string(),
        );
        event.event = Some(EventDetails {
            event_id: 4688,
            ..Default::default()
        });

        m.apply(&mut event);

        let p = event.process.as_ref().unwrap();
        assert_eq!(p.name, "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(p.command_line, "cmd.exe /c whoami");
        assert_eq!(p.pid, 4242);
        assert_eq!(p.ppid, 1234);
        assert_eq!(
            event.event.as_ref().unwrap().category,
            EventCategory::Process as i32
        );
    }

    #[test]
    fn does_not_overwrite_existing_user() {
        let mut m = WindowsEventMappings::default();
        m.security.insert(
            4624,
            HashMap::from([(
                "user.name".to_string(),
                "extract(SubjectUserName)".to_string(),
            )]),
        );

        let mut e = mk_event(4624, &[("winlog.event_data.SubjectUserName", "alice")]);
        e.user = Some(percepta_server::percepta::event::User {
            id: String::new(),
            name: "already".to_string(),
            domain: String::new(),
            privileges: Vec::new(),
        });

        m.apply(&mut e);
        assert_eq!(e.user.as_ref().unwrap().name, "already");
    }

    #[derive(Debug, Deserialize)]
    struct GoldenExpect {
        category: Option<String>,
        action: Option<String>,
        outcome: Option<String>,
        user_name: Option<String>,
        user_domain: Option<String>,
        user_id: Option<String>,
        src_ip: Option<String>,
        src_port: Option<u32>,
        process_name: Option<String>,
        process_command_line: Option<String>,
        pid: Option<u32>,
        ppid: Option<u32>,
        #[serde(default)]
        metadata_equals: HashMap<String, String>,
        rule_should_match: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct GoldenCase {
        name: String,
        event_id: u64,
        #[serde(default)]
        provider: Option<String>,
        #[serde(default)]
        agent_id: Option<String>,
        #[serde(default)]
        agent_hostname: Option<String>,
        metadata: HashMap<String, String>,
        expect: GoldenExpect,
    }

    fn server_manifest_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn make_event_from_case(c: &GoldenCase) -> Event {
        let mut e = Event::default();
        e.metadata = c.metadata.clone();
        if let Some(agent_id) = c.agent_id.as_deref() {
            let hostname = c.agent_hostname.clone().unwrap_or_default();
            e.agent = Some(Agent {
                id: agent_id.to_string(),
                hostname,
                ip: String::new(),
                mac: String::new(),
                version: String::new(),
                os: None,
            });
        }
        e.event = Some(EventDetails {
            provider: c.provider.clone().unwrap_or_default(),
            event_id: c.event_id,
            ..Default::default()
        });
        e
    }

    fn assert_normalized(case: &GoldenCase, event: &Event) {
        if let Some(expected_category) = case.expect.category.as_deref() {
            let details = event.event.as_ref().expect("event.details present");
            let actual =
                EventCategory::try_from(details.category).unwrap_or(EventCategory::CategoryUnknown);
            let want = match expected_category {
                "AUTH" => EventCategory::Auth,
                "NETWORK" => EventCategory::Network,
                "FILE" => EventCategory::File,
                "PROCESS" => EventCategory::Process,
                "REGISTRY" => EventCategory::Registry,
                "SYSTEM" => EventCategory::System,
                _ => EventCategory::CategoryUnknown,
            };
            assert_eq!(actual, want, "{}: category mismatch", case.name);
        }
        if let Some(expected_action) = case.expect.action.as_deref() {
            let details = event.event.as_ref().expect("event.details present");
            assert_eq!(
                details.action, expected_action,
                "{}: action mismatch",
                case.name
            );
        }
        if let Some(expected_outcome) = case.expect.outcome.as_deref() {
            let details = event.event.as_ref().expect("event.details present");
            let actual =
                EventOutcome::try_from(details.outcome).unwrap_or(EventOutcome::OutcomeUnknown);
            let want = match expected_outcome {
                "SUCCESS" => EventOutcome::Success,
                "FAILURE" => EventOutcome::Failure,
                "BLOCKED" => EventOutcome::Blocked,
                _ => EventOutcome::OutcomeUnknown,
            };
            assert_eq!(actual, want, "{}: outcome mismatch", case.name);
        }

        if let Some(want) = case.expect.user_name.as_deref() {
            assert_eq!(
                event.user.as_ref().map(|u| u.name.as_str()).unwrap_or(""),
                want,
                "{}: user.name mismatch",
                case.name
            );
        }
        if let Some(want) = case.expect.user_domain.as_deref() {
            assert_eq!(
                event.user.as_ref().map(|u| u.domain.as_str()).unwrap_or(""),
                want,
                "{}: user.domain mismatch",
                case.name
            );
        }
        if let Some(want) = case.expect.user_id.as_deref() {
            assert_eq!(
                event.user.as_ref().map(|u| u.id.as_str()).unwrap_or(""),
                want,
                "{}: user.id mismatch",
                case.name
            );
        }

        if let Some(want) = case.expect.src_ip.as_deref() {
            assert_eq!(
                event
                    .network
                    .as_ref()
                    .map(|n| n.src_ip.as_str())
                    .unwrap_or(""),
                want,
                "{}: network.src_ip mismatch",
                case.name
            );
        }
        if let Some(want) = case.expect.src_port {
            assert_eq!(
                event.network.as_ref().map(|n| n.src_port).unwrap_or(0),
                want,
                "{}: network.src_port mismatch",
                case.name
            );
        }

        if let Some(want) = case.expect.process_name.as_deref() {
            assert_eq!(
                event
                    .process
                    .as_ref()
                    .map(|p| p.name.as_str())
                    .unwrap_or(""),
                want,
                "{}: process.name mismatch",
                case.name
            );
        }
        if let Some(want) = case.expect.process_command_line.as_deref() {
            assert_eq!(
                event
                    .process
                    .as_ref()
                    .map(|p| p.command_line.as_str())
                    .unwrap_or(""),
                want,
                "{}: process.command_line mismatch",
                case.name
            );
        }
        if let Some(want) = case.expect.pid {
            assert_eq!(
                event.process.as_ref().map(|p| p.pid).unwrap_or(0),
                want,
                "{}: process.pid mismatch",
                case.name
            );
        }
        if let Some(want) = case.expect.ppid {
            assert_eq!(
                event.process.as_ref().map(|p| p.ppid).unwrap_or(0),
                want,
                "{}: process.ppid mismatch",
                case.name
            );
        }

        for (k, v) in &case.expect.metadata_equals {
            let actual = event.metadata.get(k).cloned().unwrap_or_default();
            assert_eq!(actual, *v, "{}: metadata mismatch for key={}", case.name, k);
        }
    }

    #[tokio::test]
    async fn golden_windows_security_normalization() {
        let mappings_path = server_manifest_path().join("parsers.yaml");
        let mappings = WindowsEventMappings::load_from_file(&mappings_path)
            .await
            .expect("load server/parsers.yaml");
        assert!(!mappings.is_empty(), "expected non-empty windows mappings");

        let cases_dir = server_manifest_path().join("testdata/windows_golden");
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&cases_dir)
            .expect("read testdata/windows_golden")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
            .collect();
        entries.sort();
        assert!(!entries.is_empty(), "expected golden corpus files");

        for path in entries {
            let content = std::fs::read_to_string(&path).expect("read golden yaml");
            let case: GoldenCase = serde_yaml::from_str(&content)
                .unwrap_or_else(|e| panic!("parse golden yaml {}: {e:#}", path.display()));

            let mut event = make_event_from_case(&case);
            mappings.apply(&mut event);
            assert_normalized(&case, &event);
        }
    }

    #[tokio::test]
    async fn golden_rule_regression_enabled_rules() {
        let mappings_path = server_manifest_path().join("parsers.yaml");
        let mappings = WindowsEventMappings::load_from_file(&mappings_path)
            .await
            .expect("load server/parsers.yaml");

        let rules_path = server_manifest_path().join("rules.yaml");
        let alert_service = Arc::new(AlertService::new(300, 3600));
        let engine = RuleEngine::new(alert_service);
        engine
            .load_rules_from_file(&rules_path)
            .await
            .expect("load server/rules.yaml");

        let cases_dir = server_manifest_path().join("testdata/windows_golden");
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&cases_dir)
            .expect("read testdata/windows_golden")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
            .collect();
        entries.sort();
        assert!(!entries.is_empty(), "expected golden corpus files");

        for path in entries {
            let content = std::fs::read_to_string(&path).expect("read golden yaml");
            let case: GoldenCase = serde_yaml::from_str(&content)
                .unwrap_or_else(|e| panic!("parse golden yaml {}: {e:#}", path.display()));

            let Some(want) = case.expect.rule_should_match.as_deref() else {
                continue;
            };

            let mut event = make_event_from_case(&case);
            mappings.apply(&mut event);
            assert_normalized(&case, &event);

            let alerts = engine.evaluate_event(&event).await.expect("evaluate event");
            assert!(
                alerts.iter().any(|a| a.rule_id == want),
                "{}: expected rule {want} to match, got rule_ids={:?}",
                case.name,
                alerts
                    .iter()
                    .map(|a| a.rule_id.as_str())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[derive(Debug, Deserialize)]
    struct GoldenSequenceExpect {
        rule_should_match: String,
        #[serde(default)]
        trigger_on_index: Option<usize>,
    }

    #[derive(Debug, Deserialize)]
    struct GoldenSequenceCase {
        name: String,
        events: Vec<GoldenCase>,
        expect: GoldenSequenceExpect,
    }

    #[tokio::test]
    async fn golden_sequence_rule_regression() {
        let mappings_path = server_manifest_path().join("parsers.yaml");
        let mappings = WindowsEventMappings::load_from_file(&mappings_path)
            .await
            .expect("load server/parsers.yaml");

        let rules_path = server_manifest_path().join("rules.yaml");

        let cases_dir = server_manifest_path().join("testdata/windows_sequences_golden");
        if !cases_dir.exists() {
            // Keep test suite flexible for minimal deployments.
            return;
        }

        let mut entries: Vec<PathBuf> = std::fs::read_dir(&cases_dir)
            .expect("read testdata/windows_sequences_golden")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("yaml"))
            .collect();
        entries.sort();

        for path in entries {
            let content = std::fs::read_to_string(&path).expect("read golden sequence yaml");
            let case: GoldenSequenceCase = serde_yaml::from_str(&content)
                .unwrap_or_else(|e| panic!("parse golden sequence yaml {}: {e:#}", path.display()));

            let alert_service = Arc::new(AlertService::new(300, 3600));
            let engine = RuleEngine::new(alert_service);
            engine
                .load_rules_from_file(&rules_path)
                .await
                .expect("load server/rules.yaml");

            assert!(
                !case.events.is_empty(),
                "{}: expected at least one event in sequence",
                case.name
            );

            let mut matched_at: Option<usize> = None;

            for (idx, ev_case) in case.events.iter().enumerate() {
                let mut event = make_event_from_case(ev_case);
                event.hash = format!("golden-seq:{}:{}", case.name, idx);
                mappings.apply(&mut event);
                assert_normalized(ev_case, &event);

                let alerts = engine.evaluate_event(&event).await.expect("evaluate event");
                if alerts
                    .iter()
                    .any(|a| a.rule_id == case.expect.rule_should_match)
                {
                    matched_at = Some(idx);
                    break;
                }
            }

            let want_idx = case.expect.trigger_on_index;
            if let Some(want) = want_idx {
                assert_eq!(
                    matched_at,
                    Some(want),
                    "{}: expected sequence rule {} to match at event index {want}, got matched_at={matched_at:?}",
                    case.name,
                    case.expect.rule_should_match
                );
            } else {
                assert!(
                    matched_at.is_some(),
                    "{}: expected sequence rule {} to match, but it did not",
                    case.name,
                    case.expect.rule_should_match
                );
            }
        }
    }
}
