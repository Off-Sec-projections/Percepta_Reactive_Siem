//! Percepta Common Schema (PCS) — Event Normalization Layer.
//!
//! Provides a canonical field taxonomy inspired by Elastic ECS & Splunk CIM.
//! After parsing, raw fields are mapped into PCS namespaces for cross-source rule writing.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// PCS field namespaces — canonical event structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NormalizedEvent {
    // Event metadata
    pub event_kind: String,     // "alert", "event", "metric", "state"
    pub event_category: String, // "authentication", "process", "network", "file", "registry"
    pub event_type: String,     // "start", "end", "creation", "deletion", "access", "change"
    pub event_outcome: String,  // "success", "failure", "unknown"
    pub event_module: String,   // "windows", "linux", "syslog", "suricata", "auditd"
    pub event_dataset: String,  // "windows.security", "linux.auth", "suricata.eve"
    pub event_severity: u8,     // 0-100 normalized severity
    pub event_risk_score: u32,  // Computed risk score

    // Source
    pub source_ip: String,
    pub source_port: u16,
    pub source_mac: String,
    pub source_hostname: String,
    pub source_domain: String,
    pub source_user: String,

    // Destination
    pub destination_ip: String,
    pub destination_port: u16,
    pub destination_mac: String,
    pub destination_hostname: String,

    // Network
    pub network_protocol: String,  // "tcp", "udp", "icmp"
    pub network_transport: String, // "ipv4", "ipv6"
    pub network_direction: String, // "inbound", "outbound", "internal"
    pub network_bytes_in: u64,
    pub network_bytes_out: u64,

    // Process
    pub process_name: String,
    pub process_pid: u32,
    pub process_ppid: u32,
    pub process_command_line: String,
    pub process_executable: String,
    pub process_user: String,

    // File
    pub file_path: String,
    pub file_name: String,
    pub file_hash_md5: String,
    pub file_hash_sha256: String,
    pub file_size: u64,
    pub file_action: String, // "created", "modified", "deleted", "accessed"

    // User
    pub user_name: String,
    pub user_domain: String,
    pub user_id: String,
    pub user_target_name: String,
    pub user_target_domain: String,

    // Host
    pub host_name: String,
    pub host_ip: String,
    pub host_os_name: String,
    pub host_os_version: String,

    // Agent
    pub agent_id: String,
    pub agent_name: String,

    // Rule/Alert
    pub rule_id: String,
    pub rule_name: String,
    pub rule_category: String,

    // Additional fields not covered by the fixed schema
    pub extra: HashMap<String, String>,
}

/// Field mapping rules: raw field name -> PCS field path.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct FieldMapping {
    pub source_field: String,
    pub pcs_field: String,
}

/// Normalize an event's metadata map into PCS fields.
/// This runs after the decoder engine parses raw events.
pub fn normalize_event(metadata: &HashMap<String, String>, sensor_kind: &str) -> NormalizedEvent {
    let mut n = NormalizedEvent::default();

    // Determine module and dataset from sensor kind
    let (module, dataset) = classify_module(sensor_kind);
    n.event_module = module;
    n.event_dataset = dataset;

    // Map common fields
    n.source_ip = get_field(
        metadata,
        &["src_ip", "source_ip", "SourceAddress", "src", "source.ip"],
    );
    n.source_port = get_field(metadata, &["src_port", "source_port", "SourcePort"])
        .parse()
        .unwrap_or(0);
    n.destination_ip = get_field(
        metadata,
        &[
            "dst_ip",
            "dest_ip",
            "DestinationAddress",
            "dst",
            "destination.ip",
        ],
    );
    n.destination_port = get_field(metadata, &["dst_port", "dest_port", "DestinationPort"])
        .parse()
        .unwrap_or(0);

    // User fields
    // SubjectUserName (the actor/initiator) must have higher priority than
    // TargetUserName (the account being acted upon).  Reversing this causes
    // Windows logon/privilege events to attribute the target as the actor.
    n.user_name = get_field(
        metadata,
        &[
            "user",
            "username",
            "SubjectUserName",
            "TargetUserName",
            "user.name",
            "uid",
        ],
    );
    n.user_domain = get_field(
        metadata,
        &[
            "domain",
            "SubjectDomainName",
            "TargetDomainName",
            "user.domain",
        ],
    );
    n.user_id = get_field(metadata, &["user_id", "SubjectUserSid", "TargetUserSid"]);
    n.user_target_name = get_field(metadata, &["target_user", "TargetUserName"]);

    // Process fields
    n.process_name = get_field(
        metadata,
        &["process", "process_name", "NewProcessName", "Image", "exe"],
    );
    n.process_pid = get_field(metadata, &["pid", "ProcessId", "NewProcessId"])
        .parse()
        .unwrap_or(0);
    n.process_ppid = get_field(metadata, &["ppid", "ParentProcessId", "CreatorProcessId"])
        .parse()
        .unwrap_or(0);
    n.process_command_line = get_field(
        metadata,
        &[
            "cmdline",
            "command_line",
            "CommandLine",
            "ProcessCommandLine",
        ],
    );
    n.process_executable = get_field(metadata, &["executable", "Image", "NewProcessName"]);
    n.process_user = get_field(metadata, &["process_user", "SubjectUserName"]);

    // File fields
    n.file_path = get_field(
        metadata,
        &["file_path", "ObjectName", "TargetFilename", "name"],
    );
    n.file_name = get_field(metadata, &["file_name", "FileName"]);
    n.file_hash_sha256 = get_field(metadata, &["sha256", "Hashes", "file_hash"]);
    n.file_hash_md5 = get_field(metadata, &["md5"]);

    // Network
    n.network_protocol = get_field(metadata, &["protocol", "proto", "Protocol"]);
    n.network_direction = get_field(metadata, &["direction", "network.direction"]);

    // Host
    n.host_name = get_field(metadata, &["hostname", "host", "ComputerName", "Hostname"]);
    n.host_ip = get_field(metadata, &["host_ip", "IpAddress"]);
    n.host_os_name = get_field(metadata, &["os", "os_name"]);

    // Agent
    n.agent_id = get_field(metadata, &["agent_id"]);
    n.agent_name = get_field(metadata, &["agent_name"]);

    // Event categorization
    n.event_kind = categorize_event_kind(metadata, sensor_kind);
    n.event_category = categorize_event_category(metadata, sensor_kind);
    n.event_type = categorize_event_type(metadata);
    n.event_outcome = categorize_event_outcome(metadata);

    // Any unmapped fields go into extra
    let mapped_fields: std::collections::HashSet<&str> = [
        // Network
        "src_ip", "source_ip", "SourceAddress", "src", "source.ip",
        "dst_ip", "dest_ip", "DestinationAddress", "dst", "destination.ip",
        "src_port", "source_port", "SourcePort",
        "dst_port", "dest_port", "DestinationPort",
        "protocol", "proto", "Protocol",
        "direction", "network.direction",
        // User (Windows Event Log + generic)
        "user", "username", "uid", "user.name",
        "SubjectUserName", "TargetUserName",
        "SubjectDomainName", "TargetDomainName",
        "domain", "user.domain",
        "user_id", "SubjectUserSid", "TargetUserSid",
        "target_user",
        // Process
        "process", "process_name", "Image", "NewProcessName", "exe",
        "pid", "ProcessId", "NewProcessId",
        "ppid", "ParentProcessId", "CreatorProcessId",
        "cmdline", "command_line", "CommandLine", "ProcessCommandLine",
        "executable",
        "process_user",
        // File
        "file_path", "ObjectName", "TargetFilename", "name",
        "file_name", "FileName",
        "sha256", "Hashes", "file_hash",
        "md5",
        // Host
        "hostname", "host", "ComputerName", "Hostname",
        "host_ip", "IpAddress",
        "os", "os_name",
        // Agent
        "agent_id", "agent_name",
    ]
    .iter()
    .copied()
    .collect();

    for (k, v) in metadata {
        if !mapped_fields.contains(k.as_str()) && !v.is_empty() {
            n.extra.insert(k.clone(), v.clone());
        }
    }

    n
}

fn get_field(metadata: &HashMap<String, String>, keys: &[&str]) -> String {
    for key in keys {
        if let Some(v) = metadata.get(*key) {
            if !v.is_empty() {
                return v.clone();
            }
        }
    }
    String::new()
}

fn classify_module(sensor_kind: &str) -> (String, String) {
    let sk = sensor_kind.to_lowercase();
    if sk.contains("windows") || sk.contains("eventlog") {
        ("windows".into(), format!("windows.{}", sk))
    } else if sk.contains("syslog") {
        ("syslog".into(), "syslog.messages".into())
    } else if sk.contains("auditd") || sk.contains("audit") {
        ("linux".into(), "linux.auditd".into())
    } else if sk.contains("suricata") || sk.contains("ids") {
        ("suricata".into(), "suricata.eve".into())
    } else if sk.contains("auth") || sk.contains("secure") {
        ("linux".into(), "linux.auth".into())
    } else if sk.contains("file") || sk.contains("fim") {
        ("fim".into(), "fim.events".into())
    } else if sk.contains("process") {
        ("endpoint".into(), "endpoint.process".into())
    } else if sk.contains("honeypot") {
        ("honeypot".into(), "honeypot.trap".into())
    } else if sk.contains("dns") {
        ("dns".into(), "dns.query".into())
    } else {
        ("generic".into(), format!("generic.{}", sk))
    }
}

fn categorize_event_kind(metadata: &HashMap<String, String>, sensor_kind: &str) -> String {
    if sensor_kind.contains("alert") || metadata.contains_key("alert_id") {
        "alert".into()
    } else if sensor_kind.contains("metric") {
        "metric".into()
    } else {
        "event".into()
    }
}

fn categorize_event_category(metadata: &HashMap<String, String>, sensor_kind: &str) -> String {
    let sk = sensor_kind.to_lowercase();
    if sk.contains("auth")
        || metadata.contains_key("LogonType")
        || metadata.contains_key("TargetUserName")
    {
        "authentication".into()
    } else if sk.contains("process")
        || metadata.contains_key("ProcessId")
        || metadata.contains_key("NewProcessName")
    {
        "process".into()
    } else if sk.contains("network")
        || sk.contains("firewall")
        || metadata.contains_key("DestinationPort")
    {
        "network".into()
    } else if sk.contains("file") || sk.contains("fim") || metadata.contains_key("TargetFilename") {
        "file".into()
    } else if metadata.contains_key("ObjectName")
        && metadata
            .get("ObjectType")
            .map(|v| v.contains("Key"))
            .unwrap_or(false)
    {
        "registry".into()
    } else {
        "host".into()
    }
}

fn categorize_event_type(metadata: &HashMap<String, String>) -> String {
    if let Some(action) = metadata.get("action").or_else(|| metadata.get("Action")) {
        let a = action.to_lowercase();
        if a.contains("creat") || a.contains("add") || a.contains("install") {
            return "creation".into();
        }
        if a.contains("delet") || a.contains("remov") || a.contains("uninstall") {
            return "deletion".into();
        }
        if a.contains("modif") || a.contains("chang") || a.contains("updat") {
            return "change".into();
        }
    }
    // Heuristic from event IDs
    if let Some(eid) = metadata.get("event_id") {
        match eid.as_str() {
            "4624" | "4648" => return "start".into(),    // logon
            "4634" | "4647" => return "end".into(),      // logoff
            "4720" | "4722" => return "creation".into(), // user created/enabled
            "4726" => return "deletion".into(),          // user deleted
            "4738" | "4742" => return "change".into(),   // user/computer changed
            "1" => return "start".into(),                // sysmon process creation
            "5" => return "end".into(),                  // sysmon process terminated
            _ => {}
        }
    }
    "info".into()
}

fn categorize_event_outcome(metadata: &HashMap<String, String>) -> String {
    if let Some(status) = metadata.get("status").or_else(|| metadata.get("Status")) {
        let s = status.to_lowercase();
        if s.contains("success") || s == "0x0" || s == "0" {
            return "success".into();
        }
        if s.contains("fail") || s.contains("denied") || s.contains("reject") {
            return "failure".into();
        }
    }
    // Windows logon: event 4624 = success, 4625 = failure
    if let Some(eid) = metadata.get("event_id") {
        match eid.as_str() {
            "4624" | "4648" | "4634" => return "success".into(),
            "4625" | "4771" | "4776" => return "failure".into(),
            _ => {}
        }
    }
    "unknown".into()
}

// ── PCS Field Taxonomy (for documentation/export) ────────────────────────

pub fn pcs_field_taxonomy() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("event.kind", "keyword", "alert, event, metric, state"),
        (
            "event.category",
            "keyword",
            "authentication, process, network, file, registry, host",
        ),
        (
            "event.type",
            "keyword",
            "start, end, creation, deletion, access, change, info",
        ),
        ("event.outcome", "keyword", "success, failure, unknown"),
        (
            "event.module",
            "keyword",
            "windows, linux, syslog, suricata, honeypot, fim, dns",
        ),
        (
            "event.dataset",
            "keyword",
            "windows.security, linux.auditd, suricata.eve, etc.",
        ),
        ("event.severity", "integer", "0-100 normalized severity"),
        ("event.risk_score", "integer", "Computed risk score"),
        ("source.ip", "ip", "Source IP address"),
        ("source.port", "integer", "Source port"),
        ("source.user", "keyword", "Source user name"),
        ("destination.ip", "ip", "Destination IP address"),
        ("destination.port", "integer", "Destination port"),
        ("network.protocol", "keyword", "tcp, udp, icmp"),
        (
            "network.direction",
            "keyword",
            "inbound, outbound, internal",
        ),
        ("process.name", "keyword", "Process name"),
        ("process.pid", "integer", "Process ID"),
        ("process.ppid", "integer", "Parent process ID"),
        ("process.command_line", "text", "Full command line"),
        ("process.executable", "keyword", "Executable path"),
        ("file.path", "keyword", "Full file path"),
        ("file.hash.sha256", "keyword", "SHA-256 hash"),
        ("file.hash.md5", "keyword", "MD5 hash"),
        (
            "file.action",
            "keyword",
            "created, modified, deleted, accessed",
        ),
        ("user.name", "keyword", "User name"),
        ("user.domain", "keyword", "User domain"),
        ("user.id", "keyword", "User SID or UID"),
        ("host.name", "keyword", "Hostname"),
        ("host.ip", "ip", "Host IP"),
        ("host.os.name", "keyword", "Operating system name"),
        ("agent.id", "keyword", "Agent unique identifier"),
        ("agent.name", "keyword", "Agent display name"),
    ]
}
