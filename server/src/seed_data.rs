//! Seed Data — Out-of-the-box examples for Percepta SIEM
//!
//! Provides realistic, functional sample data for:
//! - Playbooks (SOAR automation rules)
//! - Detection rules
//! - Saved searches
//! - Vulnerabilities (common CVEs)
//! - Sample cases
//!
//! This enables a great first-time experience without requiring manual data entry.

use serde_json::json;
use std::collections::HashMap;

/// Seed data for playbooks (SOAR automation)
pub fn get_sample_playbooks() -> Vec<serde_json::Value> {
    vec![
        // 1. Auto-block critical IDS alerts
        json!({
            "id": "pb-auto-block-critical-ids",
            "name": "Auto-Block Critical IDS Alerts",
            "description": "Automatically block source IPs from critical IDS alerts (Suricata/Snort)",
            "enabled": false, // Start in dry-run mode for safety
            "trigger_conditions": [
                {
                    "field": "severity",
                    "operator": "equals",
                    "value": "critical"
                },
                {
                    "field": "rule_category",
                    "operator": "equals",
                    "value": "ids"
                }
            ],
            "actions": [
                {
                    "action_type": "block_ip",
                    "field": "src_ip",
                    "duration_seconds": 3600,
                    "reason": "Critical IDS alert triggered"
                },
                {
                    "action_type": "create_case",
                    "severity": "high",
                    "title": "Auto-blocked IP from critical IDS alert"
                }
            ],
            "created_at": chrono::Utc::now().timestamp(),
        }),
        // 2. Disable user after multiple failed logins
        json!({
            "id": "pb-disable-bruteforce-users",
            "name": "Disable User on Brute Force",
            "description": "Disable user accounts after 5+ failed login attempts in 5 minutes",
            "enabled": false,
            "trigger_conditions": [
                {
                    "field": "rule_name",
                    "operator": "contains",
                    "value": "Failed Login"
                },
                {
                    "field": "event_count",
                    "operator": "greater_than",
                    "value": "5"
                }
            ],
            "actions": [
                {
                    "action_type": "disable_user",
                    "field": "target_user",
                    "reason": "Brute force attempt detected"
                },
                {
                    "action_type": "send_notification",
                    "channel": "email",
                    "message": "User disabled due to brute force: {{target_user}}"
                }
            ],
            "created_at": chrono::Utc::now().timestamp(),
        }),
        // 3. Escalate honeypot triggers
        json!({
            "id": "pb-escalate-honeypot",
            "name": "Escalate Honeypot Triggers",
            "description": "Create high-severity cases for honeypot interactions",
            "enabled": true,
            "trigger_conditions": [
                {
                    "field": "sensor.kind",
                    "operator": "equals",
                    "value": "honeypot"
                }
            ],
            "actions": [
                {
                    "action_type": "create_case",
                    "severity": "high",
                    "title": "Honeypot trigger: {{honeypot.trap}}"
                },
                {
                    "action_type": "send_notification",
                    "channel": "webhook",
                    "message": "Honeypot activity from {{src_ip}}"
                }
            ],
            "created_at": chrono::Utc::now().timestamp(),
        }),
        // 4. Auto-quarantine malware detections
        json!({
            "id": "pb-quarantine-malware",
            "name": "Quarantine Malware Detections",
            "description": "Isolate endpoints with confirmed malware signatures",
            "enabled": false,
            "trigger_conditions": [
                {
                    "field": "event.category",
                    "operator": "equals",
                    "value": "malware"
                },
                {
                    "field": "severity",
                    "operator": "in",
                    "value": "critical,high"
                }
            ],
            "actions": [
                {
                    "action_type": "isolate_endpoint",
                    "field": "agent_id",
                    "reason": "Malware detected"
                },
                {
                    "action_type": "create_case",
                    "severity": "critical",
                    "title": "Malware quarantine: {{agent_hostname}}"
                }
            ],
            "created_at": chrono::Utc::now().timestamp(),
        }),
        // 5. Enrich IOC matches
        json!({
            "id": "pb-enrich-ioc",
            "name": "Enrich IOC Matches",
            "description": "Automatically investigate and document IOC matches with threat intel",
            "enabled": true,
            "trigger_conditions": [
                {
                    "field": "ioc.matched",
                    "operator": "equals",
                    "value": "true"
                }
            ],
            "actions": [
                {
                    "action_type": "enrich_threat_intel",
                    "field": "ioc.matches"
                },
                {
                    "action_type": "create_case",
                    "severity": "medium",
                    "title": "IOC match investigation: {{ioc.matches}}"
                }
            ],
            "created_at": chrono::Utc::now().timestamp(),
        }),
    ]
}

/// Seed data for saved searches
pub fn get_sample_saved_searches() -> Vec<serde_json::Value> {
    vec![
        json!({
            "id": "ss-failed-ssh",
            "name": "Failed SSH Login Attempts",
            "query": "event.category:authentication AND event.outcome:failure AND process.name:sshd",
            "description": "Track failed SSH authentication attempts",
            "filters": {
                "timerange": "24h",
                "severity": "medium"
            },
            "created_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "id": "ss-suricata-critical",
            "name": "Suricata Critical Alerts",
            "query": "sensor.kind:ids AND severity:critical",
            "description": "All critical IDS alerts from Suricata",
            "filters": {
                "timerange": "7d"
            },
            "created_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "id": "ss-windows-logon-fails",
            "name": "Windows Failed Logons",
            "query": "event.code:4625 OR event.code:4771",
            "description": "Windows Event IDs for failed logon attempts",
            "filters": {
                "timerange": "24h",
                "os": "windows"
            },
            "created_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "id": "ss-honeypot-activity",
            "name": "All Honeypot Activity",
            "query": "sensor.kind:honeypot",
            "description": "All honeypot trap triggers",
            "filters": {
                "timerange": "30d"
            },
            "created_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "id": "ss-privilege-escalation",
            "name": "Privilege Escalation Attempts",
            "query": "(sudo OR runas OR powershell) AND (permission denied OR access denied)",
            "description": "Potential privilege escalation activity",
            "filters": {
                "timerange": "7d",
                "severity": "high"
            },
            "created_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "id": "ss-file-integrity",
            "name": "File Integrity Changes",
            "query": "sensor.kind:fim AND (action:modified OR action:deleted)",
            "description": "Track critical file modifications",
            "filters": {
                "timerange": "24h"
            },
            "created_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "id": "ss-external-access",
            "name": "External IP Connections",
            "query": "dst_ip:* AND NOT dst_ip:10.* AND NOT dst_ip:192.168.* AND NOT dst_ip:172.16.*",
            "description": "All connections to external IPs (non-RFC1918)",
            "filters": {
                "timerange": "1h"
            },
            "created_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "id": "ss-dlp-violations",
            "name": "DLP Violations",
            "query": "dlp.violation_count:>0",
            "description": "Data loss prevention policy violations",
            "filters": {
                "timerange": "24h",
                "severity": "high"
            },
            "created_at": chrono::Utc::now().timestamp(),
        }),
    ]
}

/// Seed data for vulnerabilities — Real CVEs relevant to common enterprise systems
pub fn get_sample_vulnerabilities() -> Vec<serde_json::Value> {
    vec![
        // Critical — actively exploited vulnerabilities
        json!({
            "cve_id": "CVE-2024-3400",
            "severity": "critical",
            "cvss_score": 10.0,
            "affected_software": "Palo Alto Networks PAN-OS",
            "description": "Command injection vulnerability in GlobalProtect gateway allows unauthenticated RCE",
            "status": "open",
            "exploited_in_wild": true,
            "remediation": "Upgrade to PAN-OS 10.2.9, 11.0.4, or 11.1.2",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "cve_id": "CVE-2023-22515",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_software": "Atlassian Confluence",
            "description": "Critical privilege escalation vulnerability allowing unauthenticated access",
            "status": "open",
            "exploited_in_wild": true,
            "remediation": "Upgrade Confluence to fixed versions immediately",
            "references": ["https://confluence.atlassian.com/security/cve-2023-22515"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "cve_id": "CVE-2023-46604",
            "severity": "critical",
            "cvss_score": 10.0,
            "affected_software": "Apache ActiveMQ",
            "description": "RCE via deserialization vulnerability in ActiveMQ",
            "status": "open",
            "exploited_in_wild": true,
            "remediation": "Upgrade to ActiveMQ 5.18.3+",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        // High severity — common enterprise vulnerabilities
        json!({
            "cve_id": "CVE-2024-21887",
            "severity": "high",
            "cvss_score": 9.1,
            "affected_software": "Ivanti Connect Secure / Policy Secure",
            "description": "Command injection vulnerability in web component",
            "status": "open",
            "exploited_in_wild": true,
            "remediation": "Apply Ivanti security patches",
            "references": ["https://forums.ivanti.com/s/article/CVE-2024-21887"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "cve_id": "CVE-2023-4966",
            "severity": "critical",
            "cvss_score": 9.4,
            "affected_software": "Citrix NetScaler ADC and Gateway",
            "description": "Session hijacking vulnerability (Citrix Bleed)",
            "status": "open",
            "exploited_in_wild": true,
            "remediation": "Upgrade NetScaler to patched versions",
            "references": ["https://support.citrix.com/article/CTX579459"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "cve_id": "CVE-2023-38831",
            "severity": "high",
            "cvss_score": 7.8,
            "affected_software": "WinRAR",
            "description": "Code execution via specially crafted RAR archives",
            "status": "open",
            "exploited_in_wild": true,
            "remediation": "Update WinRAR to 6.23 or later",
            "references": ["https://www.rarlab.com/"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        // Medium severity — tracking common issues
        json!({
            "cve_id": "CVE-2023-44487",
            "severity": "high",
            "cvss_score": 7.5,
            "affected_software": "HTTP/2 implementations (multiple vendors)",
            "description": "HTTP/2 Rapid Reset DDoS vulnerability",
            "status": "open",
            "exploited_in_wild": true,
            "remediation": "Apply vendor-specific patches for HTTP/2 implementations",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "cve_id": "CVE-2023-20198",
            "severity": "critical",
            "cvss_score": 10.0,
            "affected_software": "Cisco IOS XE Web UI",
            "description": "Privilege escalation allowing attacker to create accounts",
            "status": "remediated",
            "exploited_in_wild": true,
            "remediation": "Disable HTTP/HTTPS server or upgrade IOS XE",
            "references": ["https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "cve_id": "CVE-2023-27997",
            "severity": "critical",
            "cvss_score": 9.2,
            "affected_software": "Fortinet FortiOS SSL VPN",
            "description": "Heap-based buffer overflow in SSL VPN pre-authentication",
            "status": "open",
            "exploited_in_wild": true,
            "remediation": "Upgrade FortiOS to patched versions",
            "references": ["https://www.fortiguard.com/psirt/FG-IR-23-097"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
        json!({
            "cve_id": "CVE-2023-34362",
            "severity": "critical",
            "cvss_score": 9.8,
            "affected_software": "MOVEit Transfer",
            "description": "SQL injection vulnerability in MOVEit Transfer",
            "status": "remediated",
            "exploited_in_wild": true,
            "remediation": "Apply Progress Software security patches",
            "references": ["https://www.progress.com/moveit"],
            "discovered_at": chrono::Utc::now().timestamp(),
        }),
    ]
}

/// Seed data for sample cases
pub fn get_sample_cases() -> Vec<serde_json::Value> {
    vec![
        json!({
            "id": "case-001",
            "title": "Suspected Port Scan from 203.0.113.45",
            "description": "IDS detected systematic port scanning activity from external IP",
            "status": "in_progress",
            "severity": "medium",
            "assignee": "SOC Analyst",
            "created_at": chrono::Utc::now().timestamp() - 7200, // 2 hours ago
            "alert_ids": ["alert-ids-001", "alert-ids-002"],
            "tags": ["reconnaissance", "external-threat"],
        }),
        json!({
            "id": "case-002",
            "title": "Honeypot SSH Brute Force Attempt",
            "description": "Multiple failed SSH login attempts against honeypot from botnet",
            "status": "closed",
            "severity": "low",
            "assignee": "Threat Hunter",
            "created_at": chrono::Utc::now().timestamp() - 86400, // 1 day ago
            "closed_at": chrono::Utc::now().timestamp() - 3600,
            "alert_ids": ["alert-honeypot-001"],
            "resolution": "Blocked attacker IP, no internal systems affected",
            "tags": ["honeypot", "brute-force", "mitigated"],
        }),
        json!({
            "id": "case-003",
            "title": "Privilege Escalation Attempt Detected",
            "description": "User attempted unauthorized sudo access on production server",
            "status": "open",
            "severity": "high",
            "assignee": "Security Engineer",
            "created_at": chrono::Utc::now().timestamp() - 1800, // 30 minutes ago
            "alert_ids": ["alert-linux-001", "alert-linux-002"],
            "tags": ["privilege-escalation", "insider-threat"],
        }),
    ]
}

/// Seed data for detection rules (supplement existing rules.yaml)
pub fn get_sample_detection_rules() -> Vec<serde_json::Value> {
    vec![
        json!({
            "name": "Multiple Failed SSH Logins",
            "category": "authentication",
            "severity": "medium",
            "conditions": {
                "count": 5,
                "timeframe": 300,
                "field": "process.name",
                "value": "sshd",
                "outcome": "failure"
            },
            "description": "Detects 5+ failed SSH authentication attempts in 5 minutes (potential brute force)",
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110.001"],
        }),
        json!({
            "name": "Windows Admin Account Lockout",
            "category": "authentication",
            "severity": "high",
            "conditions": {
                "event_id": 4740,
                "user": "*admin*"
            },
            "description": "Administrator account lockout - potential targeted attack",
            "mitre_tactics": ["TA0006"],
            "mitre_techniques": ["T1110"],
        }),
        json!({
            "name": "Suricata ET EXPLOIT Attempt",
            "category": "ids",
            "severity": "high",
            "conditions": {
                "sensor.kind": "ids",
                "alert.signature": "*ET EXPLOIT*"
            },
            "description": "Emerging Threats exploit attempt detected by IDS",
            "mitre_tactics": ["TA0001", "TA0002"],
            "mitre_techniques": ["T1190"],
        }),
        json!({
            "name": "Critical File Modification",
            "category": "file_integrity",
            "severity": "critical",
            "conditions": {
                "sensor.kind": "fim",
                "path": ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "C:\\Windows\\System32\\config\\SAM"]
            },
            "description": "Critical system file modification detected",
            "mitre_tactics": ["TA0003", "TA0004"],
            "mitre_techniques": ["T1098", "T1136"],
        }),
        json!({
            "name": "IOC Match - Known Malicious IP",
            "category": "threat_intel",
            "severity": "critical",
            "conditions": {
                "ioc.matched": "true",
                "ioc_type": "ip"
            },
            "description": "Communication with known malicious IP address",
            "mitre_tactics": ["TA0011"],
            "mitre_techniques": ["T1071"],
        }),
    ]
}

/// Get compliance mapping examples (PCI-DSS, NIST, ISO 27001)
pub fn get_sample_compliance_mappings() -> HashMap<String, Vec<serde_json::Value>> {
    let mut mappings = HashMap::new();

    // PCI-DSS 4.0 mappings
    mappings.insert(
        "PCI-DSS".to_string(),
        vec![
            json!({
                "requirement": "10.2.1",
                "description": "Individual user accesses to cardholder data",
                "mapped_rules": ["Windows Admin Account Lockout", "Multiple Failed SSH Logins"],
                "coverage": "Partial",
            }),
            json!({
                "requirement": "10.2.5",
                "description": "Use of identification and authentication mechanisms",
                "mapped_rules": ["Multiple Failed SSH Logins", "Windows Admin Account Lockout"],
                "coverage": "Full",
            }),
            json!({
                "requirement": "11.4",
                "description": "Use intrusion-detection/prevention techniques",
                "mapped_rules": ["Suricata ET EXPLOIT Attempt", "IOC Match - Known Malicious IP"],
                "coverage": "Full",
            }),
        ],
    );

    // NIST CSF mappings
    mappings.insert("NIST-CSF".to_string(), vec![
        json!({
            "function": "Detect",
            "category": "DE.CM-1",
            "description": "Network monitored to detect potential cybersecurity events",
            "mapped_rules": ["Suricata ET EXPLOIT Attempt", "IOC Match - Known Malicious IP"],
        }),
        json!({
            "function": "Detect",
            "category": "DE.CM-7",
            "description": "Monitoring for unauthorized access",
            "mapped_rules": ["Multiple Failed SSH Logins", "Privilege Escalation Attempt Detected"],
        }),
    ]);

    // HIPAA Security Rule mappings
    mappings.insert("HIPAA".to_string(), vec![
        json!({
            "requirement": "164.312(b)",
            "description": "Audit controls - record and examine activity in systems containing ePHI",
            "mapped_rules": ["Windows Admin Account Lockout", "Multiple Failed SSH Logins"],
            "coverage": "Partial",
        }),
        json!({
            "requirement": "164.312(d)",
            "description": "Person or entity authentication",
            "mapped_rules": ["Multiple Failed SSH Logins", "Privilege Escalation Attempt Detected"],
            "coverage": "Full",
        }),
        json!({
            "requirement": "164.308(a)(1)(ii)(D)",
            "description": "Information system activity review",
            "mapped_rules": ["Suricata ET EXPLOIT Attempt", "IOC Match - Known Malicious IP", "Critical File Integrity Change"],
            "coverage": "Partial",
        }),
    ]);

    // SOC 2 Trust Services Criteria mappings
    mappings.insert("SOC2".to_string(), vec![
        json!({
            "criteria": "CC6.1",
            "description": "Logical and physical access controls over information assets",
            "mapped_rules": ["Multiple Failed SSH Logins", "Windows Admin Account Lockout", "Privilege Escalation Attempt Detected"],
            "coverage": "Partial",
        }),
        json!({
            "criteria": "CC7.2",
            "description": "Monitor system components for anomalies indicative of malicious acts",
            "mapped_rules": ["Suricata ET EXPLOIT Attempt", "IOC Match - Known Malicious IP"],
            "coverage": "Full",
        }),
        json!({
            "criteria": "CC7.3",
            "description": "Evaluate security events to determine impact",
            "mapped_rules": ["Critical File Integrity Change", "Data Exfiltration Detected"],
            "coverage": "Partial",
        }),
    ]);

    // GDPR relevant controls
    mappings.insert("GDPR".to_string(), vec![
        json!({
            "article": "Article 32",
            "description": "Security of processing - appropriate technical and organizational measures",
            "mapped_rules": ["Suricata ET EXPLOIT Attempt", "IOC Match - Known Malicious IP", "Multiple Failed SSH Logins"],
            "coverage": "Partial",
        }),
        json!({
            "article": "Article 33",
            "description": "Notification of breach to supervisory authority within 72 hours",
            "mapped_rules": ["Data Exfiltration Detected", "Critical File Integrity Change"],
            "coverage": "Partial",
        }),
    ]);

    // ISO 27001:2022 Annex A controls
    mappings.insert("ISO-27001".to_string(), vec![
        json!({
            "control": "A.8.15",
            "description": "Logging - event logs recording user activities and security events",
            "mapped_rules": ["Windows Admin Account Lockout", "Multiple Failed SSH Logins"],
            "coverage": "Full",
        }),
        json!({
            "control": "A.8.16",
            "description": "Monitoring activities - networks, systems and applications monitored for anomalous behaviour",
            "mapped_rules": ["Suricata ET EXPLOIT Attempt", "IOC Match - Known Malicious IP"],
            "coverage": "Full",
        }),
        json!({
            "control": "A.5.28",
            "description": "Collection of evidence",
            "mapped_rules": ["Critical File Integrity Change", "Data Exfiltration Detected"],
            "coverage": "Partial",
        }),
    ]);

    mappings
}

/// Initialize seed data (call this during server startup)
pub async fn initialize_seed_data(// Pass in your stores/engines that need seeding
    // Example structure - adjust based on your actual types
) {
    tracing::info!("🌱 Initializing seed data for first-time setup");

    // Note: Actual implementation would persist these to your database
    // This is a template showing the data structure

    let playbooks = get_sample_playbooks();
    let saved_searches = get_sample_saved_searches();
    let vulnerabilities = get_sample_vulnerabilities();
    let cases = get_sample_cases();
    let rules = get_sample_detection_rules();
    let compliance = get_sample_compliance_mappings();

    tracing::info!("✅ Seed data ready: {} playbooks, {} searches, {} vulnerabilities, {} cases, {} rules, {} compliance mappings",
        playbooks.len(),
        saved_searches.len(),
        vulnerabilities.len(),
        cases.len(),
        rules.len(),
        compliance.len()
    );

    // Runtime persistence for saved searches, vulnerabilities, and cases is wired
    // in the main application API flow + startup load path.
}

/// Check if seed data should be applied (e.g., empty database on first run)
pub async fn should_apply_seed_data(db: &crate::db::Db) -> bool {
    // Explicit skip overrides everything
    if std::env::var("PERCEPTA_SKIP_SEED_DATA").is_ok() {
        return false;
    }
    // Check if there are already events/alerts in the database — if so, skip seed data
    let client = db.client();
    let count: u64 = client
        .query("SELECT count() FROM events")
        .fetch_one()
        .await
        .unwrap_or(0);
    if count > 0 {
        tracing::info!("Database has {} events, skipping seed data", count);
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_data_structure() {
        let playbooks = get_sample_playbooks();
        assert!(!playbooks.is_empty());
        assert!(playbooks[0]["name"].is_string());

        let vulns = get_sample_vulnerabilities();
        assert!(!vulns.is_empty());
        assert!(vulns[0]["cve_id"].is_string());
    }
}
