//! Integration tests for percepta-server library components.
//!
//! These tests exercise the AlertService, RuleEngine, and related types
//! without requiring a running ClickHouse instance or full HTTP server.

use percepta_server::alerts::{AlertService, AlertSeverity, AlertStatus};
use percepta_server::percepta::Event;
use percepta_server::rule_engine::RuleEngine;
use std::collections::HashMap;
use std::sync::Arc;

/// Build a minimal protobuf Event suitable for testing.
fn test_event(agent_id: &str, hostname: &str) -> Event {
    Event {
        agent: Some(percepta_server::percepta::event::Agent {
            id: agent_id.to_string(),
            hostname: hostname.to_string(),
            ip: "10.0.0.1".to_string(),
            mac: String::new(),
            version: "0.1-test".to_string(),
            os: Some(percepta_server::percepta::event::Os {
                name: "Linux".to_string(),
                version: "6.1".to_string(),
                kernel: String::new(),
            }),
        }),
        event: Some(percepta_server::percepta::event::EventDetails {
            summary: "test event".to_string(),
            original_message: "raw log line".to_string(),
            category: 1, // AUTH
            action: "logon".to_string(),
            outcome: 1, // SUCCESS
            level: "Info".to_string(),
            severity: 1,
            provider: "test-provider".to_string(),
            event_id: 4624,
            record_id: 1,
        }),
        user: Some(percepta_server::percepta::event::User {
            id: "1000".to_string(),
            name: "testuser".to_string(),
            domain: "WORKGROUP".to_string(),
            privileges: vec![],
        }),
        process: Some(percepta_server::percepta::event::Process {
            pid: 1234,
            ppid: 1,
            name: "sshd".to_string(),
            command_line: "/usr/sbin/sshd -D".to_string(),
            hash: HashMap::new(),
        }),
        network: Some(percepta_server::percepta::event::Network {
            src_ip: "192.168.1.100".to_string(),
            src_port: 45678,
            dst_ip: "10.0.0.1".to_string(),
            dst_port: 22,
            protocol: "tcp".to_string(),
            direction: 1, // INBOUND
            bytes_in: 0,
            bytes_out: 0,
            flow_duration_ms: 0,
            tls_sni: String::new(),
            ja3: String::new(),
            ja3s: String::new(),
            tls_cert_subject: String::new(),
            tls_cert_issuer: String::new(),
        }),
        hash: "testhash001".to_string(),
        tags: vec!["login".to_string(), "ssh".to_string()],
        metadata: HashMap::new(),
        event_time: None,
        ingest_time: None,
        host: None,
        file: None,
        registry: None,
        threat_indicator: String::new(),
        threat_source: String::new(),
        correlation_id: String::new(),
    }
}

// ────────────────────────────── AlertService Tests ──────────────────────────

#[tokio::test]
async fn alert_create_basic() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    let result = svc
        .create_alert(
            "rule-1".into(),
            "Test Rule".into(),
            AlertSeverity::High,
            "auth".into(),
            "Suspicious login detected".into(),
            &ev,
            HashMap::new(),
            "dedup:rule-1:agent-1".into(),
            "suppress:rule-1:agent-1".into(),
        )
        .await
        .expect("create_alert should succeed");

    let alert = result.expect("First alert should not be deduplicated");
    assert_eq!(alert.rule_id, "rule-1");
    assert_eq!(alert.rule_name, "Test Rule");
    assert_eq!(alert.severity, AlertSeverity::High);
    assert_eq!(alert.status, AlertStatus::New);
    assert_eq!(alert.count, 1);
    assert_eq!(alert.agent_id, "agent-1");
    assert_eq!(alert.agent_hostname, "host-a");
    assert_eq!(alert.source_events, vec!["testhash001"]);
}

#[tokio::test]
async fn alert_dedup_within_window() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");
    let dedup = "dedup:rule-1:agent-1".to_string();
    let suppress = "suppress:rule-1:agent-1".to_string();

    // First alert — creates new
    let first = svc
        .create_alert(
            "rule-1".into(),
            "Test Rule".into(),
            AlertSeverity::Medium,
            "auth".into(),
            "msg".into(),
            &ev,
            HashMap::new(),
            dedup.clone(),
            suppress.clone(),
        )
        .await
        .unwrap()
        .expect("First alert should be created");
    assert_eq!(first.count, 1);

    // Second alert with same dedup key — should be deduplicated (count bumps)
    let second = svc
        .create_alert(
            "rule-1".into(),
            "Test Rule".into(),
            AlertSeverity::Medium,
            "auth".into(),
            "msg".into(),
            &ev,
            HashMap::new(),
            dedup.clone(),
            suppress.clone(),
        )
        .await
        .unwrap()
        .expect("Deduped alert should still return Some");
    assert_eq!(second.count, 2);
    assert_eq!(second.id, first.id);

    // Total alerts in memory should be 1
    let all = svc.get_alerts().await;
    assert_eq!(all.len(), 1);
}

#[tokio::test]
async fn alert_different_dedup_keys_creates_separate() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    svc.create_alert(
        "rule-1".into(),
        "Rule A".into(),
        AlertSeverity::Low,
        "auth".into(),
        "msg".into(),
        &ev,
        HashMap::new(),
        "dedup:rule-1:agent-1".into(),
        "suppress:rule-1:agent-1".into(),
    )
    .await
    .unwrap();

    svc.create_alert(
        "rule-2".into(),
        "Rule B".into(),
        AlertSeverity::High,
        "network".into(),
        "msg2".into(),
        &ev,
        HashMap::new(),
        "dedup:rule-2:agent-1".into(),
        "suppress:rule-2:agent-1".into(),
    )
    .await
    .unwrap();

    let all = svc.get_alerts().await;
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn alert_update_status() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    let alert = svc
        .create_alert(
            "rule-1".into(),
            "Test".into(),
            AlertSeverity::Critical,
            "auth".into(),
            "msg".into(),
            &ev,
            HashMap::new(),
            "dedup:1".into(),
            "suppress:1".into(),
        )
        .await
        .unwrap()
        .unwrap();

    svc.update_alert_status(&alert.id, AlertStatus::Investigating)
        .await
        .expect("Status update should succeed");

    let by_status = svc.get_alerts_by_status(AlertStatus::Investigating).await;
    assert_eq!(by_status.len(), 1);
    assert_eq!(by_status[0].id, alert.id);
}

#[tokio::test]
async fn alert_update_status_not_found() {
    let svc = AlertService::new(300, 3600);

    let result = svc
        .update_alert_status("nonexistent-id", AlertStatus::Resolved)
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Alert not found"));
}

#[tokio::test]
async fn alert_remove() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    let alert = svc
        .create_alert(
            "rule-1".into(),
            "Test".into(),
            AlertSeverity::Low,
            "auth".into(),
            "msg".into(),
            &ev,
            HashMap::new(),
            "dedup:rm".into(),
            "suppress:rm".into(),
        )
        .await
        .unwrap()
        .unwrap();

    svc.remove_alert(&alert.id)
        .await
        .expect("Remove should succeed");
    assert_eq!(svc.get_alerts().await.len(), 0);

    // Second remove should fail
    assert!(svc.remove_alert(&alert.id).await.is_err());
}

#[tokio::test]
async fn alert_with_alerts_zero_copy() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    svc.create_alert(
        "rule-1".into(),
        "Test".into(),
        AlertSeverity::High,
        "auth".into(),
        "msg".into(),
        &ev,
        HashMap::new(),
        "dedup:zc".into(),
        "suppress:zc".into(),
    )
    .await
    .unwrap();

    let count = svc.with_alerts(|map| map.len()).await;
    assert_eq!(count, 1);

    let ids: Vec<String> = svc
        .with_alerts(|map| map.values().map(|a| a.id.clone()).collect())
        .await;
    assert_eq!(ids.len(), 1);
}

#[tokio::test]
async fn alert_severity_str() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    let alert = svc
        .create_alert(
            "rule-1".into(),
            "Test".into(),
            AlertSeverity::Critical,
            "auth".into(),
            "msg".into(),
            &ev,
            HashMap::new(),
            "dedup:sev".into(),
            "suppress:sev".into(),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(alert.severity_str(), "CRITICAL");
}

#[tokio::test]
async fn alert_get_by_severity() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    svc.create_alert(
        "rule-hi".into(),
        "High".into(),
        AlertSeverity::High,
        "auth".into(),
        "msg".into(),
        &ev,
        HashMap::new(),
        "dedup:hi".into(),
        "suppress:hi".into(),
    )
    .await
    .unwrap();

    svc.create_alert(
        "rule-lo".into(),
        "Low".into(),
        AlertSeverity::Low,
        "auth".into(),
        "msg".into(),
        &ev,
        HashMap::new(),
        "dedup:lo".into(),
        "suppress:lo".into(),
    )
    .await
    .unwrap();

    let highs = svc.get_alerts_by_severity(AlertSeverity::High).await;
    assert_eq!(highs.len(), 1);
    assert_eq!(highs[0].rule_id, "rule-hi");

    let mediums = svc.get_alerts_by_severity(AlertSeverity::Medium).await;
    assert_eq!(mediums.len(), 0);
}

#[tokio::test]
async fn alert_clear_all() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    for i in 0..5 {
        svc.create_alert(
            format!("rule-{i}"),
            format!("Rule {i}"),
            AlertSeverity::Medium,
            "auth".into(),
            "msg".into(),
            &ev,
            HashMap::new(),
            format!("dedup:{i}"),
            format!("suppress:{i}"),
        )
        .await
        .unwrap();
    }
    assert_eq!(svc.get_alerts().await.len(), 5);

    svc.clear_alerts().await;
    assert_eq!(svc.get_alerts().await.len(), 0);
}

#[tokio::test]
async fn alert_metadata_preserved() {
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    let mut md = HashMap::new();
    md.insert("mitre_attack".to_string(), "T1078".to_string());
    md.insert("mitre_tactics".to_string(), "initial-access".to_string());

    let alert = svc
        .create_alert(
            "rule-1".into(),
            "Test".into(),
            AlertSeverity::High,
            "auth".into(),
            "msg".into(),
            &ev,
            md,
            "dedup:md".into(),
            "suppress:md".into(),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(alert.metadata.get("mitre_attack").unwrap(), "T1078");
    assert_eq!(
        alert.metadata.get("mitre_tactics").unwrap(),
        "initial-access"
    );
    // dedup_key and suppress_key are auto-added
    assert!(alert.metadata.contains_key("dedup_key"));
    assert!(alert.metadata.contains_key("suppress_key"));
}

#[tokio::test]
async fn alert_false_positive_suppression() {
    // false_positive_suppress_seconds > 0 means marking as FP suppresses that pattern
    let svc = AlertService::new(300, 3600);
    let ev = test_event("agent-1", "host-a");

    let alert = svc
        .create_alert(
            "rule-1".into(),
            "Test".into(),
            AlertSeverity::Medium,
            "auth".into(),
            "msg".into(),
            &ev,
            HashMap::new(),
            "dedup:fp".into(),
            "suppress:fp".into(),
        )
        .await
        .unwrap()
        .unwrap();

    // Mark as FalsePositive — should trigger suppression
    svc.update_alert_status(&alert.id, AlertStatus::FalsePositive)
        .await
        .unwrap();

    // Now creating an alert with the same suppress_key should return None (suppressed)
    let suppressed = svc
        .create_alert(
            "rule-1".into(),
            "Test".into(),
            AlertSeverity::Medium,
            "auth".into(),
            "msg".into(),
            &ev,
            HashMap::new(),
            "dedup:fp-new".into(), // different dedup key
            "suppress:fp".into(),  // same suppress key
        )
        .await
        .unwrap();

    assert!(
        suppressed.is_none(),
        "Alert should be suppressed after FP marking"
    );
}

#[tokio::test]
async fn alert_cleanup_expired_suppressions() {
    let svc = AlertService::new(300, 0); // 0 = no auto-suppression window
    let removed = svc.cleanup_expired_suppressions().await;
    assert_eq!(removed, 0);
}

// ───────────────────────────── RuleEngine Tests ─────────────────────────────

#[tokio::test]
async fn rule_engine_load_rules_from_file() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine
        .load_rules_from_file(&rules_path)
        .await
        .expect("Loading production rules.yaml should succeed");
}

#[tokio::test]
async fn rule_engine_evaluate_auth_event() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc.clone());

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    // Build an event that exercises some rule (brute-force-like: failed auth)
    let mut ev = test_event("agent-1", "host-a");
    if let Some(ref mut details) = ev.event {
        details.outcome = 2; // FAILURE
        details.action = "logon".to_string();
        details.category = 1; // AUTH
        details.summary = "Failed authentication attempt".to_string();
    }

    // evaluate_event should succeed even if no rules fire (threshold rules need multiple events)
    let alerts = engine
        .evaluate_event(&ev)
        .await
        .expect("evaluate_event should not error");

    // We just verify it runs without panicking; whether a specific alert fires
    // depends on rule thresholds and exact field matching.
    let _ = alerts;
}

#[tokio::test]
async fn rule_engine_windows_4625_machine_account_exception_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    // Should be suppressed by exception in win_failed_logon_4625_bruteforce_threshold.
    for idx in 0..8 {
        let mut ev = test_event("agent-1", "win-host-a");
        if let Some(ref mut details) = ev.event {
            details.provider = "Microsoft-Windows-Security-Auditing".to_string();
            details.event_id = 4625;
            details.outcome = 2; // FAILURE
            details.action = "logon".to_string();
        }
        if let Some(ref mut user) = ev.user {
            user.name = "WORKSTATION01$".to_string();
        }
        ev.hash = format!("t-win-4625-machine-{idx}");

        let alerts = engine.evaluate_event(&ev).await.unwrap();
        assert!(
            !alerts
                .iter()
                .any(|a| a.rule_id == "win_failed_logon_4625_bruteforce_threshold"),
            "Machine-account 4625 burst should be exception-suppressed"
        );
    }
}

#[tokio::test]
async fn rule_engine_windows_4625_real_user_still_triggers_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    let mut saw_threshold_alert = false;
    for idx in 0..8 {
        let mut ev = test_event("agent-1", "win-host-a");
        if let Some(ref mut details) = ev.event {
            details.provider = "Microsoft-Windows-Security-Auditing".to_string();
            details.event_id = 4625;
            details.original_message =
                "An account failed to log on".to_string();
            details.outcome = 2; // FAILURE
            details.action = "logon".to_string();
        }
        if let Some(ref mut user) = ev.user {
            user.name = "alice".to_string();
        }
        ev.hash = format!("t-win-4625-real-user-{idx}");

        let alerts = engine.evaluate_event(&ev).await.unwrap();
        if alerts
            .iter()
            .any(|a| a.rule_id == "win_failed_logon_4625_bruteforce_threshold")
        {
            saw_threshold_alert = true;
        }
    }

    assert!(
        saw_threshold_alert,
        "Real-user Windows 4625 burst should still trigger threshold rule"
    );
}

#[tokio::test]
async fn rule_engine_windows_4625_real_user_does_not_trigger_password_spray_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    for idx in 0..15 {
        let mut ev = test_event("agent-1", "win-host-a");
        if let Some(ref mut details) = ev.event {
            details.provider = "Microsoft-Windows-Security-Auditing".to_string();
            details.event_id = 4625;
            details.original_message = "An account failed to log on".to_string();
            details.outcome = 2; // FAILURE
            details.action = "logon".to_string();
        }
        if let Some(ref mut user) = ev.user {
            user.name = "alice".to_string();
        }
        ev.hash = format!("t-win-4625-real-user-no-spray-{idx}");

        let alerts = engine.evaluate_event(&ev).await.unwrap();
        assert!(
            !alerts
                .iter()
                .any(|a| a.rule_id == "win_failed_logon_4625_password_spray_threshold"),
            "Regular same-user 4625 failures should not trigger password-spray rule"
        );
    }
}

#[tokio::test]
async fn rule_engine_windows_4625_invalid_user_triggers_password_spray_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    let mut saw_spray_alert = false;
    for idx in 0..15 {
        let mut ev = test_event("agent-1", "win-host-a");
        if let Some(ref mut details) = ev.event {
            details.provider = "Microsoft-Windows-Security-Auditing".to_string();
            details.event_id = 4625;
            details.original_message =
                "An account failed to log on. Status: 0xC0000064, user name does not exist"
                    .to_string();
            details.outcome = 2; // FAILURE
            details.action = "logon".to_string();
        }
        if let Some(ref mut user) = ev.user {
            user.name = format!("nonexistent_{idx}");
        }
        ev.hash = format!("t-win-4625-invalid-user-spray-{idx}");

        let alerts = engine.evaluate_event(&ev).await.unwrap();
        if alerts
            .iter()
            .any(|a| a.rule_id == "win_failed_logon_4625_password_spray_threshold")
        {
            saw_spray_alert = true;
        }
    }

    assert!(
        saw_spray_alert,
        "Invalid-user 4625 burst should trigger password-spray threshold rule"
    );
}

#[tokio::test]
async fn rule_engine_linux_ssh_bruteforce_localhost_exception_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    for idx in 0..5 {
        let mut ev = test_event("agent-1", "linux-host-a");
        if let Some(ref mut details) = ev.event {
            details.provider = "sshd".to_string();
            details.original_message =
                "Failed password for invalid user test from 127.0.0.1 port 51515 ssh2".to_string();
            details.outcome = 2; // FAILURE
            details.action = "logon".to_string();
        }
        if let Some(ref mut user) = ev.user {
            user.name = "test".to_string();
        }
        if let Some(ref mut host) = ev.agent {
            host.ip = "127.0.0.1".to_string();
        }
        ev.hash = format!("t-linux-ssh-localhost-{idx}");

        let alerts = engine.evaluate_event(&ev).await.unwrap();
        assert!(
            !alerts
                .iter()
                .any(|a| a.rule_id == "brute_force_linux_ssh_threshold"),
            "Localhost SSH failures should be exception-suppressed"
        );
    }
}

#[tokio::test]
async fn rule_engine_linux_ssh_bruteforce_failed_password_overlap_exception_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    for idx in 0..5 {
        let mut ev = test_event("agent-1", "linux-host-a");
        if let Some(ref mut details) = ev.event {
            details.provider = "sshd".to_string();
            details.original_message =
                "sshd[1234]: Failed password for alice from 10.10.10.50 port 44321 ssh2"
                    .to_string();
            details.category = 1; // AUTH
            details.outcome = 2; // FAILURE
            details.action = "logon".to_string();
        }
        if let Some(ref mut user) = ev.user {
            user.name = "alice".to_string();
        }
        ev.hash = format!("t-linux-ssh-overlap-{idx}");

        let alerts = engine.evaluate_event(&ev).await.unwrap();
        assert!(
            !alerts.iter().any(|a| a.rule_id == "linux_ssh_bruteforce"),
            "Failed-password SSH events should be handled by linux_ssh_failed_password_threshold and suppressed in linux_ssh_bruteforce"
        );
    }
}

#[tokio::test]
async fn rule_engine_linux_sudo_failures_auth_overlap_exception_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    for idx in 0..3 {
        let mut ev = test_event("agent-1", "linux-host-a");
        if let Some(ref mut details) = ev.event {
            details.original_message =
                "sudo: pam_unix(sudo:auth): authentication failure; user=alice"
                    .to_string();
            details.outcome = 2; // FAILURE
            details.action = "privilege_escalation".to_string();
        }
        if let Some(ref mut user) = ev.user {
            user.name = "alice".to_string();
        }
        ev.hash = format!("t-linux-sudo-overlap-{idx}");

        let alerts = engine.evaluate_event(&ev).await.unwrap();
        assert!(
            !alerts.iter().any(|a| a.rule_id == "linux_sudo_failures"),
            "sudo authentication failure bursts should be handled by linux_sudo_auth_fail_threshold and suppressed in linux_sudo_failures"
        );
    }
}

#[tokio::test]
async fn rule_engine_windows_new_user_then_enabled_sequence_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    let mut ev_create = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev_create.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4720;
        details.action = "user-account-management".to_string();
    }
    if let Some(ref mut user) = ev_create.user {
        user.name = "staged_user".to_string();
    }
    ev_create.hash = "t-win-seq-4720-step1".to_string();

    let first_alerts = engine.evaluate_event(&ev_create).await.unwrap();
    assert!(
        !first_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_new_user_then_enabled_4720_4722"),
        "Sequence should not trigger on first step only"
    );

    let mut ev_enable = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev_enable.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4722;
        details.action = "user-account-management".to_string();
    }
    if let Some(ref mut user) = ev_enable.user {
        user.name = "staged_user".to_string();
    }
    ev_enable.hash = "t-win-seq-4720-step2".to_string();

    let second_alerts = engine.evaluate_event(&ev_enable).await.unwrap();
    assert!(
        second_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_new_user_then_enabled_4720_4722"),
        "4720 then 4722 for same user should trigger sequence rule"
    );
}

#[tokio::test]
async fn rule_engine_windows_new_user_then_priv_group_sequence_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    let mut ev_create = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev_create.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4720;
        details.action = "user-account-management".to_string();
    }
    if let Some(ref mut user) = ev_create.user {
        user.name = "newadmin".to_string();
    }
    ev_create
        .metadata
        .insert("target_user_short".to_string(), "newadmin".to_string());
    ev_create.hash = "t-win-seq-4720-priv-step1".to_string();

    let first_alerts = engine.evaluate_event(&ev_create).await.unwrap();
    assert!(
        !first_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_new_user_then_priv_group_4720_4728_4732"),
        "Priv-group sequence should not trigger on first step only"
    );

    let mut ev_group_add = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev_group_add.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4728;
        details.action = "group-membership-change".to_string();
    }
    ev_group_add
        .metadata
        .insert("target_user_short".to_string(), "newadmin".to_string());
    ev_group_add
        .metadata
        .insert("group".to_string(), "Domain Admins".to_string());
    ev_group_add.hash = "t-win-seq-4720-priv-step2".to_string();

    let second_alerts = engine.evaluate_event(&ev_group_add).await.unwrap();
    assert!(
        second_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_new_user_then_priv_group_4720_4728_4732"),
        "4720 then 4728/4732 with privileged group metadata should trigger sequence rule"
    );
}

#[tokio::test]
async fn rule_engine_windows_audit_policy_then_log_cleared_sequence_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    let mut ev_policy = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev_policy.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4719;
        details.action = "audit-policy-change".to_string();
    }
    if let Some(ref mut user) = ev_policy.user {
        user.name = "secadmin".to_string();
    }
    ev_policy.hash = "t-win-seq-4719-step1".to_string();

    let first_alerts = engine.evaluate_event(&ev_policy).await.unwrap();
    assert!(
        !first_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_audit_policy_then_log_cleared_4719_1102"),
        "Sequence should not trigger on first step only"
    );

    let mut ev_logclear = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev_logclear.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 1102;
        details.action = "log-cleared".to_string();
    }
    if let Some(ref mut user) = ev_logclear.user {
        user.name = "secadmin".to_string();
    }
    ev_logclear.hash = "t-win-seq-4719-step2".to_string();

    let second_alerts = engine.evaluate_event(&ev_logclear).await.unwrap();
    assert!(
        second_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_audit_policy_then_log_cleared_4719_1102"),
        "4719 then 1102 for same user should trigger defense-evasion sequence rule"
    );
}

#[tokio::test]
async fn rule_engine_windows_credential_to_priv_to_persistence_sequence_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    let mut ev_auth_fail = test_event("agent-chain-1", "win-chain-1");
    if let Some(ref mut details) = ev_auth_fail.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4625;
        details.action = "logon-failed".to_string();
    }
    if let Some(ref mut user) = ev_auth_fail.user {
        user.name = "svc_backup".to_string();
    }
    ev_auth_fail.hash = "t-win-seq-4625-step1".to_string();

    let first_alerts = engine.evaluate_event(&ev_auth_fail).await.unwrap();
    assert!(
        !first_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_credential_to_priv_to_persistence_4625_4672_4698"),
        "Sequence should not trigger on first step only"
    );

    let mut ev_priv = test_event("agent-chain-1", "win-chain-1");
    if let Some(ref mut details) = ev_priv.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4672;
        details.action = "special-privileges-assigned".to_string();
    }
    if let Some(ref mut user) = ev_priv.user {
        user.name = "svc_backup".to_string();
    }
    ev_priv.hash = "t-win-seq-4625-step2".to_string();

    let second_alerts = engine.evaluate_event(&ev_priv).await.unwrap();
    assert!(
        !second_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_credential_to_priv_to_persistence_4625_4672_4698"),
        "Sequence should not trigger on second step only"
    );

    let mut ev_persist = test_event("agent-chain-1", "win-chain-1");
    if let Some(ref mut details) = ev_persist.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4698;
        details.action = "scheduled-task-created".to_string();
    }
    if let Some(ref mut user) = ev_persist.user {
        user.name = "svc_backup".to_string();
    }
    ev_persist.hash = "t-win-seq-4625-step3".to_string();

    let third_alerts = engine.evaluate_event(&ev_persist).await.unwrap();
    assert!(
        third_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_credential_to_priv_to_persistence_4625_4672_4698"),
        "4625 then 4672 then 4698 for same user/agent should trigger the multi-step sequence"
    );
}

#[tokio::test]
async fn rule_engine_windows_credential_to_priv_to_log_clear_sequence_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    let mut ev_auth_fail = test_event("agent-chain-2", "win-chain-2");
    if let Some(ref mut details) = ev_auth_fail.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4625;
        details.action = "logon-failed".to_string();
    }
    if let Some(ref mut user) = ev_auth_fail.user {
        user.name = "secops_temp".to_string();
    }
    ev_auth_fail.hash = "t-win-seq-4625-1102-step1".to_string();

    let first_alerts = engine.evaluate_event(&ev_auth_fail).await.unwrap();
    assert!(
        !first_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_credential_to_priv_to_log_clear_4625_4672_1102"),
        "Sequence should not trigger on first step only"
    );

    let mut ev_priv = test_event("agent-chain-2", "win-chain-2");
    if let Some(ref mut details) = ev_priv.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 4672;
        details.action = "special-privileges-assigned".to_string();
    }
    if let Some(ref mut user) = ev_priv.user {
        user.name = "secops_temp".to_string();
    }
    ev_priv.hash = "t-win-seq-4625-1102-step2".to_string();

    let second_alerts = engine.evaluate_event(&ev_priv).await.unwrap();
    assert!(
        !second_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_credential_to_priv_to_log_clear_4625_4672_1102"),
        "Sequence should not trigger on second step only"
    );

    let mut ev_log_clear = test_event("agent-chain-2", "win-chain-2");
    if let Some(ref mut details) = ev_log_clear.event {
        details.provider = "Microsoft-Windows-Security-Auditing".to_string();
        details.event_id = 1102;
        details.action = "log-cleared".to_string();
    }
    if let Some(ref mut user) = ev_log_clear.user {
        user.name = "secops_temp".to_string();
    }
    ev_log_clear.hash = "t-win-seq-4625-1102-step3".to_string();

    let third_alerts = engine.evaluate_event(&ev_log_clear).await.unwrap();
    assert!(
        third_alerts
            .iter()
            .any(|a| a.rule_id == "win_sequence_credential_to_priv_to_log_clear_4625_4672_1102"),
        "4625 then 4672 then 1102 for same user/agent should trigger the defense-evasion sequence"
    );
}

#[tokio::test]
async fn rule_engine_windows_4771_threshold_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules.yaml");
    engine.load_rules_from_file(&rules_path).await.unwrap();

    let mut saw_threshold_alert = false;
    for idx in 0..5 {
        let mut ev = test_event("agent-1", "dc-host-a");
        if let Some(ref mut details) = ev.event {
            details.provider = "Microsoft-Windows-Security-Auditing".to_string();
            details.event_id = 4771;
            details.outcome = 2; // FAILURE
            details.action = "kerberos_preauth".to_string();
            details.original_message =
                "Kerberos pre-authentication failed".to_string();
        }
        if let Some(ref mut user) = ev.user {
            user.name = "alice".to_string();
        }
        if let Some(ref mut agent) = ev.agent {
            agent.ip = "10.50.50.10".to_string();
        }
        ev.host = Some(percepta_server::percepta::event::Host {
            ip: vec!["10.50.50.10".to_string()],
            ..Default::default()
        });
        ev.hash = format!("t-win-4771-threshold-{idx}");

        let alerts = engine.evaluate_event(&ev).await.unwrap();
        if alerts
            .iter()
            .any(|a| a.rule_id == "win_kerberos_preauth_fail_4771_threshold")
        {
            saw_threshold_alert = true;
        }
    }

    assert!(
        saw_threshold_alert,
        "Windows 4771 burst should trigger win_kerberos_preauth_fail_4771_threshold"
    );
}

#[tokio::test]
async fn rule_engine_sequence_window_expiry_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_yaml = r#"
rules:
  - id: "test-seq-expiry"
    name: "Sequence expiry"
    description: "Sequence should expire before second step"
    enabled: true
    severity: "high"
    category: "authentication"
    conditions: []
    sequence:
      window_seconds: 1
      group_by: [agent.id, user.name]
      steps:
        - conditions:
            - field: event.event_id
              operator: equals
              value: "4720"
        - conditions:
            - field: event.event_id
              operator: equals
              value: "4722"
    actions:
      - type: "alert"
        message: "sequence fired"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let mut ev1 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev1.event {
        details.event_id = 4720;
    }
    if let Some(ref mut user) = ev1.user {
        user.name = "alice".to_string();
    }
    ev1.hash = "t-seq-expiry-step1".to_string();
    let first = engine.evaluate_event(&ev1).await.unwrap();
    assert!(first.is_empty());

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let mut ev2 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev2.event {
        details.event_id = 4722;
    }
    if let Some(ref mut user) = ev2.user {
        user.name = "alice".to_string();
    }
    ev2.hash = "t-seq-expiry-step2".to_string();
    let second = engine.evaluate_event(&ev2).await.unwrap();

    assert!(
        second.iter().all(|a| a.rule_id != "test-seq-expiry"),
        "Sequence should not fire after window expiry"
    );
}

#[tokio::test]
async fn rule_engine_sequence_grouping_mismatch_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_yaml = r#"
rules:
  - id: "test-seq-grouping"
    name: "Sequence grouping"
    description: "Sequence should not cross grouping keys"
    enabled: true
    severity: "high"
    category: "authentication"
    conditions: []
    sequence:
      window_seconds: 120
      group_by: [agent.id, user.name]
      steps:
        - conditions:
            - field: event.event_id
              operator: equals
              value: "4719"
        - conditions:
            - field: event.event_id
              operator: equals
              value: "1102"
    actions:
      - type: "alert"
        message: "sequence fired"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let mut ev1 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev1.event {
        details.event_id = 4719;
    }
    if let Some(ref mut user) = ev1.user {
        user.name = "alice".to_string();
    }
    ev1.hash = "t-seq-group-step1".to_string();
    let first = engine.evaluate_event(&ev1).await.unwrap();
    assert!(first.is_empty());

    let mut ev2 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev2.event {
        details.event_id = 1102;
    }
    if let Some(ref mut user) = ev2.user {
        user.name = "bob".to_string();
    }
    ev2.hash = "t-seq-group-step2".to_string();
    let second = engine.evaluate_event(&ev2).await.unwrap();

    assert!(
        second.iter().all(|a| a.rule_id != "test-seq-grouping"),
        "Sequence should not fire across grouping-key mismatch"
    );
}

#[tokio::test]
async fn rule_engine_sequence_retrigger_requires_new_chain_regression() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_yaml = r#"
rules:
  - id: "test-seq-retrigger"
    name: "Sequence retrigger"
    description: "Sequence retriggers only after a fresh step-0 event"
    enabled: true
    severity: "high"
    category: "authentication"
    conditions: []
    sequence:
      window_seconds: 120
      group_by: [agent.id, user.name]
      steps:
        - conditions:
            - field: event.event_id
              operator: equals
              value: "4719"
        - conditions:
            - field: event.event_id
              operator: equals
              value: "1102"
    actions:
      - type: "alert"
        message: "sequence fired"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let mut ev1 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev1.event {
        details.event_id = 4719;
    }
    if let Some(ref mut user) = ev1.user {
        user.name = "alice".to_string();
    }
    ev1.hash = "t-seq-retrigger-step1-a".to_string();
    let first = engine.evaluate_event(&ev1).await.unwrap();
    assert!(first.is_empty());

    let mut ev2 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev2.event {
        details.event_id = 1102;
    }
    if let Some(ref mut user) = ev2.user {
        user.name = "alice".to_string();
    }
    ev2.hash = "t-seq-retrigger-step2-a".to_string();
    let second = engine.evaluate_event(&ev2).await.unwrap();
    assert!(second.iter().any(|a| a.rule_id == "test-seq-retrigger"));

    // Repeating only step-1 should not retrigger without a fresh step-0.
    let mut ev3 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev3.event {
        details.event_id = 1102;
    }
    if let Some(ref mut user) = ev3.user {
        user.name = "alice".to_string();
    }
    ev3.hash = "t-seq-retrigger-step2-b".to_string();
    let third = engine.evaluate_event(&ev3).await.unwrap();
    assert!(
        third.iter().all(|a| a.rule_id != "test-seq-retrigger"),
        "Sequence must not retrigger from repeated terminal step"
    );

    // Fresh full chain should retrigger.
    let mut ev4 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev4.event {
        details.event_id = 4719;
    }
    if let Some(ref mut user) = ev4.user {
        user.name = "alice".to_string();
    }
    ev4.hash = "t-seq-retrigger-step1-b".to_string();
    let fourth = engine.evaluate_event(&ev4).await.unwrap();
    assert!(fourth.is_empty());

    let mut ev5 = test_event("agent-1", "win-host-a");
    if let Some(ref mut details) = ev5.event {
        details.event_id = 1102;
    }
    if let Some(ref mut user) = ev5.user {
        user.name = "alice".to_string();
    }
    ev5.hash = "t-seq-retrigger-step2-c".to_string();
    let fifth = engine.evaluate_event(&ev5).await.unwrap();
    assert!(
        fifth.iter().any(|a| a.rule_id == "test-seq-retrigger"),
        "Sequence should retrigger after a fresh full chain"
    );
}

#[tokio::test]
async fn rule_engine_evaluate_non_matching_event() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    // Load a minimal inline rules file
    let rules_yaml = r#"
rules:
  - id: "test-rule-001"
    name: "Detect specific process"
    description: "Fire on notepad.exe"
    enabled: true
    severity: "medium"
    category: "process"
    conditions:
      - field: "process.name"
        operator: "equals"
        value: "notepad.exe"
    actions:
      - type: "alert"
        message: "Notepad was launched"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    // Event with process="sshd" should NOT match the notepad rule
    let ev = test_event("agent-1", "host-a");
    let alerts = engine.evaluate_event(&ev).await.unwrap();
    assert!(alerts.is_empty(), "sshd should not match notepad rule");
}

#[tokio::test]
async fn rule_engine_evaluate_matching_event() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc.clone());

    let rules_yaml = r#"
rules:
  - id: "test-rule-002"
    name: "Detect sshd"
    description: "Fire on sshd process"
    enabled: true
    severity: "high"
    category: "process"
    conditions:
      - field: "process.name"
        operator: "equals"
        value: "sshd"
    actions:
      - type: "alert"
        message: "sshd was detected"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let ev = test_event("agent-1", "host-a");
    let alerts = engine.evaluate_event(&ev).await.unwrap();
    assert_eq!(alerts.len(), 1, "sshd should match the sshd rule");
    assert_eq!(alerts[0].rule_id, "test-rule-002");
    assert_eq!(alerts[0].severity, AlertSeverity::High);
}

#[tokio::test]
async fn rule_engine_disabled_rule_skipped() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_yaml = r#"
rules:
  - id: "test-disabled"
    name: "Disabled rule"
    description: "Should be skipped"
    enabled: false
    severity: "critical"
    category: "process"
    conditions:
      - field: "process.name"
        operator: "equals"
        value: "sshd"
    actions:
      - type: "alert"
        message: "Should never fire"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let ev = test_event("agent-1", "host-a");
    let alerts = engine.evaluate_event(&ev).await.unwrap();
    assert!(alerts.is_empty(), "Disabled rule should not fire");
}

#[tokio::test]
async fn rule_engine_exception_skips_rule() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_yaml = r#"
rules:
  - id: "test-exception"
    name: "Detect sshd with exception"
    description: "Fire on sshd unless agent is host-a"
    enabled: true
    severity: "medium"
    category: "process"
    conditions:
      - field: "process.name"
        operator: "equals"
        value: "sshd"
    exceptions:
      - name: "Allow host-a"
        conditions:
          - field: "agent.hostname"
            operator: "equals"
            value: "host-a"
    actions:
      - type: "alert"
        message: "sshd detected"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let ev = test_event("agent-1", "host-a");
    let alerts = engine.evaluate_event(&ev).await.unwrap();
    assert!(
        alerts.is_empty(),
        "Exception should prevent rule from firing"
    );
}

#[tokio::test]
async fn rule_engine_mitre_metadata_in_alert() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc.clone());

    let rules_yaml = r#"
rules:
  - id: "test-mitre"
    name: "MITRE tagged rule"
    description: "Rule with MITRE ATT&CK metadata"
    enabled: true
    severity: "high"
    category: "process"
    mitre_attack:
      - "T1059.001"
    mitre_tactics:
      - "execution"
    conditions:
      - field: "process.name"
        operator: "equals"
        value: "sshd"
    actions:
      - type: "alert"
        message: "sshd detected with MITRE"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let ev = test_event("agent-1", "host-a");
    let alerts = engine.evaluate_event(&ev).await.unwrap();
    assert_eq!(alerts.len(), 1);

    let md = &alerts[0].metadata;
    assert_eq!(md.get("mitre_attack").unwrap(), "T1059.001");
    assert_eq!(md.get("mitre_tactics").unwrap(), "execution");
}

#[tokio::test]
async fn rule_engine_regex_condition() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_yaml = r#"
rules:
  - id: "test-regex"
    name: "Regex match"
    description: "Match process name via regex"
    enabled: true
    severity: "low"
    category: "process"
    conditions:
      - field: "process.name"
        operator: "regex"
        value: "^ssh"
    actions:
      - type: "alert"
        message: "SSH-related process"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let ev = test_event("agent-1", "host-a");
    let alerts = engine.evaluate_event(&ev).await.unwrap();
    assert_eq!(alerts.len(), 1, "Regex ^ssh should match sshd");
}

#[tokio::test]
async fn rule_engine_contains_condition() {
    let alert_svc = Arc::new(AlertService::new(300, 3600));
    let engine = RuleEngine::new(alert_svc);

    let rules_yaml = r#"
rules:
  - id: "test-contains"
    name: "Contains match"
    description: "Match process command_line containing -D"
    enabled: true
    severity: "info"
    category: "process"
    conditions:
      - field: "process.command_line"
        operator: "contains"
        value: "-D"
    actions:
      - type: "alert"
        message: "Daemon mode detected"
"#;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), rules_yaml).unwrap();
    engine.load_rules_from_file(tmp.path()).await.unwrap();

    let ev = test_event("agent-1", "host-a"); // command_line = "/usr/sbin/sshd -D"
    let alerts = engine.evaluate_event(&ev).await.unwrap();
    assert_eq!(alerts.len(), 1, "contains -D should match sshd -D");
}
