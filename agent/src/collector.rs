//! Event Collection Module
//!
//! Provides event collection capabilities for the Percepta SIEM agent.
//!
//! - On Windows, leverages the native `WindowsEventCollector` for incremental
//!   collection with cursor persistence stored alongside agent certificates.
//! - On other platforms, or when the windows feature is not enabled, a simulated
//!   event generator is used.

use anyhow::Result;
use openssl::sha::sha256;
use std::{path::PathBuf, time::Duration};
use tokio::time::sleep;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::system_info;

use crate::percepta::{
    event::{
        Agent, EventCategory, EventDetails, File, FileOperation, Network, NetworkDirection,
        Process, User,
    },
    Event,
};

#[cfg(target_os = "windows")]
use crate::windows_eventlog::WindowsEventCollector;

#[cfg(target_os = "linux")]
use crate::linux_logs::LinuxLogCollector;

const EVENT_BATCH_MAX: usize = 512;

fn get_agent_info(agent_id: &str) -> Result<Agent> {
    Ok(system_info::build_agent(agent_id))
}

pub async fn collect_once(
    agent_id: &str,
    cert_dir: PathBuf,
    simulate_mode: bool,
) -> Result<Vec<Event>> {
    if simulate_mode {
        return collect_simulated_events(agent_id).await;
    }

    #[cfg(target_os = "windows")]
    {
        let mut collector =
            WindowsEventCollector::initialize(agent_id.to_string(), cert_dir).await?;
        collector.collect_events(EVENT_BATCH_MAX).await
    }

    #[cfg(target_os = "linux")]
    {
        let mut collector =
            LinuxLogCollector::initialize(agent_id.to_string(), cert_dir).await?;
        collector.collect_events(EVENT_BATCH_MAX).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = cert_dir;
        collect_simulated_events(agent_id).await
    }
}

pub async fn collect_loop(
    simulate_mode: bool,
    agent_id: String,
    cert_dir: PathBuf,
    event_sender: tokio::sync::mpsc::UnboundedSender<Vec<Event>>,
) -> Result<()> {
    // Collection cadence strongly affects “time to appear” on the dashboard.
    // Default to near-real-time while keeping it configurable.
    // Env: PERCEPTA_COLLECT_INTERVAL_MS (default 2000, min 1000, max 60000)
    let poll_interval = {
        let raw = std::env::var("PERCEPTA_COLLECT_INTERVAL_MS").ok();
        let ms = raw
            .as_deref()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(2000);
        let ms = ms.clamp(1000, 60_000);
        Duration::from_millis(ms)
    };
    let mut interval = tokio::time::interval(poll_interval);
    info!(
        "Starting event collection loop (simulate_mode: {}, interval_ms: {})",
        simulate_mode
        , poll_interval.as_millis()
    );

    #[cfg(target_os = "windows")]
    let mut windows_collector = if simulate_mode {
        None
    } else {
        match WindowsEventCollector::initialize(agent_id.clone(), cert_dir.clone()).await {
            Ok(collector) => Some(collector),
            Err(e) => {
                tracing::warn!("Failed to initialize Windows collector: {:#}. Falling back to simulated events.", e);
                None
            }
        }
    };

    #[cfg(target_os = "linux")]
    let mut linux_collector = if simulate_mode {
        None
    } else {
        match LinuxLogCollector::initialize(agent_id.clone(), cert_dir.clone()).await {
            Ok(collector) => Some(collector),
            Err(e) => {
                tracing::warn!("Failed to initialize Linux collector: {:#}. Falling back to simulated events.", e);
                None
            }
        }
    };

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    let _ = &cert_dir;

    // Perform an initial collection once at startup to reduce latency
    match collect_once(&agent_id, cert_dir.clone(), simulate_mode).await {
        Ok(initial) if !initial.is_empty() => {
            debug!("Collected {} initial events", initial.len());
            if let Err(e) = event_sender.send(initial) {
                error!("Failed to send initial events: {}", e);
            }
        }
        Ok(_) => {
            debug!("No initial events collected");
        }
        Err(e) => {
            error!("Initial event collection failed: {:#}", e);
        }
    }

    loop {
        interval.tick().await;

        let events_result = if simulate_mode {
            collect_simulated_events(&agent_id).await
        } else {
            #[cfg(target_os = "windows")]
            {
                if let Some(ref mut collector) = windows_collector {
                    collector.collect_events(EVENT_BATCH_MAX).await
                } else {
                    collect_simulated_events(&agent_id).await
                }
            }

            #[cfg(target_os = "linux")]
            {
                if let Some(ref mut collector) = linux_collector {
                    collector.collect_events(EVENT_BATCH_MAX).await
                } else {
                    collect_simulated_events(&agent_id).await
                }
            }

            #[cfg(not(any(target_os = "windows", target_os = "linux")))]
            {
                collect_simulated_events(&agent_id).await
            }
        };

        match events_result {
            Ok(events) if !events.is_empty() => {
                let current_user = system_info::get_current_username();
                let mut events = events;
                for evt in &mut events {
                    // Always attach current session user for GUI display.
                    evt.metadata
                        .insert("current_user".to_string(), current_user.clone());

                    // If the collector didn't provide a specific user (common on Linux/syslog/system
                    // events), fall back to the current session user.
                    if evt.user.is_none() && current_user != "unknown" {
                        evt.user = Some(User {
                            id: String::new(),
                            name: current_user.clone(),
                            domain: String::new(),
                            privileges: Vec::new(),
                        });
                    }
                }

                debug!("Collected {} events", events.len());
                if let Err(e) = event_sender.send(events) {
                    error!("Failed to send events: {}", e);
                    break;
                }
            }
            Ok(_) => {
                debug!("No new events collected this cycle");
            }
            Err(e) => {
                error!("Event collection failed: {:#}", e);
                sleep(Duration::from_secs(60)).await;
            }
        }
    }

    Ok(())
}

async fn collect_simulated_events(agent_id: &str) -> Result<Vec<Event>> {
    let agent_info = get_agent_info(agent_id)?;
    let mut events = Vec::new();
    let count = fastrand::usize(1..=EVENT_BATCH_MAX.min(5));
    for i in 0..count {
        events.push(generate_dummy_event(&agent_info, agent_id, i)?);
    }
    debug!("Generated {} simulated events", events.len());
    Ok(events)
}

fn generate_dummy_event(agent_info: &Agent, agent_id: &str, sequence: usize) -> Result<Event> {
    use chrono::Utc;
    let now = Utc::now();
    let event_id = fastrand::u32(1000..9999);
    let record_id = fastrand::u64(100000..999999);
    let providers = [
        "Microsoft-Windows-Security-Auditing",
        "Service Control Manager",
        "Application",
    ];
    let provider = providers[sequence % providers.len()];
    let correlation_id = Uuid::new_v4().to_string();
    let hash = hex::encode(sha256(
        format!("{}{}{}", agent_id, now.timestamp(), event_id).as_bytes(),
    ));
    let category = match provider {
        "Microsoft-Windows-Security-Auditing" => EventCategory::Auth,
        "Service Control Manager" => EventCategory::System,
        _ => EventCategory::Other,
    };
    let level = match fastrand::usize(0..4) {
        0 => "Info".to_string(),
        1 => "Warning".to_string(),
        2 => "Error".to_string(),
        _ => "Critical".to_string(),
    };
    let summary = match category {
        EventCategory::Auth => "User authentication event".to_string(),
        EventCategory::System => "System service event".to_string(),
        _ => "Application event".to_string(),
    };
    let message = match category {
        EventCategory::Auth => {
            format!("An account was successfully logged on. Subject: User: SYSTEM")
        }
        EventCategory::System => format!(
            "The {} service entered the running state.",
            ["Windows Update", "BITS", "Spooler"][sequence % 3]
        ),
        _ => format!(
            "Application event {} occurred in process {}",
            event_id,
            fastrand::u32(1000..9999)
        ),
    };

    let direction = match category {
        EventCategory::Auth => NetworkDirection::Inbound,
        EventCategory::System => NetworkDirection::Outbound,
        _ => NetworkDirection::Lateral,
    } as i32;

    let network = Network {
        src_ip: format!("192.168.1.{}", 10 + sequence % 200),
        src_port: 40_000 + sequence as u32,
        dst_ip: agent_info.ip.clone(),
        dst_port: match category {
            EventCategory::Auth => 3389,
            EventCategory::System => 445,
            _ => 80,
        },
        protocol: "tcp".to_string(),
        direction,
        bytes_in: fastrand::u64(512..32_768),
        bytes_out: fastrand::u64(256..16_384),
        flow_duration_ms: fastrand::u64(50..5_000),
        tls_sni: String::new(),
        ja3: String::new(),
        ja3s: String::new(),
        tls_cert_subject: String::new(),
        tls_cert_issuer: String::new(),
    };

    let mut process_hash = std::collections::HashMap::new();
    process_hash.insert(
        "sha256".to_string(),
        hex::encode(sha256(message.as_bytes())),
    );

    let process = Process {
        pid: 3_000 + sequence as u32,
        ppid: 2_000 + sequence as u32,
        name: format!("proc_{}.exe", sequence),
        command_line: format!("C:/Program Files/Example/proc_{} --run", sequence),
        hash: process_hash,
    };

    let mut file_hash = std::collections::HashMap::new();
    file_hash.insert(
        "sha256".to_string(),
        hex::encode(sha256(summary.as_bytes())),
    );

    let file = File {
        path: format!("C:/Windows/Temp/sample_{}.log", sequence),
        hash: file_hash,
        permissions: "rw-r--r--".to_string(),
        operation: match category {
            EventCategory::System => FileOperation::Modified as i32,
            EventCategory::Auth => FileOperation::Read as i32,
            _ => FileOperation::FileOpUnknown as i32,
        },
    };

    Ok(Event {
        event_time: Some(prost_types::Timestamp {
            seconds: now.timestamp(),
            nanos: (now.timestamp_subsec_nanos()) as i32,
        }),
        ingest_time: Some(prost_types::Timestamp {
            seconds: now.timestamp(),
            nanos: (now.timestamp_subsec_nanos()) as i32,
        }),
        agent: Some(agent_info.clone()),
        event: Some(EventDetails {
            summary: summary.clone(),
            original_message: message.clone(),
            category: category as i32,
            action: "".to_string(),
            outcome: 0,
            level: level.clone(),
            severity: 1,
            provider: provider.to_string(),
            event_id: event_id as u64,
            record_id,
        }),
        user: Some(User {
            id: "S-1-5-18".to_string(),
            name: "SYSTEM".to_string(),
            domain: "NT AUTHORITY".to_string(),
            privileges: vec![],
        }),
        host: Some(system_info::build_host(&agent_info)),
        network: Some(network),
        process: Some(process),
        file: Some(file),
        registry: None,
        metadata: std::collections::HashMap::new(),
        tags: vec![],
        threat_indicator: "".to_string(),
        threat_source: "".to_string(),
        correlation_id,
        hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_collect_simulated_events() {
        let events = collect_simulated_events("test").await.unwrap();
        assert!(!events.is_empty());
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn test_collect_once_non_windows() {
        let cert_dir = std::env::temp_dir();
        let events = collect_once("test", cert_dir, false).await.unwrap();
        assert!(!events.is_empty());
    }
}
