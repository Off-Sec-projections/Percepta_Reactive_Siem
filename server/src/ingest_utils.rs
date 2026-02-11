use anyhow::{anyhow, Result};
use chrono::Utc;
use prost_types::Timestamp;
use std::collections::hash_map::Entry;
use uuid::Uuid;

use percepta_server::percepta::event::Agent;
use percepta_server::percepta::Event;

pub fn ensure_event_hash(event: &mut Event) {
    if event.hash.is_empty() {
        event.hash = Uuid::new_v4().to_string();
    }
}

pub fn enrich_event(event: &mut Event, agent_hint: Option<&str>) {
    let now = Utc::now();

    if event.ingest_time.is_none() {
        event.ingest_time = Some(Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos() as i32,
        });
    }

    if event.event_time.is_none() {
        event.event_time = event.ingest_time.clone();
    }

    match event.agent.as_mut() {
        Some(agent) => {
            if let Some(hint) = agent_hint {
                // Always normalize agent.id to the mTLS identity (CN) for consistent
                // connected-agent tracking and UI correlation.
                if !agent.id.is_empty() && agent.id != hint {
                    event
                        .metadata
                        .entry("agent.reported_id".to_string())
                        .or_insert_with(|| agent.id.clone());
                }
                agent.id = hint.to_string();
            } else if agent.id.is_empty() {
                // Leave as-is; validate_event will reject missing agent context.
            }
        }
        None => {
            if let Some(hint) = agent_hint {
                event.agent = Some(Agent {
                    id: hint.to_string(),
                    hostname: String::new(),
                    ip: String::new(),
                    mac: String::new(),
                    version: String::new(),
                    os: None,
                });
            }
        }
    }

    if let Some(agent) = event.agent.as_ref() {
        if !agent.hostname.is_empty() {
            match event.metadata.entry("host.hostname".to_string()) {
                Entry::Vacant(entry) => {
                    entry.insert(agent.hostname.clone());
                }
                Entry::Occupied(mut entry) if entry.get().is_empty() => {
                    entry.insert(agent.hostname.clone());
                }
                _ => {}
            }
        }

        // Friendly, stable display name for the UI.
        // Prefer hostname when present; fall back to the normalized agent.id (mTLS CN).
        let display_name = if !agent.hostname.trim().is_empty() {
            agent.hostname.clone()
        } else {
            agent.id.clone()
        };
        match event.metadata.entry("agent.display_name".to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(display_name);
            }
            Entry::Occupied(mut entry) if entry.get().is_empty() => {
                entry.insert(display_name);
            }
            _ => {}
        }

        match event.metadata.entry("agent.id".to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(agent.id.clone());
            }
            Entry::Occupied(mut entry) if entry.get().is_empty() => {
                entry.insert(agent.id.clone());
            }
            _ => {}
        }
    } else if let Some(hint) = agent_hint {
        event
            .metadata
            .entry("agent.id".to_string())
            .or_insert_with(|| hint.to_string());
    }

    // Backfill host context from agent context when collectors omit it.
    if let Some(agent) = event.agent.as_ref() {
        let host = event
            .host
            .get_or_insert_with(|| percepta_server::percepta::event::Host {
                ip: Vec::new(),
                mac: Vec::new(),
            });

        if host.ip.is_empty() && !agent.ip.trim().is_empty() {
            host.ip.push(agent.ip.clone());
        }
        if host.mac.is_empty() {
            let m = agent.mac.trim();
            if !m.is_empty() && m != "unknown" {
                host.mac.push(agent.mac.clone());
            }
        }
    }

    if event.ingest_time.is_some() {
        event
            .metadata
            .entry("ingest.timestamp".to_string())
            .or_insert_with(|| {
                let ts = event.ingest_time.as_ref().unwrap();
                ts.seconds.to_string()
            });
    }
}

pub fn validate_event(event: &Event) -> Result<()> {
    if event.hash.is_empty() {
        return Err(anyhow!("Event missing hash"));
    }

    if event
        .agent
        .as_ref()
        .map(|agent| agent.id.is_empty())
        .unwrap_or(true)
    {
        return Err(anyhow!("Event missing agent context"));
    }

    if event.event_time.is_none() {
        return Err(anyhow!("Event missing event_time"));
    }

    if event.event.is_none() {
        return Err(anyhow!("Event missing normalized event details"));
    }

    Ok(())
}
