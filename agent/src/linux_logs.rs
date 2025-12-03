//! Linux Log Collection Module
//!
//! Collects real system logs from Linux systems:
//! - /var/log/auth.log - Authentication events
//! - /var/log/syslog - System events
//! - journalctl - Systemd journal (if available)

use anyhow::Result;
use chrono::Utc;
use prost_types::Timestamp;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::fs;
use tracing::debug;
use uuid::Uuid;

use crate::system_info;

use crate::percepta::{
    event::{EventCategory, EventDetails, EventOutcome},
    Event,
};

pub struct LinuxLogCollector {
    agent_id: String,
    agent: crate::percepta::event::Agent,
    host: crate::percepta::event::Host,
    cursor_path: PathBuf,
    last_auth_position: u64,
    last_syslog_position: u64,
}

impl LinuxLogCollector {
    pub async fn initialize(agent_id: String, cert_dir: PathBuf) -> Result<Self> {
        let cursor_path = cert_dir.join("linux_log_cursor.json");
        
        let (last_auth_position, last_syslog_position) = if cursor_path.exists() {
            let content = fs::read_to_string(&cursor_path).await?;
            let cursor: LogCursor = serde_json::from_str(&content).unwrap_or_default();
            (cursor.auth_position, cursor.syslog_position)
        } else {
            // Start from current position (don't read entire history)
            let auth_pos = Self::get_file_size("/var/log/auth.log").await.unwrap_or(0);
            let syslog_pos = Self::get_file_size("/var/log/syslog").await.unwrap_or(0);
            (auth_pos, syslog_pos)
        };

        let agent = system_info::build_agent(&agent_id);
        let host = system_info::build_host(&agent);

        Ok(Self {
            agent_id,
            agent,
            host,
            cursor_path,
            last_auth_position,
            last_syslog_position,
        })
    }

    pub async fn collect_events(&mut self, max_events: usize) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        // Collect from auth.log
        if let Ok(auth_events) = self.collect_from_auth_log(max_events / 2).await {
            events.extend(auth_events);
        }

        // Collect from syslog
        if let Ok(syslog_events) = self.collect_from_syslog(max_events / 2).await {
            events.extend(syslog_events);
        }

        // Collect from journalctl (systemd)
        if let Ok(journal_events) = self.collect_from_journalctl(50).await {
            events.extend(journal_events);
        }

        // Save cursor position
        self.save_cursor().await?;

        debug!("Collected {} Linux log events", events.len());
        Ok(events)
    }

    async fn collect_from_auth_log(&mut self, max_events: usize) -> Result<Vec<Event>> {
        let path = Path::new("/var/log/auth.log");
        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(path).await?;
        let bytes = content.as_bytes();
        
        if (self.last_auth_position as usize) >= bytes.len() {
            return Ok(Vec::new());
        }

        let new_content = &content[self.last_auth_position as usize..];
        let lines: Vec<&str> = new_content.lines().take(max_events).collect();
        
        let mut events = Vec::new();
        for line in lines {
            if let Some(event) = self.parse_auth_log_line(line).await {
                events.push(event);
            }
        }

        self.last_auth_position = bytes.len() as u64;
        Ok(events)
    }

    async fn collect_from_syslog(&mut self, max_events: usize) -> Result<Vec<Event>> {
        let path = Path::new("/var/log/syslog");
        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(path).await?;
        let bytes = content.as_bytes();
        
        if (self.last_syslog_position as usize) >= bytes.len() {
            return Ok(Vec::new());
        }

        let new_content = &content[self.last_syslog_position as usize..];
        let lines: Vec<&str> = new_content.lines().take(max_events).collect();
        
        let mut events = Vec::new();
        for line in lines {
            if let Some(event) = self.parse_syslog_line(line).await {
                events.push(event);
            }
        }

        self.last_syslog_position = bytes.len() as u64;
        Ok(events)
    }

    async fn collect_from_journalctl(&self, max_events: usize) -> Result<Vec<Event>> {
        // Use journalctl to get recent logs
        let output = Command::new("journalctl")
            .args(&[
                "-n",
                &max_events.to_string(),
                "--output=json",
                "--no-pager",
            ])
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => return Ok(Vec::new()), // journalctl not available or failed
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut events = Vec::new();

        for line in stdout.lines().take(max_events) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(event) = self.parse_journalctl_entry(&json).await {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }

    async fn parse_auth_log_line(&self, line: &str) -> Option<Event> {
        if line.trim().is_empty() {
            return None;
        }

        let now = Utc::now();
        let timestamp = Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos() as i32,
        };

        // Parse auth.log patterns
        let (category, action, outcome, summary) = if line.contains("Failed password") {
            (EventCategory::Auth, "login_failed", EventOutcome::Failure, "Failed password authentication")
        } else if line.contains("Accepted password") || line.contains("Accepted publickey") {
            (EventCategory::Auth, "login_success", EventOutcome::Success, "Successful authentication")
        } else if line.contains("sudo:") {
            (EventCategory::Process, "sudo_execution", EventOutcome::Success, "Sudo command executed")
        } else if line.contains("session opened") {
            (EventCategory::Auth, "session_start", EventOutcome::Success, "User session opened")
        } else if line.contains("session closed") {
            (EventCategory::Auth, "session_end", EventOutcome::Success, "User session closed")
        } else {
            (EventCategory::System, "log_entry", EventOutcome::Success, "System log entry")
        };

        let hash = format!("{}-{}", self.agent_id, Uuid::new_v4());

        Some(Event {
            event_time: Some(timestamp.clone()),
            ingest_time: Some(timestamp),
            agent: Some(self.agent.clone()),
            host: Some(self.host.clone()),
            event: Some(EventDetails {
                summary: summary.to_string(),
                original_message: line.to_string(),
                category: category as i32,
                action: action.to_string(),
                outcome: outcome as i32,
                level: "Info".to_string(),
                severity: 1,
                provider: "auth.log".to_string(),
                event_id: 0,
                record_id: 0,
            }),
            hash,
            ..Default::default()
        })
    }

    async fn parse_syslog_line(&self, line: &str) -> Option<Event> {
        if line.trim().is_empty() {
            return None;
        }

        let now = Utc::now();
        let timestamp = Timestamp {
            seconds: now.timestamp(),
            nanos: now.timestamp_subsec_nanos() as i32,
        };

        let summary = if line.len() > 100 {
            &line[..100]
        } else {
            line
        };

        let hash = format!("{}-{}", self.agent_id, Uuid::new_v4());

        Some(Event {
            event_time: Some(timestamp.clone()),
            ingest_time: Some(timestamp),
            agent: Some(self.agent.clone()),
            host: Some(self.host.clone()),
            event: Some(EventDetails {
                summary: summary.to_string(),
                original_message: line.to_string(),
                category: EventCategory::System as i32,
                action: "log_entry".to_string(),
                outcome: EventOutcome::Success as i32,
                level: "Info".to_string(),
                severity: 1,
                provider: "syslog".to_string(),
                event_id: 0,
                record_id: 0,
            }),
            hash,
            ..Default::default()
        })
    }

    async fn parse_journalctl_entry(&self, json: &serde_json::Value) -> Option<Event> {
        let message = json.get("MESSAGE")?.as_str()?;
        let timestamp_usec = json.get("__REALTIME_TIMESTAMP")?.as_str()?.parse::<i64>().ok()?;
        
        let timestamp = Timestamp {
            seconds: timestamp_usec / 1_000_000,
            nanos: ((timestamp_usec % 1_000_000) * 1000) as i32,
        };

        let hash = format!("{}-{}", self.agent_id, Uuid::new_v4());

        Some(Event {
            event_time: Some(timestamp.clone()),
            ingest_time: Some(timestamp),
            agent: Some(self.agent.clone()),
            host: Some(self.host.clone()),
            event: Some(EventDetails {
                summary: message.to_string(),
                original_message: message.to_string(),
                category: EventCategory::System as i32,
                action: "journal_entry".to_string(),
                outcome: EventOutcome::Success as i32,
                level: "Info".to_string(),
                severity: 1,
                provider: "journald".to_string(),
                event_id: 0,
                record_id: 0,
            }),
            hash,
            ..Default::default()
        })
    }

    async fn save_cursor(&self) -> Result<()> {
        let cursor = LogCursor {
            auth_position: self.last_auth_position,
            syslog_position: self.last_syslog_position,
        };

        let json = serde_json::to_string_pretty(&cursor)?;
        fs::write(&self.cursor_path, json).await?;
        Ok(())
    }

    async fn get_file_size(path: &str) -> Result<u64> {
        let metadata = fs::metadata(path).await?;
        Ok(metadata.len())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
struct LogCursor {
    auth_position: u64,
    syslog_position: u64,
}
