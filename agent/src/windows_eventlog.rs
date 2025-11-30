//! Windows Event Log Collector
//! Reads events from Windows Event Log channels (Security, System, Application)
//! and converts them to the SIEM Event protobuf format. Maintains bookmark
//! state on disk so subsequent runs resume from the last processed record.

#[cfg(windows)]
use anyhow::{bail, Context, Result};
#[cfg(windows)]
use chrono::{DateTime, Duration, Utc};
#[cfg(windows)]
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
#[cfg(windows)]
use tokio::fs;
#[cfg(windows)]
use tracing::{debug, info, warn};
#[cfg(windows)]
use windows::{
    core::PCWSTR,
    Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryReverseDirection, EvtRender,
        EvtRenderEventXml, EVT_HANDLE,
    },
};

use crate::percepta::Event;

#[cfg(windows)]
const CURSOR_FILENAME: &str = "cursors.json";
#[cfg(windows)]
const MAX_EVENTS_PER_CHANNEL: usize = 256;

#[cfg(windows)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChannelCursor {
    last_record_id: u64,
    last_update: DateTime<Utc>,
}

#[cfg(windows)]
impl Default for ChannelCursor {
    fn default() -> Self {
        // Start five minutes in the past so initial enrollment captures a small window
        Self {
            last_record_id: 0,
            last_update: Utc::now() - Duration::minutes(5),
        }
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CursorState {
    security: ChannelCursor,
    system: ChannelCursor,
    application: ChannelCursor,
}

#[cfg(windows)]
impl CursorState {
    async fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)
            .await
            .context("Failed to read Windows cursor file")?;
        let state =
            serde_json::from_str(&content).context("Failed to parse Windows cursor file")?;
        Ok(state)
    }

    async fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .context("Failed to create cursor directory")?;
        }
        let body =
            serde_json::to_string_pretty(self).context("Failed to serialize cursor state")?;
        fs::write(path, body)
            .await
            .context("Failed to write cursor state")?;
        Ok(())
    }
}

#[cfg(windows)]
pub struct WindowsEventCollector {
    channels: Vec<String>,
    agent_id: String,
    state: CursorState,
    state_path: PathBuf,
}

#[cfg(windows)]
impl WindowsEventCollector {
    /// Create a new Windows Event Log collector with persisted cursor state
    pub async fn initialize(agent_id: String, cert_dir: PathBuf) -> Result<Self> {
        let state_path = cert_dir.join(CURSOR_FILENAME);
        let state = CursorState::load(&state_path).await?;

        Ok(Self {
            channels: vec![
                "Security".to_string(),
                "System".to_string(),
                "Application".to_string(),
            ],
            agent_id,
            state,
            state_path,
        })
    }

    /// Collect events from Windows Event Log and persist updated cursor state
    pub async fn collect_events(&mut self, max_events: usize) -> Result<Vec<Event>> {
        info!(
            "🪟 Collecting Windows Event Log events (target {})",
            max_events
        );

        let mut collected = Vec::new();

        // Clone channel list to avoid borrowing self immutably while mutably borrowing in calls
        let channels = self.channels.clone();
        for channel in channels.iter() {
            let channel_max = max_events
                .saturating_sub(collected.len())
                .min(MAX_EVENTS_PER_CHANNEL);
            if channel_max == 0 {
                break;
            }

            let result = self.read_channel_events(channel, channel_max).await;
            match result {
                Ok(events) => {
                    if !events.is_empty() {
                        debug!("Collected {} events from {}", events.len(), channel);
                        collected.extend(events);
                    }
                }
                Err(e) => {
                    warn!("Failed to read events from {}: {}", channel, e);
                }
            }

            if collected.len() >= max_events {
                break;
            }
        }

        if !collected.is_empty() {
            self.state.save(&self.state_path).await?;
        }

        info!("✅ Collected {} Windows events", collected.len());
        Ok(collected)
    }

    async fn read_channel_events(
        &mut self,
        channel: &str,
        max_events: usize,
    ) -> Result<Vec<Event>> {
        let mut events = Vec::new();

        // Open event log channel
        let channel_wide: Vec<u16> = channel.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // Query for recent events (newest first)
            // Use the persisted last_update as the time window upper bound to reduce duplicates.
            let last_update = match channel {
                "Security" => self.state.security.last_update,
                "System" => self.state.system.last_update,
                "Application" => self.state.application.last_update,
                _ => Utc::now() - Duration::minutes(5),
            };
            let mut timediff_ms = (Utc::now() - last_update).num_milliseconds();
            if timediff_ms <= 0 {
                timediff_ms = 60_000;
            }
            if timediff_ms > 3_600_000 {
                timediff_ms = 3_600_000;
            }
            // If we have a last_record_id > 0 include it to reduce duplicates.
            let last_record_id = match channel {
                "Security" => self.state.security.last_record_id,
                "System" => self.state.system.last_record_id,
                "Application" => self.state.application.last_record_id,
                _ => 0,
            };
            let query = if last_record_id > 0 {
                format!(
                    "*[System[(EventRecordID>{}) and TimeCreated[timediff(@SystemTime) <= {}]]]",
                    last_record_id, timediff_ms
                )
            } else {
                format!(
                    "*[System[TimeCreated[timediff(@SystemTime) <= {}]]]",
                    timediff_ms
                )
            };
            let query_wide: Vec<u16> = query.encode_utf16().chain(std::iter::once(0)).collect();
            let query_pwstr = PCWSTR::from_raw(query_wide.as_ptr());
            let channel_pcwstr = PCWSTR::from_raw(channel_wide.as_ptr());

            let handle = EvtQuery(
                None,
                channel_pcwstr,
                query_pwstr,
                EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
            )?;

            // Read events in batches
            let mut raw_handles: Vec<isize> = vec![0; 100];
            let mut returned = 0u32;

            while EvtNext(
                handle,
                &mut raw_handles,
                0, // timeout (no timeout)
                0, // flags
                &mut returned,
            )
            .is_ok()
                && returned > 0
            {
                for i in 0..returned as usize {
                    let raw = raw_handles[i];
                    if raw != 0 {
                        let event_handle = EVT_HANDLE(raw);
                        if let Ok(event) = self.parse_event(event_handle, channel).await {
                            events.push(event);
                            if events.len() >= max_events {
                                let _ = EvtClose(event_handle);
                                break;
                            }
                        }
                        let _ = EvtClose(event_handle);
                    }
                }

                if events.len() >= max_events {
                    break;
                }
            }

            let _ = EvtClose(handle);
        }

        // Update cursor for this channel
        if !events.is_empty() {
            let max_record_id = events
                .iter()
                .filter_map(|e| e.event.as_ref().map(|d| d.record_id))
                .max()
                .unwrap_or(0);
            let now = Utc::now();
            match channel {
                "Security" => {
                    self.state.security.last_record_id = max_record_id;
                    self.state.security.last_update = now;
                }
                "System" => {
                    self.state.system.last_record_id = max_record_id;
                    self.state.system.last_update = now;
                }
                "Application" => {
                    self.state.application.last_record_id = max_record_id;
                    self.state.application.last_update = now;
                }
                _ => {}
            }
        }

        Ok(events)
    }

    async fn parse_event(&self, event_handle: EVT_HANDLE, channel: &str) -> Result<Event> {
        unsafe {
            // Get event XML
            let xml = self.get_event_xml(event_handle)?;

            // Parse XML to extract fields
            let (event_id, timestamp, system_data, event_data) = self.parse_event_xml(&xml)?;

            // Extract record_id if available for downstream enrichment and hashing
            let record_id = system_data
                .get("EventRecordID")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            // Build Event protobuf based on event ID
            let mut event = match event_id {
                4624 => self.build_logon_success_event(timestamp, &system_data, &event_data)?,
                4625 => self.build_logon_failure_event(timestamp, &system_data, &event_data)?,
                4688 => self.build_process_creation_event(timestamp, &system_data, &event_data)?,
                4672 => {
                    self.build_privilege_assignment_event(timestamp, &system_data, &event_data)?
                }
                4720 => self.build_user_created_event(timestamp, &system_data, &event_data)?,
                _ => self.build_generic_event(event_id, timestamp, channel, &system_data)?,
            };

            // Populate record_id and provider if missing
            if let Some(ref mut details) = event.event {
                if details.record_id == 0 {
                    details.record_id = record_id;
                }
                if details.provider.is_empty() {
                    if let Some(provider) = system_data.get("Provider") {
                        details.provider = provider.clone();
                    }
                }
            }

            // Ensure a stable, deterministic hash for deduplication: use channel/event_id/record_id/timestamp
            if let Some(ref details) = event.event {
                use openssl::sha::sha256;
                // Include nanos and provider to reduce collision risk; append a short UUID segment.
                let provider = &details.provider;
                let nanos = timestamp.timestamp_subsec_nanos();
                let entropy = uuid::Uuid::new_v4().to_string();
                let short_entropy = &entropy[..8];
                let base = format!(
                    "{}:{}:{}:{}:{}:{}",
                    channel,
                    details.event_id,
                    details.record_id,
                    timestamp.timestamp(),
                    nanos,
                    provider
                );
                let digest = sha256(base.as_bytes());
                event.hash = format!("{}{}", hex::encode(digest), short_entropy);
            }

            Ok(event)
        }
    }

    unsafe fn get_event_xml(&self, event_handle: EVT_HANDLE) -> Result<String> {
        let mut buffer_size = 0u32;
        let mut buffer_used = 0u32;
        let mut property_count = 0u32;

        // Get required buffer size
        let _ = EvtRender(
            EVT_HANDLE::default(),
            event_handle,
            EvtRenderEventXml.0,
            buffer_size,
            None,
            &mut buffer_used,
            &mut property_count,
        );

        if buffer_used == 0 {
            bail!("Failed to get event XML buffer size");
        }

        // Allocate buffer
        buffer_size = buffer_used;
        let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];

        // Render event as XML
        EvtRender(
            EVT_HANDLE::default(),
            event_handle,
            EvtRenderEventXml.0,
            buffer_size,
            Some(buffer.as_mut_ptr() as *mut core::ffi::c_void),
            &mut buffer_used,
            &mut property_count,
        )?;

        // Convert to string
        let xml = String::from_utf16_lossy(&buffer);
        Ok(xml.trim_end_matches('\0').to_string())
    }

    fn parse_event_xml(
        &self,
        xml: &str,
    ) -> Result<(
        u32,
        DateTime<Utc>,
        HashMap<String, String>,
        HashMap<String, String>,
    )> {
        use quick_xml::events::Event as XmlEvent;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut event_id = 0u32;
        let mut timestamp = Utc::now();
        let mut system_data = HashMap::new();
        let mut event_data = HashMap::new();

        let mut current_section = String::new();
        let mut current_element = String::new();
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(XmlEvent::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                    if name == "System" {
                        current_section = "System".to_string();
                    } else if name == "EventData" {
                        current_section = "EventData".to_string();
                    } else if name == "Provider" && current_section == "System" {
                        // Provider has Name attribute
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"Name" {
                                    let val = String::from_utf8_lossy(&attr.value).to_string();
                                    system_data.insert("Provider".to_string(), val);
                                }
                            }
                        }
                        current_element = name;
                    } else if name == "Data" && current_section == "EventData" {
                        // Get Data Name attribute
                        if let Some(attr) = e
                            .attributes()
                            .find(|a| a.as_ref().ok().map(|a| a.key.as_ref()) == Some(b"Name"))
                        {
                            if let Ok(attr) = attr {
                                current_element = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    } else {
                        current_element = name;
                    }
                }
                Ok(XmlEvent::Text(e)) => {
                    let text = e.unescape().unwrap_or_default().to_string();

                    if current_section == "System" {
                        if current_element == "EventID" {
                            event_id = text.parse().unwrap_or(0);
                        } else if current_element == "EventRecordID" {
                            system_data.insert("EventRecordID".to_string(), text.clone());
                        } else if current_element == "TimeCreated" {
                            // TimeCreated is an attribute, handled separately
                        } else {
                            system_data.insert(current_element.clone(), text);
                        }
                    } else if current_section == "EventData" && !current_element.is_empty() {
                        event_data.insert(current_element.clone(), text);
                    }
                }
                Ok(XmlEvent::Empty(ref e)) => {
                    if String::from_utf8_lossy(e.name().as_ref()) == "TimeCreated" {
                        // Extract SystemTime attribute
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"SystemTime" {
                                    let time_str = String::from_utf8_lossy(&attr.value);
                                    if let Ok(dt) = DateTime::parse_from_rfc3339(&time_str) {
                                        timestamp = dt.with_timezone(&Utc);
                                    }
                                }
                            }
                        }
                    } else if String::from_utf8_lossy(e.name().as_ref()) == "Provider" {
                        // Also handle Provider as empty element
                        for attr in e.attributes() {
                            if let Ok(attr) = attr {
                                if attr.key.as_ref() == b"Name" {
                                    let val = String::from_utf8_lossy(&attr.value).to_string();
                                    system_data.insert("Provider".to_string(), val);
                                }
                            }
                        }
                    }
                }
                Ok(XmlEvent::Eof) => break,
                Err(e) => {
                    warn!("XML parse error: {}", e);
                    break;
                }
                _ => {}
            }
            buf.clear();
        }

        Ok((event_id, timestamp, system_data, event_data))
    }

    fn build_logon_success_event(
        &self,
        timestamp: DateTime<Utc>,
        _system: &HashMap<String, String>,
        data: &HashMap<String, String>,
    ) -> Result<Event> {
        let mut event = self.create_base_event(timestamp);

        // Event details
        if let Some(event_obj) = event.event.as_mut() {
            event_obj.category = crate::percepta::event::EventCategory::Auth as i32;
            event_obj.action = "logon".to_string();
            event_obj.outcome = crate::percepta::event::EventOutcome::Success as i32;
            event_obj.summary = "Successful user logon".to_string();
            event_obj.event_id = 4624;
        }

        // User info
        event.user = Some(crate::percepta::event::User {
            id: data.get("TargetUserSid").cloned().unwrap_or_default(),
            name: data.get("TargetUserName").cloned().unwrap_or_default(),
            domain: data.get("TargetDomainName").cloned().unwrap_or_default(),
            privileges: vec![],
        });

        // Network info
        if let Some(ip) = data.get("IpAddress") {
            event.network = Some(crate::percepta::event::Network {
                src_ip: ip.clone(),
                src_port: data.get("IpPort").and_then(|p| p.parse().ok()).unwrap_or(0),
                ..Default::default()
            });
        }

        // Metadata
        event.metadata.insert(
            "LogonType".to_string(),
            data.get("LogonType").cloned().unwrap_or_default(),
        );
        event.metadata.insert(
            "WorkstationName".to_string(),
            data.get("WorkstationName").cloned().unwrap_or_default(),
        );

        Ok(event)
    }

    fn build_logon_failure_event(
        &self,
        timestamp: DateTime<Utc>,
        _system: &HashMap<String, String>,
        data: &HashMap<String, String>,
    ) -> Result<Event> {
        let mut event = self.create_base_event(timestamp);

        if let Some(event_obj) = event.event.as_mut() {
            event_obj.category = crate::percepta::event::EventCategory::Auth as i32;
            event_obj.action = "logon".to_string();
            event_obj.outcome = crate::percepta::event::EventOutcome::Failure as i32;
            event_obj.summary = "Failed user logon attempt".to_string();
            event_obj.event_id = 4625;
        }

        event.user = Some(crate::percepta::event::User {
            id: data.get("TargetUserSid").cloned().unwrap_or_default(),
            name: data.get("TargetUserName").cloned().unwrap_or_default(),
            domain: data.get("TargetDomainName").cloned().unwrap_or_default(),
            privileges: vec![],
        });

        if let Some(ip) = data.get("IpAddress") {
            event.network = Some(crate::percepta::event::Network {
                src_ip: ip.clone(),
                ..Default::default()
            });
        }

        event.metadata.insert(
            "FailureReason".to_string(),
            data.get("FailureReason").cloned().unwrap_or_default(),
        );
        event.metadata.insert(
            "Status".to_string(),
            data.get("Status").cloned().unwrap_or_default(),
        );

        Ok(event)
    }

    fn build_process_creation_event(
        &self,
        timestamp: DateTime<Utc>,
        _system: &HashMap<String, String>,
        data: &HashMap<String, String>,
    ) -> Result<Event> {
        let mut event = self.create_base_event(timestamp);

        if let Some(event_obj) = event.event.as_mut() {
            event_obj.category = crate::percepta::event::EventCategory::Process as i32;
            event_obj.action = "process_create".to_string();
            event_obj.outcome = crate::percepta::event::EventOutcome::Success as i32;
            event_obj.summary = "Process creation".to_string();
            event_obj.event_id = 4688;
        }

        event.process = Some(crate::percepta::event::Process {
            pid: data
                .get("NewProcessId")
                .and_then(|p| u32::from_str_radix(p.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0),
            ppid: data
                .get("ProcessId")
                .and_then(|p| u32::from_str_radix(p.trim_start_matches("0x"), 16).ok())
                .unwrap_or(0),
            name: data.get("NewProcessName").cloned().unwrap_or_default(),
            command_line: data.get("CommandLine").cloned().unwrap_or_default(),
            hash: HashMap::new(),
        });

        event.user = Some(crate::percepta::event::User {
            name: data.get("SubjectUserName").cloned().unwrap_or_default(),
            domain: data.get("SubjectDomainName").cloned().unwrap_or_default(),
            id: data.get("SubjectUserSid").cloned().unwrap_or_default(),
            privileges: vec![],
        });

        Ok(event)
    }

    fn build_privilege_assignment_event(
        &self,
        timestamp: DateTime<Utc>,
        _system: &HashMap<String, String>,
        data: &HashMap<String, String>,
    ) -> Result<Event> {
        let mut event = self.create_base_event(timestamp);

        if let Some(event_obj) = event.event.as_mut() {
            event_obj.category = crate::percepta::event::EventCategory::Auth as i32;
            event_obj.action = "privilege_assignment".to_string();
            event_obj.outcome = crate::percepta::event::EventOutcome::Success as i32;
            event_obj.summary = "Special privileges assigned to logon".to_string();
            event_obj.event_id = 4672;
        }

        let privileges: Vec<String> = data
            .get("PrivilegeList")
            .map(|p| p.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_default();

        event.user = Some(crate::percepta::event::User {
            name: data.get("SubjectUserName").cloned().unwrap_or_default(),
            domain: data.get("SubjectDomainName").cloned().unwrap_or_default(),
            id: data.get("SubjectUserSid").cloned().unwrap_or_default(),
            privileges,
        });

        Ok(event)
    }

    fn build_user_created_event(
        &self,
        timestamp: DateTime<Utc>,
        _system: &HashMap<String, String>,
        data: &HashMap<String, String>,
    ) -> Result<Event> {
        let mut event = self.create_base_event(timestamp);

        if let Some(event_obj) = event.event.as_mut() {
            event_obj.category = crate::percepta::event::EventCategory::Auth as i32;
            event_obj.action = "user_add".to_string();
            event_obj.outcome = crate::percepta::event::EventOutcome::Success as i32;
            event_obj.summary = "User account created".to_string();
            event_obj.event_id = 4720;
        }

        event.user = Some(crate::percepta::event::User {
            name: data.get("TargetUserName").cloned().unwrap_or_default(),
            domain: data.get("TargetDomainName").cloned().unwrap_or_default(),
            id: data.get("TargetSid").cloned().unwrap_or_default(),
            privileges: vec![],
        });

        event.metadata.insert(
            "creator".to_string(),
            data.get("SubjectUserName").cloned().unwrap_or_default(),
        );

        Ok(event)
    }

    fn build_generic_event(
        &self,
        event_id: u32,
        timestamp: DateTime<Utc>,
        channel: &str,
        system: &HashMap<String, String>,
    ) -> Result<Event> {
        let mut event = self.create_base_event(timestamp);

        if let Some(event_obj) = event.event.as_mut() {
            event_obj.category = crate::percepta::event::EventCategory::System as i32;
            event_obj.action = "windows_event".to_string();
            event_obj.outcome = crate::percepta::event::EventOutcome::Success as i32;
            event_obj.summary = format!("Windows {} Event {}", channel, event_id);
            event_obj.event_id = event_id as u64;
            event_obj.provider = system.get("Provider").cloned().unwrap_or_default();
        }

        Ok(event)
    }

    fn create_base_event(&self, timestamp: DateTime<Utc>) -> Event {
        let hostname = hostname::get()
            .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
            .to_string_lossy()
            .to_string();

        // Use the persisted agent_id provided at initialization instead of regenerating each time.
        let agent_id = self.agent_id.clone();

        let agent = crate::percepta::event::Agent {
            id: agent_id.clone(),
            hostname: hostname.clone(),
            ip: local_ip_address::local_ip()
                .ok()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            mac: crate::system_info::get_primary_mac().unwrap_or_else(|| "unknown".to_string()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            os: Some(crate::percepta::event::Os {
                name: "Windows".to_string(),
                version: sys_info::os_release().unwrap_or_default(),
                kernel: String::new(),
            }),
        };

        Event {
            event_time: Some(prost_types::Timestamp {
                seconds: timestamp.timestamp(),
                nanos: 0,
            }),
            ingest_time: Some(prost_types::Timestamp {
                seconds: Utc::now().timestamp(),
                nanos: 0,
            }),
            agent: Some(agent.clone()),
            event: Some(crate::percepta::event::EventDetails {
                summary: String::new(),
                original_message: String::new(),
                category: 0,
                action: String::new(),
                outcome: 0,
                level: String::new(),
                severity: 0,
                provider: String::new(),
                event_id: 0,
                record_id: 0,
            }),
            user: None,
            host: Some(crate::system_info::build_host(&agent)),
            network: None,
            process: None,
            file: None,
            registry: None,
            metadata: HashMap::new(),
            tags: vec![],
            threat_indicator: String::new(),
            threat_source: String::new(),
            correlation_id: String::new(),
            hash: uuid::Uuid::new_v4().to_string(),
        }
    }
}

// Non-Windows stub
#[cfg(not(windows))]
pub struct WindowsEventCollector;

#[cfg(not(windows))]
impl WindowsEventCollector {
    pub fn new(_bookmark_path: std::path::PathBuf) -> Self {
        Self
    }

    pub async fn collect_events(
        &self,
        _max_events: usize,
    ) -> anyhow::Result<Vec<crate::percepta::Event>> {
        anyhow::bail!("Windows Event Log collection is only available on Windows")
    }
}

pub mod percepta {
    tonic::include_proto!("percepta.siem.ingestion.v1");
}
