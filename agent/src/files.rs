//! File Buffer Management Module
//! Provides robust, asynchronous file-based buffering for event data using newline-delimited JSON (NDJSON).

use anyhow::bail;
use anyhow::{Context, Result};
use chrono::{Local, TimeZone, Timelike};
use serde_json;
use std::{
    env,
    path::{Path, PathBuf},
};
use tokio::{fs, sync::Mutex};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::percepta::Event;

/// FilesHandler provides a structured interface to file operations
pub struct FilesHandler {
    outgoing_dir: PathBuf,
    // Use a Tokio Mutex for async-aware locking
    file_lock: Arc<Mutex<()>>,
}

impl FilesHandler {
    pub fn new(outgoing_dir: PathBuf) -> Result<Self> {
        Ok(Self {
            outgoing_dir,
            file_lock: Arc::new(Mutex::new(())),
        })
    }

    #[allow(dead_code)]
    pub async fn write_short_buffer(&self, events: &[Event]) -> Result<()> {
        write_short(&self.outgoing_dir, &self.file_lock, events).await
    }

    #[allow(dead_code)]
    pub async fn flush_short(&self) -> Result<Option<Vec<Event>>> {
        flush_short(&self.outgoing_dir, &self.file_lock).await
    }

    pub async fn write_archive(&self, events: &[Event]) -> Result<()> {
        write_archive(&self.outgoing_dir, &self.file_lock, events).await
    }

    pub async fn flush_archive(&self) -> Result<()> {
        rotate_current_archive(&self.outgoing_dir, &self.file_lock).await
    }
}

// ... (rest of the file remains the same, but with async file operations)

use std::sync::Arc;

/// Default configuration constants
const DEFAULT_SHORT_WINDOW_SECONDS: u64 = 10;
const DEFAULT_ARCHIVE_ROTATE_HOURS: u64 = 12;
const DEFAULT_MAX_FILE_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100MB

/// Global configuration loaded from environment variables
#[derive(Debug, Clone)]
struct Config {
    #[allow(dead_code)] // This config is unused after moving to the archive-only buffering model
    short_window_seconds: u64,
    archive_rotate_hours: u64,
    max_file_size_bytes: u64,
}

impl Config {
    fn load() -> Self {
        let short_window = env::var("PERCEPTA_SHORT_WINDOW")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_SHORT_WINDOW_SECONDS);

        let archive_rotate = env::var("PERCEPTA_ARCHIVE_ROTATE_HOURS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_ARCHIVE_ROTATE_HOURS);

        let max_file_size = env::var("PERCEPTA_MAX_FILE_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MAX_FILE_SIZE_BYTES);

        Self {
            short_window_seconds: short_window,
            archive_rotate_hours: archive_rotate,
            max_file_size_bytes: max_file_size,
        }
    }
}

/// Initialize the file system structure
pub async fn init(out_dir: &Path) -> Result<()> {
    // Create main output directory
    if !out_dir.exists() {
        fs::create_dir_all(out_dir)
            .await
            .with_context(|| format!("Failed to create output directory: {}", out_dir.display()))?;
        info!("Created output directory: {}", out_dir.display());
    }

    // Create archives subdirectory
    let archives_dir = out_dir.join("archives");
    if !archives_dir.exists() {
        fs::create_dir_all(&archives_dir).await.with_context(|| {
            format!(
                "Failed to create archives directory: {}",
                archives_dir.display()
            )
        })?;
        debug!("Created archives directory: {}", archives_dir.display());
    }

    // Set appropriate permissions on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [out_dir, &archives_dir] {
            let metadata = fs::metadata(dir).await?;
            let mut perms = metadata.permissions();
            perms.set_mode(0o700); // Owner read/write/execute only
            fs::set_permissions(dir, perms).await?;
        }
    }

    info!("File system initialized in: {}", out_dir.display());
    Ok(())
}

/// Write events to the current short buffer file
#[allow(dead_code)]
pub async fn write_short(out_dir: &Path, lock: &Mutex<()>, events: &[Event]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    let filename = current_short_filename();
    let file_path = out_dir.join(&filename);
    let temp_path = out_dir.join(format!("{}.tmp", filename));

    let events_json = serialize_events_to_ndjson(events)?;
    let events_count = events.len();

    let _guard = lock.lock().await;

    fs::write(&temp_path, events_json).await.with_context(|| {
        format!(
            "Failed to write events to temp file: {}",
            temp_path.display()
        )
    })?;
    fs::rename(&temp_path, &file_path).await.with_context(|| {
        format!(
            "Failed to rename {} to {}",
            temp_path.display(),
            file_path.display()
        )
    })?;

    debug!("Wrote {} events to short file: {}", events_count, filename);
    Ok(())
}

/// Atomically read and remove the current short buffer file
#[allow(dead_code)]
pub async fn flush_short(out_dir: &Path, lock: &Mutex<()>) -> Result<Option<Vec<Event>>> {
    let filename = current_short_filename();
    let file_path = out_dir.join(&filename);

    if !file_path.exists() {
        return Ok(None);
    }

    let _guard = lock.lock().await;

    // Re-check existence after acquiring lock
    if !file_path.exists() {
        return Ok(None);
    }

    let events = read_ndjson_events(&file_path).await?;

    fs::remove_file(&file_path)
        .await
        .with_context(|| format!("Failed to remove short file: {}", file_path.display()))?;

    debug!(
        "Flushed {} events from short file: {}",
        events.len(),
        filename
    );
    Ok(Some(events))
}

/// Append events to the current archive file
pub async fn write_archive(out_dir: &Path, lock: &Mutex<()>, events: &[Event]) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    let filename = current_archive_filename();
    let file_path = out_dir.join(&filename);

    let config = Config::load();
    if file_path.exists() {
        let metadata = fs::metadata(&file_path).await?;
        if metadata.len() > config.max_file_size_bytes {
            rotate_archive(out_dir, &filename, lock).await?;
        }
    }

    let events_json = serialize_events_to_ndjson(events)?;
    let events_count = events.len();

    let _guard = lock.lock().await;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file_path)
        .await
        .with_context(|| format!("Failed to open archive file: {}", file_path.display()))?;

    use tokio::io::AsyncWriteExt;
    file.write_all(events_json.as_bytes())
        .await
        .context("Failed to append events to archive file")?;
    file.flush().await.context("Failed to flush archive file")?;

    debug!(
        "Appended {} events to archive file: {}",
        events_count, filename
    );
    Ok(())
}

/// Rotates the current archive file into the archives directory so it can be shipped.
pub async fn rotate_current_archive(out_dir: &Path, lock: &Mutex<()>) -> Result<()> {
    let filename = current_archive_filename();
    let file_path = out_dir.join(&filename);

    if !file_path.exists() {
        return Ok(());
    }

    let _guard = lock.lock().await;

    if !file_path.exists() {
        return Ok(());
    }

    // Don't bother rotating an empty file.
    if fs::metadata(&file_path).await?.len() == 0 {
        return Ok(());
    }

    let archives_dir = out_dir.join("archives");
    // Use the same "rotated_" prefix so the shipper task can find it.
    let rotated_filename = format!("rotated_on_flush_{}_{}", Uuid::new_v4(), filename);
    let rotated_path = archives_dir.join(&rotated_filename);

    fs::rename(&file_path, &rotated_path)
        .await
        .with_context(|| {
            format!(
                "Failed to rotate archive file to: {}",
                rotated_path.display()
            )
        })?;

    info!(
        "Rotated current archive file for shipping: {} -> {}",
        filename, rotated_filename
    );
    Ok(())
}

/// Get the current short buffer filename based on timestamp
#[allow(dead_code)]
pub fn current_short_filename() -> String {
    let now = Local::now();
    now.format("%Y%m%d_%H%M%S_short.json").to_string()
}

/// Get the current archive filename based on 12-hour window
pub fn current_archive_filename() -> String {
    let now = Local::now();
    let config = Config::load();

    let window_start_hour =
        (now.hour() / config.archive_rotate_hours as u32) * config.archive_rotate_hours as u32;

    // Build a naive datetime at the start of the rotation window. Avoid panics on DST edges
    // by falling back to the current local time if the conversion is ambiguous or invalid.
    let naive = now
        .date_naive()
        .and_hms_opt(window_start_hour, 0, 0)
        .unwrap_or_else(|| now.naive_local());

    let local_dt = Local.from_local_datetime(&naive).earliest().unwrap_or(now);

    local_dt.format("%Y%m%d_%H%M%S_archive.json").to_string()
}

/// Serialize events to NDJSON format
fn serialize_events_to_ndjson(events: &[Event]) -> Result<String> {
    events
        .iter()
        .map(|event| serde_json::to_string(event).context("Failed to serialize event to JSON"))
        .collect::<Result<Vec<_>>>()
        .map(|lines| lines.join("\n") + "\n")
}

/// Read events from an NDJSON file, logging parse errors
#[allow(dead_code)]
async fn read_ndjson_events(file_path: &Path) -> Result<Vec<Event>> {
    let content = fs::read_to_string(file_path).await?;
    let mut events = Vec::new();
    let mut parse_errors = Vec::new();

    for (line_number, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(line) {
            Ok(event) => events.push(event),
            Err(e) => {
                let error_msg = format!("Line {}: {}", line_number + 1, e);
                parse_errors.push(error_msg.clone());
                warn!(
                    "Failed to parse event from {}: {}",
                    file_path.display(),
                    error_msg
                );
            }
        }
    }

    if !parse_errors.is_empty() {
        if let Ok(out_dir) = get_output_directory() {
            log_parse_errors(&out_dir, file_path, &parse_errors).await?;
        }
    }

    debug!(
        "Read {} events from {} ({} parse errors)",
        events.len(),
        file_path.display(),
        parse_errors.len()
    );
    Ok(events)
}

/// Log parse errors to errors.log file
#[allow(dead_code)]
async fn log_parse_errors(out_dir: &Path, source_file: &Path, errors: &[String]) -> Result<()> {
    let error_log_path = out_dir.join("errors.log");
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let mut error_entries = String::new();
    error_entries.push_str(&format!(
        "[{}] Parse errors in {}:\n",
        timestamp,
        source_file.display()
    ));

    for error in errors {
        error_entries.push_str(&format!("  {}\\n", error));
    }
    error_entries.push('\n');

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&error_log_path)
        .await?;

    use tokio::io::AsyncWriteExt;
    file.write_all(error_entries.as_bytes()).await?;
    file.flush().await?;

    Ok(())
}

/// Rotate archive file when size limit is reached
async fn rotate_archive(out_dir: &Path, current_filename: &str, lock: &Mutex<()>) -> Result<()> {
    let _guard = lock.lock().await;
    let current_path = out_dir.join(current_filename);
    if !current_path.exists() {
        return Ok(());
    }

    let archives_dir = out_dir.join("archives");
    let rotated_filename = format!("rotated_{}_{}", Uuid::new_v4(), current_filename);
    let rotated_path = archives_dir.join(rotated_filename);

    fs::rename(&current_path, &rotated_path)
        .await
        .with_context(|| {
            format!(
                "Failed to rotate archive file to: {}",
                rotated_path.display()
            )
        })?;

    info!(
        "Rotated archive file due to size limit: {} -> {}",
        current_filename,
        rotated_path.display()
    );
    Ok(())
}

/// Get the output directory from environment or use default
#[allow(dead_code)]
fn get_output_directory() -> Result<PathBuf> {
    let default_dir = if cfg!(windows) {
        r"C:\ProgramData\percepta_agent\outgoing"
    } else {
        "./outgoing"
    };

    let out_dir = env::var("PERCEPTA_OUT").unwrap_or_else(|_| default_dir.to_string());
    Ok(PathBuf::from(out_dir))
}

/// Read server configuration from config file
#[allow(dead_code)] // currently used only by future dynamic server config reload feature
pub async fn read_server_config(cert_dir: &Path) -> Result<String> {
    let config_path_primary = cert_dir.join("server-config.txt");
    let config_path_legacy = cert_dir.join("server_config.txt");

    let config_path = if config_path_primary.exists() {
        config_path_primary
    } else if config_path_legacy.exists() {
        config_path_legacy
    } else {
        anyhow::bail!(
            "Server config not found at: {} (or legacy {})",
            config_path_primary.display(),
            config_path_legacy.display()
        );
    };

    let content = fs::read_to_string(&config_path).await.with_context(|| {
        format!("Failed to read server config from: {}", config_path.display())
    })?;

    // Parse server address from config.
    // Preferred keys:
    // - grpc_server=<host:50051>
    // - server=<host:port> (legacy)
    // Also tolerate:
    // - enroll_url/server_url (portal HTTP URL)
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("server=") {
            return Ok(line.trim_start_matches("server=").to_string());
        } else if line.starts_with("grpc_server=") {
            return Ok(line.trim_start_matches("grpc_server=").to_string());
        } else if line.starts_with("enroll_url=") {
            return Ok(derive_grpc_address(line.trim_start_matches("enroll_url=")));
        } else if line.starts_with("server_url=") {
            return Ok(derive_grpc_address(line.trim_start_matches("server_url=")));
        } else if !line.is_empty() && !line.starts_with('#') {
            // Assume first non-comment line is the server address
            return Ok(line.to_string());
        }
    }

    anyhow::bail!(
        "No server address found in config file: {}",
        config_path.display()
    );
}

/// Persist the server configuration for GUI/service restarts
#[cfg(feature = "gui")]
#[allow(dead_code)]
pub async fn write_server_config(cert_dir: &Path, server_addr: &str) -> Result<()> {
    let config_path = cert_dir.join("server-config.txt");
    let legacy_path = cert_dir.join("server_config.txt");

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
    }

    let trimmed = server_addr.trim();
    if trimmed.is_empty() {
        bail!("Server address is empty; cannot persist configuration");
    }

    let grpc_line = derive_grpc_address(trimmed);
    let mut content = format!("server={}\n", trimmed);
    content.push_str(&format!("grpc_server={}\n", grpc_line));

    fs::write(&config_path, &content).await.with_context(|| {
        format!(
            "Failed to write server config to: {}",
            config_path.display()
        )
    })?;

    // Backward-compat: keep the legacy underscore filename in sync.
    // Ignore errors here (best-effort), because some environments may not want the extra file.
    let _ = fs::write(&legacy_path, content).await;

    Ok(())
}

#[allow(dead_code)]
fn derive_grpc_address(input: &str) -> String {
    let mut base = input.trim();
    if base.is_empty() {
        return String::new();
    }

    if let Some(rest) = base
        .strip_prefix("http://")
        .or_else(|| base.strip_prefix("https://"))
    {
        base = rest;
    }

    if let Some((hostport, _path)) = base.split_once('/') {
        base = hostport;
    }

    let mut parts = base.split(':');
    let host = parts.next().unwrap_or(base);
    match parts.next() {
        Some(port) if !port.is_empty() => {
            if port == "50051" {
                format!("{}:{}", host, port)
            } else {
                format!("{}:50051", host)
            }
        }
        _ => format!("{}:50051", host),
    }
}

/// Check whether the agent already has the required enrollment artifacts on disk
#[cfg(feature = "gui")]
#[allow(dead_code)]
pub fn enrollment_artifacts_present(cert_dir: &Path) -> bool {
    [
        "agent_cert.pem",
        "agent_key.pem",
        "ca_cert.pem",
        "ca_fingerprint.txt",
    ]
    .iter()
    .all(|file| cert_dir.join(file).exists())
}

/// Get agent ID from certificate directory
#[allow(dead_code)] // not used; Config::load handles agent id generation
pub async fn get_agent_id(cert_dir: &Path) -> Result<String> {
    let agent_id_path = cert_dir.join("agent_id.txt");

    // Prefer the permanent identity (MAC + first user) if available/creatable.
    // This makes the agent_id stable across reconnects and across GUI/service launches.
    match crate::identity::load_or_create(cert_dir).await {
        Ok(ident) => {
            let stable_id = ident.agent_id.trim().to_string();
            if stable_id.is_empty() {
                bail!("identity.json produced empty agent_id");
            }

            // Keep legacy agent_id.txt present and in sync for backward compatibility.
            // (Some older paths and tools still read agent_id.txt directly.)
            if let Some(parent) = agent_id_path.parent() {
                fs::create_dir_all(parent)
                    .await
                    .with_context(|| format!("Failed to create cert directory: {}", parent.display()))?;
            }

            let needs_write = match fs::read_to_string(&agent_id_path).await {
                Ok(existing) => existing.trim() != stable_id,
                Err(_) => true,
            };

            if needs_write {
                fs::write(&agent_id_path, &stable_id)
                    .await
                    .with_context(|| {
                        format!("Failed to write agent ID to: {}", agent_id_path.display())
                    })?;
            }

            return Ok(stable_id);
        }
        Err(e) => {
            // If identity creation fails, fall back to legacy behavior to avoid breaking
            // GUI/service startup. We still prefer an existing legacy agent_id.txt.
            warn!("Permanent identity unavailable ({}); falling back", e);

            if agent_id_path.exists() {
                let id = fs::read_to_string(&agent_id_path).await.with_context(|| {
                    format!("Failed to read agent ID from: {}", agent_id_path.display())
                })?;
                let id = id.trim().to_string();
                if !id.is_empty() {
                    return Ok(id);
                }
            }

            // Last resort: random UUID (not preferred).
            let new_id = Uuid::new_v4().to_string();

            if let Some(parent) = agent_id_path.parent() {
                fs::create_dir_all(parent)
                    .await
                    .with_context(|| {
                        format!("Failed to create cert directory: {}", parent.display())
                    })?;
            }

            fs::write(&agent_id_path, &new_id)
                .await
                .with_context(|| format!("Failed to write agent ID to: {}", agent_id_path.display()))?;

            info!("Generated fallback agent ID: {}", new_id);
            Ok(new_id)
        }
    }
}
