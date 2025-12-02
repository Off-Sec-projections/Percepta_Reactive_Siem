//! Complete Windows SIEM Agent with GUI
//! Single executable that includes:
//! - Real Windows Event Log collection  
//! - System tray icon
//! - Windows service mode with auto-restart
//! - Enrollment UI
//! - Log parsing and streaming to server
//! - Self-installing (no external files needed)

use percepta_agent::{client, embedded_assets, files, system_info, tls, windows_service};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Local};
use hex;
use openssl::{hash::MessageDigest, x509::{X509, X509NameRef}};
use reqwest::Client;
use serde::Deserialize;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::fs;
use tokio::task;
use zip::ZipArchive;
#[cfg(feature = "gui")]
use rfd::FileDialog;
// use tokio::fs as async_fs; // Removed unused import to silence warning

/// Application state shared between GUI and background tasks
#[derive(Clone)]
struct AgentState {
    status: Arc<Mutex<String>>,
    server_addr: Arc<Mutex<String>>,
    enrolled: Arc<Mutex<bool>>,
    stats: Arc<Mutex<AgentStats>>,
    logs: Arc<Mutex<VecDeque<String>>>,
    reset_prompt: Arc<Mutex<Option<ResetPrompt>>>,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            status: Arc::new(Mutex::new("Initializing...".to_string())),
            server_addr: Arc::new(Mutex::new(String::new())),
            enrolled: Arc::new(Mutex::new(false)),
            stats: Arc::new(Mutex::new(AgentStats::default())),
            logs: Arc::new(Mutex::new(VecDeque::new())),
            reset_prompt: Arc::new(Mutex::new(None)),
        }
    }
}

impl AgentState {
    fn set_status(&self, message: impl Into<String>) {
        if let Some(mut status) = self.status.lock().ok() {
            *status = message.into();
        }
    }

    fn update_stats<F>(&self, f: F)
    where
        F: FnOnce(&mut AgentStats),
    {
        if let Some(mut stats) = self.stats.lock().ok() {
            f(&mut stats);
        }
    }

    fn append_log(&self, message: impl Into<String>) {
        const MAX_LOG_LINES: usize = 2000;
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        if let Some(mut logs) = self.logs.lock().ok() {
            if logs.len() >= MAX_LOG_LINES {
                logs.pop_front();
            }
            logs.push_back(format!("[{timestamp}] {}", message.into()));
        }
    }

    fn latest_logs(&self) -> Vec<String> {
        self.logs
            .lock()
            .map(|buf| buf.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn show_reset_prompt(&self, reason: ResetPromptReason) {
        if let Ok(mut prompt) = self.reset_prompt.lock() {
            *prompt = Some(ResetPrompt { reason });
        }
    }

    fn take_reset_prompt(&self) -> Option<ResetPrompt> {
        self.reset_prompt
            .lock()
            .ok()
            .and_then(|mut guard| guard.take())
    }
}

#[derive(Clone, Debug)]
enum ResetPromptReason {
    BundleImported,
    UserRequested,
}

#[derive(Clone, Debug)]
struct ResetPrompt {
    reason: ResetPromptReason,
}

#[derive(Clone, Debug)]
struct BundleFeedback {
    message: String,
    success: bool,
    enroll_url: Option<String>,
    grpc_addr: Option<String>,
}

#[derive(Clone, Debug)]
struct DiagnosticsFeedback {
    message: String,
    success: bool,
}

#[derive(Debug, Default)]
struct PortalBundleImport {
    enroll_url: Option<String>,
    grpc_addr: Option<String>,
    otk_copied: bool,
    ca_copied: bool,
}

#[derive(Default)]
struct BundleFiles {
    otk: Option<String>,
    ca_cert: Option<Vec<u8>>,
    server_config: Option<String>,
}

#[derive(Clone, Default)]
struct AgentCertMetadata {
    subject: String,
    issuer: String,
    valid_from: String,
    valid_until: String,
    serial: String,
}

#[derive(Clone, Default)]
struct AgentStats {
    events_sent: u64,
    last_batch: Option<usize>,
    last_connected: Option<DateTime<Local>>,
    ca_installed: bool,
    otk_available: bool,
    agent_cert: Option<AgentCertMetadata>,
}

const CERT_DIR_PATH: &str = r"C:\ProgramData\percepta_agent\certs";

fn cert_directory() -> PathBuf {
    PathBuf::from(CERT_DIR_PATH)
}

#[derive(Default, Clone)]
struct EmbeddedStatus {
    ca_present: bool,
    ca_fingerprint: Option<String>,
    otk_present: bool,
}

async fn provision_embedded_assets(cert_dir: &Path) -> Result<EmbeddedStatus> {
    fs::create_dir_all(cert_dir)
        .await
        .with_context(|| format!("Failed to create cert directory: {}", cert_dir.display()))?;

    let mut status = EmbeddedStatus::default();

    let ca_path = cert_dir.join("ca_cert.pem");
    if ca_path.exists() {
        status.ca_present = true;
    }

    if let Some(ca_pem) = embedded_assets::embedded_ca_cert() {
        if !ca_path.exists() {
            fs::write(&ca_path, ca_pem.as_bytes())
                .await
                .with_context(|| {
                    format!("Failed to write embedded CA cert to {}", ca_path.display())
                })?;
            status.ca_present = true;
        }

        let ca = X509::from_pem(ca_pem.as_bytes())?;
        let fingerprint = hex::encode(ca.digest(MessageDigest::sha256())?);
        let fp_path = cert_dir.join("ca_fingerprint.txt");
        fs::write(&fp_path, &fingerprint)
            .await
            .with_context(|| format!("Failed to write CA fingerprint to {}", fp_path.display()))?;
        status.ca_fingerprint = Some(fingerprint);
    }

    let otk_path = cert_dir.join("embedded_otk.txt");
    if otk_path.exists() {
        status.otk_present = true;
    }

    if let Some(otk) = embedded_assets::embedded_otk() {
        if !otk_path.exists() {
            fs::write(&otk_path, otk.as_bytes())
                .await
                .with_context(|| {
                    format!("Failed to write embedded OTK to {}", otk_path.display())
                })?;
        }
        status.otk_present = true;
    }

    Ok(status)
}

async fn hydrate_state_from_disk(state: &AgentState) {
    let cert_dir = cert_directory();
    if !files::enrollment_artifacts_present(&cert_dir) {
        return;
    }

    match files::read_server_config(&cert_dir).await {
        Ok(server_addr) => {
            if let Some(mut enrolled) = state.enrolled.lock().ok() {
                *enrolled = true;
            }
            if let Some(mut addr) = state.server_addr.lock().ok() {
                *addr = server_addr.clone();
            }
            if let Some(mut status) = state.status.lock().ok() {
                *status = "✅ Existing enrollment detected. Connecting...".to_string();
            }
        }
        Err(e) => {
            if let Some(mut status) = state.status.lock().ok() {
                *status = format!("⚠️ Certificates found but server config missing: {}", e);
            }
        }
    }
}

async fn bootstrap_state(state: &AgentState) -> Result<EmbeddedStatus> {
    let cert_dir = cert_directory();
    let embedded = provision_embedded_assets(&cert_dir).await?;
    if let Ok(bundle_auto) = auto_seed_from_bundle_folder(&cert_dir).await {
        if bundle_auto.otk_copied || bundle_auto.ca_copied {
            state.append_log("Auto-imported portal bundle artifacts from executable folder");
        }
        if let Some(url) = bundle_auto.enroll_url {
            if let Ok(mut addr) = state.server_addr.lock() {
                *addr = url;
            }
        }
    }
    state.update_stats(|stats| {
        stats.ca_installed = embedded.ca_present;
        stats.otk_available = embedded.otk_present;
    });
    hydrate_state_from_disk(state).await;
    if let Err(e) = refresh_agent_certificate_stats(state).await {
        state.append_log(format!("Unable to load existing agent certificate metadata: {}", e));
    }
    Ok(embedded)
}

async fn auto_seed_from_bundle_folder(cert_dir: &Path) -> Result<PortalBundleImport> {
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .ok_or_else(|| anyhow::anyhow!("Could not determine executable directory"))?;
    if exe_dir == cert_dir {
        return Ok(PortalBundleImport::default());
    }
    import_portal_directory(&exe_dir, cert_dir).await
}

async fn import_portal_bundle(path: &Path, cert_dir: &Path) -> Result<PortalBundleImport> {
    if path.is_dir() {
        import_portal_directory(path, cert_dir).await
    } else {
        import_portal_zip(path, cert_dir).await
    }
}

async fn import_portal_directory(dir: &Path, cert_dir: &Path) -> Result<PortalBundleImport> {
    let mut result = PortalBundleImport::default();

    let otk_path = dir.join("otk.txt");
    if otk_path.exists() {
        let content = tokio::fs::read_to_string(&otk_path)
            .await
            .context("Failed to read otk.txt from bundle directory")?;
        if !content.trim().is_empty() {
            write_otk_file(cert_dir, content.trim()).await?;
            result.otk_copied = true;
        }
    }

    let ca_path = dir.join("ca_cert.pem");
    if ca_path.exists() {
        let bytes = tokio::fs::read(&ca_path)
            .await
            .context("Failed to read ca_cert.pem from bundle directory")?;
        write_ca_files(cert_dir, &bytes).await?;
        result.ca_copied = true;
    }

    let server_cfg_path = dir.join("server-config.txt");
    if server_cfg_path.exists() {
        let cfg_text = tokio::fs::read_to_string(&server_cfg_path)
            .await
            .context("Failed to read server-config.txt")?;
        let (enroll, grpc) = parse_server_config_text(&cfg_text);
        result.enroll_url = enroll;
        result.grpc_addr = grpc;
    }

    Ok(result)
}

async fn import_portal_zip(zip_path: &Path, cert_dir: &Path) -> Result<PortalBundleImport> {
    let zip_path_buf = zip_path.to_path_buf();
    let bundle = task::spawn_blocking(move || -> Result<BundleFiles> {
        let file = File::open(&zip_path_buf)
            .with_context(|| format!("Failed to open zip bundle at {}", zip_path_buf.display()))?;
        let mut archive = ZipArchive::new(file)?;
        let mut bundle = BundleFiles::default();
        if let Ok(mut file) = archive.by_name("otk.txt") {
            let mut buf = String::new();
            file.read_to_string(&mut buf)?;
            bundle.otk = Some(buf);
        }
        if let Ok(mut file) = archive.by_name("ca_cert.pem") {
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            bundle.ca_cert = Some(buf);
        }
        if let Ok(mut file) = archive.by_name("server-config.txt") {
            let mut buf = String::new();
            file.read_to_string(&mut buf)?;
            bundle.server_config = Some(buf);
        }
        Ok(bundle)
    })
    .await??;

    let mut result = PortalBundleImport::default();
    if let Some(otk) = bundle.otk {
        if !otk.trim().is_empty() {
            write_otk_file(cert_dir, otk.trim()).await?;
            result.otk_copied = true;
        }
    }
    if let Some(ca_bytes) = bundle.ca_cert {
        write_ca_files(cert_dir, &ca_bytes).await?;
        result.ca_copied = true;
    }
    if let Some(cfg) = bundle.server_config {
        let (enroll, grpc) = parse_server_config_text(&cfg);
        result.enroll_url = enroll;
        result.grpc_addr = grpc;
    }
    Ok(result)
}

async fn write_otk_file(cert_dir: &Path, content: &str) -> Result<()> {
    let otk_dest = cert_dir.join("otk.txt");
    tokio::fs::write(&otk_dest, content.as_bytes())
        .await
        .with_context(|| format!("Failed to write {}", otk_dest.display()))?;
    Ok(())
}

async fn write_ca_files(cert_dir: &Path, ca_bytes: &[u8]) -> Result<()> {
    let ca_dest = cert_dir.join("ca_cert.pem");
    tokio::fs::write(&ca_dest, ca_bytes)
        .await
        .with_context(|| format!("Failed to write {}", ca_dest.display()))?;

    let ca = X509::from_pem(ca_bytes)?;
    let fingerprint = hex::encode(ca.digest(MessageDigest::sha256())?);
    let fp_path = cert_dir.join("ca_fingerprint.txt");
    tokio::fs::write(&fp_path, fingerprint.as_bytes())
        .await
        .with_context(|| format!("Failed to write {}", fp_path.display()))?;
    Ok(())
}

fn parse_server_config_text(text: &str) -> (Option<String>, Option<String>) {
    let mut enroll = None;
    let mut grpc = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("enroll_url=") {
            enroll = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("grpc_server=") {
            grpc = Some(value.trim().to_string());
        }
    }
    (enroll, grpc)
}

async fn refresh_agent_certificate_stats(state: &AgentState) -> Result<()> {
    let cert_dir = cert_directory();
    let metadata = extract_agent_cert_metadata(&cert_dir).await?;
    state.update_stats(|stats| {
        stats.agent_cert = metadata;
    });
    Ok(())
}

async fn extract_agent_cert_metadata(cert_dir: &Path) -> Result<Option<AgentCertMetadata>> {
    let cert_path = cert_dir.join("agent_cert.pem");
    if !cert_path.exists() {
        return Ok(None);
    }

    let meta = task::spawn_blocking(move || -> Result<AgentCertMetadata> {
        let bytes = std::fs::read(&cert_path)
            .with_context(|| format!("Failed to read {}", cert_path.display()))?;
        let cert = X509::from_pem(&bytes)?;

        let subject = describe_x509_name(cert.subject_name());
        let issuer = describe_x509_name(cert.issuer_name());
        let valid_from = cert.not_before().to_string();
        let valid_until = cert.not_after().to_string();
        let serial = cert
            .serial_number()
            .to_bn()
            .and_then(|bn| Ok(bn.to_hex_str()?.to_string()))?;

        Ok(AgentCertMetadata {
            subject,
            issuer,
            valid_from,
            valid_until,
            serial,
        })
    })
    .await??;

    Ok(Some(meta))
}

fn describe_x509_name(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let field = entry.object().nid().short_name().unwrap_or("?");
        let value = entry
            .data()
            .as_utf8()
            .map(|cow| cow.to_string())
            .unwrap_or_else(|_| hex::encode(entry.data().as_slice()));
        parts.push(format!("{}={}", field, value));
    }
    parts.join(", ")
}

async fn export_diagnostics_snapshot(state: AgentState) -> Result<PathBuf> {
    let cert_dir = cert_directory();
    fs::create_dir_all(&cert_dir)
        .await
        .with_context(|| format!("Failed to ensure {} exists", cert_dir.display()))?;

    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let file_path = cert_dir.join(format!("diagnostics_{}.txt", timestamp));

    let status = state.status.lock().unwrap().clone();
    let enrolled = *state.enrolled.lock().unwrap();
    let server_addr = state.server_addr.lock().unwrap().clone();
    let stats = state.stats.lock().unwrap().clone();
    let logs = state.latest_logs();

    let mut report = String::new();
    let _ = writeln!(report, "Percepta Agent Diagnostics Snapshot");
    let _ = writeln!(report, "Generated at: {}", Local::now().format("%Y-%m-%d %H:%M:%S"));
    let _ = writeln!(report, "Status: {}", status);
    let _ = writeln!(report, "Enrolled: {}", enrolled);
    let _ = writeln!(report, "Server (GUI state): {}", server_addr);
    let _ = writeln!(report, "CA installed: {}", stats.ca_installed);
    let _ = writeln!(report, "Embedded OTK available: {}", stats.otk_available);
    let _ = writeln!(report, "Events sent: {}", stats.events_sent);
    let _ = writeln!(report, "Last batch size: {:?}", stats.last_batch);
    let _ = writeln!(report, "Last connected: {:?}", stats.last_connected);

    if let Some(cert) = stats.agent_cert {
        let _ = writeln!(report, "Agent cert subject: {}", cert.subject);
        let _ = writeln!(report, "Agent cert issuer: {}", cert.issuer);
        let _ = writeln!(report, "Valid from: {}", cert.valid_from);
        let _ = writeln!(report, "Valid until: {}", cert.valid_until);
        let _ = writeln!(report, "Serial: {}", cert.serial);
    } else {
        let _ = writeln!(report, "Agent certificate: not present");
    }

    let _ = writeln!(report, "");
    let _ = writeln!(report, "Recent Logs ({} entries):", logs.len());
    for line in logs {
        let _ = writeln!(report, "{}", line);
    }

    fs::write(&file_path, report)
        .await
        .with_context(|| format!("Failed to write diagnostics to {}", file_path.display()))?;

    Ok(file_path)
}

const RESETTABLE_FILES: [&str; 7] = [
    "agent_cert.pem",
    "agent_key.pem",
    "server-config.txt",
    "ca_cert.pem",
    "ca_fingerprint.txt",
    "otk.txt",
    "pending_enrollment.req",
];

async fn purge_enrollment_files(cert_dir: &Path) -> Result<usize> {
    let mut removed = 0;
    for file in RESETTABLE_FILES.iter() {
        let path = cert_dir.join(file);
        if path.exists() {
            fs::remove_file(&path)
                .await
                .with_context(|| format!("Failed to remove {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

async fn reset_enrollment_artifacts(state: AgentState) -> Result<()> {
    let cert_dir = cert_directory();
    state.append_log("Reset requested: removing enrollment artifacts");
    state.set_status("🧹 Removing certificates and config...");

    let removed = purge_enrollment_files(&cert_dir).await?;
    state.append_log(format!("Removed {} enrollment files", removed));

    if let Some(mut enrolled) = state.enrolled.lock().ok() {
        *enrolled = false;
    }
    if let Some(mut addr) = state.server_addr.lock().ok() {
        addr.clear();
    }

    let embedded = provision_embedded_assets(&cert_dir).await?;
    state.update_stats(|stats| {
        stats.ca_installed = embedded.ca_present;
        stats.otk_available = embedded.otk_present;
        stats.events_sent = 0;
        stats.last_batch = None;
        stats.last_connected = None;
        stats.agent_cert = None;
    });

    state.set_status("✅ Certificates removed. Ready for portal bundle import.");
    Ok(())
}

fn normalize_enrollment_base(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        let host = trimmed.split(':').next().unwrap_or(trimmed);
        format!("http://{}:8080", host)
    }
}

fn normalize_connection_addr(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut base = trimmed;
    if let Some(rest) = trimmed
        .strip_prefix("http://")
        .or_else(|| trimmed.strip_prefix("https://"))
    {
        base = rest;
    }

    if let Some((hostport, _path)) = base.split_once('/') {
        base = hostport;
    }

    let mut parts = base.split(':');
    let host = parts.next().unwrap_or(base);
    match parts.next() {
        Some(port) if port == "50051" => format!("{}:50051", host),
        Some(port) if port.is_empty() => format!("{}:50051", host),
        Some(port) if port == "8080" => format!("{}:50051", host),
        Some(port) => format!("{}:{}", host, port),
        None => format!("{}:50051", host),
    }
}

#[derive(Deserialize)]
struct ServerOtkResponse {
    otk: String,
    #[allow(dead_code)]
    expires_at: Option<String>,
}

async fn resolve_otk(enroll_url: &str) -> Result<String> {
    if let Some(otk) = embedded_assets::embedded_otk() {
        let trimmed = otk.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }

    request_otk_from_server(enroll_url).await
}

async fn request_otk_from_server(enroll_url: &str) -> Result<String> {
    let client = Client::new();
    let url = format!("{}/api/enroll/request", enroll_url.trim_end_matches('/'));
    let response = client
        .post(&url)
        .json(&serde_json::json!({ "admin_id": "windows-gui" }))
        .send()
        .await
        .with_context(|| format!("Failed to request OTK from {}", url))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "<no body>".to_string());
        bail!("OTK request failed (status {}): {}", status, body);
    }

    let payload: ServerOtkResponse = response
        .json()
        .await
        .context("Failed to parse OTK response from server")?;

    if payload.otk.trim().is_empty() {
        bail!("Server returned empty OTK");
    }

    Ok(payload.otk)
}

#[cfg(feature = "gui")]
mod gui_app {
    use super::*;
    use eframe::egui::{self, Align2, Color32, RichText};

    pub struct PerceptaAgentApp {
        state: AgentState,
        server_input: String,
        enrolling: bool,
        embedded: EmbeddedStatus,
        importing_bundle: bool,
        bundle_status: Option<String>,
        show_logs: bool,
        auto_scroll_logs: bool,
        active_reset_prompt: Option<ResetPrompt>,
        bundle_feedback: Arc<Mutex<Option<BundleFeedback>>>,
        exporting_diag: bool,
        diag_status: Option<String>,
    diag_status_color: Option<Color32>,
        diag_feedback: Arc<Mutex<Option<DiagnosticsFeedback>>>,
    }

    impl PerceptaAgentApp {
        pub fn new(state: AgentState, embedded: EmbeddedStatus) -> Self {
            let cached_addr = state.server_addr.lock().unwrap().clone();
            let default_server = if cached_addr.is_empty() {
                "http://localhost:8080".to_string()
            } else if cached_addr.contains(':') {
                let host = cached_addr.split(':').next().unwrap_or("localhost");
                format!("http://{}:8080", host)
            } else {
                format!("http://{}:8080", cached_addr)
            };

            Self {
                state,
                server_input: default_server,
                enrolling: false,
                embedded,
                importing_bundle: false,
                bundle_status: None,
                show_logs: false,
                auto_scroll_logs: true,
                active_reset_prompt: None,
                bundle_feedback: Arc::new(Mutex::new(None)),
                exporting_diag: false,
                diag_status: None,
                diag_status_color: None,
                diag_feedback: Arc::new(Mutex::new(None)),
            }
        }

        fn process_bundle_feedback(&mut self) {
            if let Ok(mut guard) = self.bundle_feedback.lock() {
                if let Some(feedback) = guard.take() {
                    self.importing_bundle = false;
                    if feedback.success {
                        if let Some(enroll_url) = feedback.enroll_url.clone() {
                            self.server_input = enroll_url;
                        }
                        if let Some(grpc_addr) = feedback.grpc_addr.clone() {
                            if let Ok(mut addr) = self.state.server_addr.lock() {
                                *addr = grpc_addr;
                            }
                        }
                    }
                    self.bundle_status = Some(feedback.message);
                }
            }
        }

        fn process_diag_feedback(&mut self) {
            if let Ok(mut guard) = self.diag_feedback.lock() {
                if let Some(feedback) = guard.take() {
                    self.exporting_diag = false;
                    self.diag_status = Some(feedback.message.clone());
                    self.diag_status_color = Some(if feedback.success {
                        Color32::from_rgb(0, 140, 0)
                    } else {
                        Color32::from_rgb(200, 0, 0)
                    });
                }
            }
        }

        fn start_diagnostics_export(&mut self) {
            if self.exporting_diag {
                return;
            }
            self.exporting_diag = true;
            self.diag_status = Some("Generating diagnostics snapshot...".to_string());
            let feedback_slot = self.diag_feedback.clone();
            let state = self.state.clone();

            tokio::spawn(async move {
                let feedback = match export_diagnostics_snapshot(state.clone()).await {
                    Ok(path) => {
                        let msg = format!("✅ Diagnostics saved to {}", path.display());
                        state.append_log(format!("Diagnostics snapshot written to {}", path.display()));
                        DiagnosticsFeedback {
                            message: msg,
                            success: true,
                        }
                    }
                    Err(err) => {
                        state.append_log(format!("Diagnostics export failed: {}", err));
                        DiagnosticsFeedback {
                            message: format!("❌ Diagnostics export failed: {}", err),
                            success: false,
                        }
                    }
                };

                if let Ok(mut guard) = feedback_slot.lock() {
                    *guard = Some(feedback);
                }
            });
        }

        fn start_bundle_import(&mut self, bundle_path: PathBuf) {
            let display_name = bundle_path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| bundle_path.display().to_string());
            self.importing_bundle = true;
            self.bundle_status = Some(format!("Importing {}...", display_name));

            let feedback_slot = self.bundle_feedback.clone();
            let state = self.state.clone();

            tokio::spawn(async move {
                let cert_dir = cert_directory();
                let result = import_portal_bundle(&bundle_path, &cert_dir).await;
                let feedback = match result {
                    Ok(summary) => {
                        state.update_stats(|stats| {
                            if summary.ca_copied {
                                stats.ca_installed = true;
                            }
                            if summary.otk_copied {
                                stats.otk_available = true;
                            }
                        });
                        state.append_log(format!(
                            "Bundle '{}' imported (CA copied: {}, OTK copied: {})",
                            display_name, summary.ca_copied, summary.otk_copied
                        ));
                        if files::enrollment_artifacts_present(&cert_dir) {
                            state.show_reset_prompt(ResetPromptReason::BundleImported);
                        }

                        if let Some(enroll) = summary.enroll_url.as_ref() {
                            state.append_log(format!("Enrollment portal auto-set to {}", enroll));
                        }
                        if let Some(grpc) = summary.grpc_addr.as_ref() {
                            if let Ok(mut addr) = state.server_addr.lock() {
                                *addr = grpc.clone();
                            }
                            state.append_log(format!("gRPC endpoint set to {}", grpc));
                        }

                        BundleFeedback {
                            message: format!("✅ Bundle imported from {}", display_name),
                            success: true,
                            enroll_url: summary.enroll_url,
                            grpc_addr: summary.grpc_addr,
                        }
                    }
                    Err(err) => {
                        state.append_log(format!("Bundle import failed: {}", err));
                        BundleFeedback {
                            message: format!("❌ Bundle import failed: {}", err),
                            success: false,
                            enroll_url: None,
                            grpc_addr: None,
                        }
                    }
                };

                if let Ok(mut guard) = feedback_slot.lock() {
                    *guard = Some(feedback);
                }
            });
        }

        fn render_bundle_controls(&mut self, ui: &mut egui::Ui) {
            ui.heading("Portal Bundle Import");
            ui.label("Select the ZIP or folder downloaded from the enrollment portal. We'll extract OTK, CA, and server info automatically.");
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!self.importing_bundle, egui::Button::new("📦 Import Bundle Zip"))
                    .clicked()
                {
                    if let Some(path) = FileDialog::new()
                        .set_title("Select Percepta portal bundle")
                        .add_filter("Zip", &["zip"])
                        .pick_file()
                    {
                        self.start_bundle_import(path);
                    }
                }

                if ui
                    .add_enabled(!self.importing_bundle, egui::Button::new("📁 Import Folder"))
                    .clicked()
                {
                    if let Some(path) = FileDialog::new()
                        .set_title("Select extracted portal folder")
                        .pick_folder()
                    {
                        self.start_bundle_import(path);
                    }
                }

                if ui.button("🧹 Reset Certificates").clicked() {
                    self.state.show_reset_prompt(ResetPromptReason::UserRequested);
                }
            });

            if self.importing_bundle {
                ui.label("Importing bundle ...");
            }
            if let Some(status) = &self.bundle_status {
                let color = if status.starts_with("✅") {
                    Color32::from_rgb(0, 150, 0)
                } else if status.starts_with("❌") {
                    Color32::from_rgb(200, 0, 0)
                } else {
                    Color32::from_rgb(200, 200, 50)
                };
                ui.label(RichText::new(status.clone()).color(color));
            }
        }

        fn render_logs(&mut self, ui: &mut egui::Ui) {
            ui.horizontal(|ui| {
                let button_label = if self.show_logs { "Hide Logs" } else { "Show Logs" };
                if ui.button(button_label).clicked() {
                    self.show_logs = !self.show_logs;
                }
                ui.checkbox(&mut self.auto_scroll_logs, "Auto-scroll");
            });

            if self.show_logs {
                let logs = self.state.latest_logs();
                egui::ScrollArea::vertical()
                    .max_height(220.0)
                    .stick_to_bottom(self.auto_scroll_logs)
                    .show(ui, |ui| {
                        for line in logs {
                            ui.monospace(line);
                        }
                    });
            }
        }

        fn render_reset_modal(&mut self, ctx: &egui::Context) {
            if let Some(prompt) = &self.active_reset_prompt {
                let reason_text = match prompt.reason {
                    ResetPromptReason::BundleImported => {
                        "A new bundle was imported. Delete existing certificates to avoid trust conflicts?"
                    }
                    ResetPromptReason::UserRequested => {
                        "This will delete current certificates and server config so you can start fresh."
                    }
                };

                egui::Window::new("Reset enrollment?")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(reason_text);
                        ui.horizontal(|ui| {
                            if ui.button("Delete & Reset").clicked() {
                                let state = self.state.clone();
                                tokio::spawn(async move {
                                    if let Err(err) = reset_enrollment_artifacts(state.clone()).await {
                                        state.append_log(format!("Reset failed: {}", err));
                                        state.set_status(format!(
                                            "❌ Failed to reset certificates: {}",
                                            err
                                        ));
                                    } else {
                                        state.append_log("Enrollment artifacts cleared");
                                        state.set_status(
                                            "✅ Certificates removed. Import a new portal bundle to continue.",
                                        );
                                    }
                                });
                                self.active_reset_prompt = None;
                            }
                            if ui.button("Cancel").clicked() {
                                self.active_reset_prompt = None;
                            }
                        });
                    });
            }
        }
    }

    impl eframe::App for PerceptaAgentApp {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            self.process_bundle_feedback();
            self.process_diag_feedback();

            if self.active_reset_prompt.is_none() {
                if let Some(prompt) = self.state.take_reset_prompt() {
                    self.active_reset_prompt = Some(prompt);
                }
            }

            if self.enrolling {
                let enrolled_flag = *self.state.enrolled.lock().unwrap();
                let status_snapshot = self.state.status.lock().unwrap().clone();
                if enrolled_flag
                    || status_snapshot.starts_with("❌")
                    || status_snapshot.starts_with("✅")
                {
                    self.enrolling = false;
                }
            }

            egui::CentralPanel::default().show(ctx, |ui| {
                let status_text = self.state.status.lock().unwrap().clone();
                let enrolled = *self.state.enrolled.lock().unwrap();
                let stats = self.state.stats.lock().unwrap().clone();

                ui.heading("🛡️ Percepta SIEM Agent");
                ui.label("Configurationless Windows collector with embedded trust");
                ui.separator();

                ui.horizontal(|ui| {
                    ui.group(|ui| {
                        ui.label(RichText::new("Connection").strong());
                        ui.label(status_text.clone());
                        if let Some(last) = stats.last_connected {
                            ui.label(format!(
                                "Last handshake: {}",
                                last.format("%Y-%m-%d %H:%M:%S")
                            ));
                        }
                    });

                    ui.group(|ui| {
                        ui.label(RichText::new("Telemetry").strong());
                        ui.label(format!("Events sent: {}", stats.events_sent));
                        if let Some(batch) = stats.last_batch {
                            ui.label(format!("Last batch size: {}", batch));
                        } else {
                            ui.label("No batches yet");
                        }
                    });

                    ui.group(|ui| {
                        ui.label(RichText::new("Identity").strong());
                        let cert_dir = cert_directory();
                        let agent_id = std::fs::read_to_string(cert_dir.join("agent_id.txt"))
                            .ok()
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| "Not initialized".to_string());
                        ui.label(format!("Agent ID (stable): {}", agent_id));
                        ui.label(format!(
                            "Current user: {}",
                            system_info::get_current_username()
                        ));
                    });
                });

                ui.horizontal(|ui| {
                    let ca_status = if stats.ca_installed {
                        "✅ Embedded CA ready"
                    } else {
                        "⚠️ Embedded CA missing"
                    };
                    let otk_status = if stats.otk_available {
                        "✅ Embedded OTK ready"
                    } else {
                        "⚠️ Embedded OTK missing"
                    };
                    ui.label(ca_status);
                    ui.label(otk_status);
                    if let Some(fp) = self.embedded.ca_fingerprint.as_ref() {
                        ui.label(format!("Fingerprint: {}", fp));
                    }
                });

                if let Some(cert) = stats.agent_cert.clone() {
                    ui.separator();
                    ui.group(|ui| {
                        ui.label(RichText::new("Agent Certificate").strong());
                        ui.label(format!("Subject: {}", cert.subject));
                        ui.label(format!("Issuer: {}", cert.issuer));
                        ui.label(format!("Valid: {} → {}", cert.valid_from, cert.valid_until));
                        ui.label(format!("Serial: {}", cert.serial));
                    });
                }

                ui.separator();

                self.render_bundle_controls(ui);

                ui.separator();

                if !enrolled {
                    ui.heading("Enroll & Start");
                    ui.label("Provide the server's HTTP address (port 8080). The GUI handles OTK + CA automatically.");
                    ui.horizontal(|ui| {
                        ui.label("Server URL:");
                        ui.text_edit_singleline(&mut self.server_input);
                    });

                    let enroll_btn = ui.add_enabled(!self.enrolling, egui::Button::new("🚀 Enroll & Start"));
                    if enroll_btn.clicked() {
                        let server_input = self.server_input.trim().to_string();
                        if server_input.is_empty() {
                            self.state
                                .set_status("❌ Please enter the server URL (e.g., http://siem-host:8080)");
                        } else {
                            self.enrolling = true;
                            let state = self.state.clone();
                            tokio::spawn(async move {
                                run_enrollment_flow(state, server_input).await;
                            });
                        }
                    }

                    if self.enrolling {
                        ui.label("Enrollment in progress...");
                    }
                } else {
                    ui.heading("Live Operations");
                    ui.label("Collecting Windows Event Logs and streaming over mTLS to the SIEM server.");
                    ui.horizontal(|ui| {
                        if ui.button("🔄 Force Reconnect").clicked() {
                            self.state.set_status("Reconnecting to server...");
                            if let Some(mut enrolled) = self.state.enrolled.lock().ok() {
                                *enrolled = false;
                            }
                        }
                        if ui.button("🧪 Send Test Pulse").clicked() {
                            self.state.set_status("Manual health check requested");
                        }
                        if ui.button("🔐 Request Cert Renewal").clicked() {
                            let state = self.state.clone();
                            let server_url = self.server_input.trim().to_string();
                            self.state.set_status("Requesting renewal (awaiting approval)...");
                            tokio::spawn(async move {
                                let cert_dir = cert_directory();
                                let agent_id = match files::get_agent_id(&cert_dir).await {
                                    Ok(v) => v,
                                    Err(e) => {
                                        state.set_status(format!("❌ Failed to get agent ID: {}", e));
                                        state.append_log(format!("Failed to get agent ID: {}", e));
                                        return;
                                    }
                                };

                                let token = match tls::request_certificate_renewal(
                                    &server_url,
                                    &agent_id,
                                    &cert_dir,
                                )
                                .await
                                {
                                    Ok(t) => t,
                                    Err(e) => {
                                        state.set_status(format!("❌ Renewal request failed: {}", e));
                                        state.append_log(format!("Renewal request failed: {}", e));
                                        return;
                                    }
                                };

                                state.append_log("Renewal requested; waiting for admin approval...".to_string());

                                let deadline = tokio::time::Instant::now()
                                    + std::time::Duration::from_secs(10 * 60);
                                loop {
                                    if tokio::time::Instant::now() > deadline {
                                        state.set_status("⏳ Renewal pending (timed out waiting)".to_string());
                                        state.append_log(
                                            "Timed out waiting for approval; you can click Request Cert Renewal again later.".to_string(),
                                        );
                                        return;
                                    }

                                    match tls::pickup_certificate_renewal(&server_url, &cert_dir, &token)
                                        .await
                                    {
                                        Ok(true) => {
                                            state.set_status("✅ Renewal installed".to_string());
                                            state.append_log("Renewal installed successfully".to_string());
                                            return;
                                        }
                                        Ok(false) => {
                                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                        }
                                        Err(e) => {
                                            state.set_status(format!("❌ Renewal pickup failed: {}", e));
                                            state.append_log(format!("Renewal pickup failed: {}", e));
                                            return;
                                        }
                                    }
                                }
                            });
                        }
                    });
                }

                ui.separator();
                egui::CollapsingHeader::new("Diagnostics & Files")
                    .default_open(false)
                    .show(ui, |ui| {
                        let cert_dir = cert_directory();
                        ui.label(format!("Certificate folder: {}", cert_dir.display()));
                        if ui.button("� Open Folder").clicked() {
                            let _ = std::process::Command::new("explorer")
                                .arg(cert_dir)
                                .spawn();
                        }
                        if ui
                            .add_enabled(!self.exporting_diag, egui::Button::new("📝 Export Diagnostics Snapshot"))
                            .clicked()
                        {
                            self.start_diagnostics_export();
                        }
                        if let Some(status) = &self.diag_status {
                            let color = self
                                .diag_status_color
                                .unwrap_or(Color32::from_rgb(180, 180, 50));
                            ui.label(RichText::new(status.clone()).color(color));
                        }
                        ui.label("Embedded assets stored on first launch. Delete certs to re-enroll.");
                    });

                ui.separator();
                ui.heading("Verbose Logs");
                self.render_logs(ui);
            });

            ctx.request_repaint();

            self.render_reset_modal(ctx);
        }
    }
}

async fn run_enrollment_flow(state: AgentState, server_input: String) {
    let trimmed = server_input.trim().to_string();
    if trimmed.is_empty() {
        state.set_status("❌ Please provide the server URL before enrolling");
        return;
    }

    state.append_log(format!("Enrollment requested for {}", trimmed));
    state.set_status("Enrolling with server...");
    let cert_dir = cert_directory();
    if let Err(e) = provision_embedded_assets(&cert_dir).await {
        state.set_status(format!("❌ Failed to prepare embedded assets: {}", e));
        state.append_log(format!("Embedded asset provisioning failed: {}", e));
        return;
    }

    let enroll_url = normalize_enrollment_base(&trimmed);
    let connection_addr = normalize_connection_addr(&trimmed);

    if enroll_url.is_empty() || connection_addr.is_empty() {
        state.set_status("❌ Unable to determine server address. Please supply host or URL.");
        state.append_log("Enrollment failed: missing server address");
        return;
    }

    let otk_value = match resolve_otk(&enroll_url).await {
        Ok(otk) => otk,
        Err(e) => {
            state.set_status(format!("❌ Failed to obtain OTK: {}", e));
            state.append_log(format!("Failed to obtain OTK: {}", e));
            return;
        }
    };

    let agent_id = match files::get_agent_id(&cert_dir).await {
        Ok(id) => id,
        Err(e) => {
            state.set_status(format!("❌ Failed to read agent ID: {}", e));
            state.append_log(format!("Failed to read agent ID: {}", e));
            return;
        }
    };

    match tls::enroll_with_otk(&enroll_url, &otk_value, &agent_id, &cert_dir).await {
        Ok(_) => {}
        Err(e) => {
            state.set_status(format!("❌ Enrollment failed: {}", e));
            state.append_log(format!("Enrollment failed: {}", e));
            return;
        }
    }

    if let Err(e) = files::write_server_config(&cert_dir, &connection_addr).await {
        state.set_status(format!(
            "❌ Enrollment succeeded but failed to save config: {}",
            e
        ));
        state.append_log(format!("Enrollment config save failed: {}", e));
        return;
    }

    state.update_stats(|stats| {
        stats.ca_installed = true;
        stats.otk_available = true;
    });

    if let Err(e) = refresh_agent_certificate_stats(&state).await {
        state.append_log(format!("Enrollment succeeded but failed to parse agent cert: {}", e));
    }

    state.set_status("✅ Enrolled! Agent starting...");
    state.append_log("Enrollment completed successfully");
    if let Some(mut enrolled) = state.enrolled.lock().ok() {
        *enrolled = true;
    }
    if let Some(mut addr) = state.server_addr.lock().ok() {
        *addr = connection_addr;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Check for service mode flag
    let args: Vec<String> = std::env::args().collect();

    // Tray mode: single-EXE controller for the Windows service
    if args.contains(&"--tray".to_string()) {
        #[cfg(all(target_os = "windows", feature = "windows-service"))]
        {
            percepta_agent::tray_app::run_tray()?;
            return Ok(());
        }
        #[cfg(not(all(target_os = "windows", feature = "windows-service")))]
        {
            bail!("Tray mode requires Windows + windows-service feature");
        }
    }

    if args.contains(&"--service".to_string()) {
        // Run as Windows service (no GUI)
        return run_agent_service().await;
    }

    // Otherwise run with GUI
    #[cfg(feature = "gui")]
    {
        let state = AgentState::default();
        let embedded_summary = match bootstrap_state(&state).await {
            Ok(summary) => summary,
            Err(e) => {
                state.set_status(format!("❌ Failed to prepare embedded assets: {}", e));
                EmbeddedStatus::default()
            }
        };

        // Start background agent task
        let bg_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_agent_background(bg_state).await {
                eprintln!("Agent background task error: {}", e);
            }
        });

        // Launch GUI on main thread
        let options = eframe::NativeOptions::default();
        let gui_state = state.clone();
        let summary_for_gui = embedded_summary.clone();
        eframe::run_native(
            "Percepta SIEM Agent",
            options,
            Box::new(move |_cc| {
                Box::new(gui_app::PerceptaAgentApp::new(
                    gui_state.clone(),
                    summary_for_gui.clone(),
                ))
            }),
        )
        .map_err(|e| anyhow::anyhow!("GUI error: {}", e))?;
    }

    #[cfg(not(feature = "gui"))]
    {
        bail!("GUI feature not enabled");
    }

    Ok(())
}

/// Run agent as Windows service (no GUI)
async fn run_agent_service() -> Result<()> {
    windows_service::run_as_service(|| async {
        // Run standard agent collection loop in service mode
        let cert_dir = cert_directory();

        // Check if enrolled
        if !(cert_dir.join("agent_cert.pem").exists() && cert_dir.join("agent_key.pem").exists() && cert_dir.join("ca_cert.pem").exists()) {
            bail!("Agent not enrolled. Missing certificates in {}. Run without --service flag first to enroll.", cert_dir.display());
        }

        // Read server config
        let server_addr = match files::read_server_config(&cert_dir).await {
            Ok(addr) => addr,
            Err(e) => bail!("Failed to read server config: {}", e),
        };

        // Get agent ID
        let agent_id: String = files::get_agent_id(&cert_dir).await?;

        // Determine gRPC address
        let grpc_addr = normalize_connection_addr(&server_addr);

        println!("🛡️ Percepta SIEM Agent Service Starting");
        println!("   Server: {}", grpc_addr);
        println!("   Agent ID: {}", agent_id);

        // Main service loop with auto-reconnect
        loop {
            println!("🔗 Connecting to server...");

            let client_handle = match client::connect_and_stream(&grpc_addr, &cert_dir, &agent_id).await {
                Ok(handle) => {
                    println!("✅ Connected to server");
                    handle
                }
                Err(e) => {
                    println!("❌ Connection failed: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    continue;
                }
            };

            // Initialize Windows Event Log collector
            #[cfg(windows)]
            let mut collector = match percepta_agent::windows_eventlog::WindowsEventCollector::initialize(
                agent_id.clone(),
                cert_dir.clone(),
            ).await {
                Ok(c) => {
                    println!("📋 Event collector initialized");
                    c
                }
                Err(e) => {
                    println!("❌ Failed to initialize collector: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    continue;
                }
            };

            let mut event_count = 0u64;
            println!("🔍 Collecting Windows Event Logs...");

            // Collection loop
            loop {
                #[cfg(windows)]
                let events = match collector.collect_events(100).await {
                    Ok(evts) => evts,
                    Err(e) => {
                        println!("⚠️  Collection error: {}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };

                #[cfg(windows)]
                if !events.is_empty() {
                    event_count += events.len() as u64;
                    println!("📤 Sending {} events (total: {})...", events.len(), event_count);

                    if let Err(e) = client_handle.send_events(events).await {
                        println!("⚠️  Send failed: {}", e);
                        break; // Reconnect
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            }

            println!("Connection lost, reconnecting...");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    }).await
}

/// Background agent task (collects and sends logs)
async fn run_agent_background(state: AgentState) -> Result<()> {
    let mut waiting_logged = false;
    loop {
        let enrolled = *state.enrolled.lock().unwrap();

        if !enrolled {
            *state.status.lock().unwrap() = "Waiting for enrollment...".to_string();
            if !waiting_logged {
                state.append_log("Background task idle: waiting for enrollment");
                waiting_logged = true;
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            continue;
        }
        waiting_logged = false;

        // Agent is enrolled, start collection
        *state.status.lock().unwrap() = "Connecting to server...".to_string();

        let cert_dir = cert_directory();
        // Get server address (prefer in-memory, fall back to disk)
        let mut server_addr = state.server_addr.lock().unwrap().clone();
        if server_addr.is_empty() {
            match files::read_server_config(&cert_dir).await {
                Ok(addr) => {
                    server_addr = addr.clone();
                    if let Some(mut guard) = state.server_addr.lock().ok() {
                        *guard = addr;
                    }
                }
                Err(e) => {
                    *state.status.lock().unwrap() = format!(
                        "❌ No server address configured ({}). Please enroll first.",
                        e
                    );
                    state.append_log(format!("Missing server address: {}", e));
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            }
        }

        let agent_id: String = match files::get_agent_id(&cert_dir).await {
            Ok(id) => id,
            Err(e) => {
                *state.status.lock().unwrap() = format!("❌ Failed to get agent ID: {}", e);
                state.append_log(format!("Failed to read agent ID: {}", e));
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Connect to server with gRPC
        *state.status.lock().unwrap() = "🔗 Connecting to SIEM server...".to_string();

        // Determine gRPC address (server_addr may be a full URL). Strip scheme and path, force :50051 when needed.
        let grpc_addr = normalize_connection_addr(&server_addr);

        let client_handle = match client::connect_and_stream(&grpc_addr, &cert_dir, &agent_id).await
        {
            Ok(handle) => {
                *state.status.lock().unwrap() = "✅ Connected to server".to_string();
                state.append_log(format!("Connected to {}", grpc_addr));
                state.update_stats(|stats| {
                    stats.last_connected = Some(Local::now());
                });
                handle
            }
            Err(e) => {
                *state.status.lock().unwrap() = format!("❌ Connection failed: {}", e);
                state.append_log(format!("Connection failed: {}", e));
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                continue;
            }
        };

        // Initialize Windows Event Log collector
        #[cfg(windows)]
        let mut collector =
            match percepta_agent::windows_eventlog::WindowsEventCollector::initialize(
                agent_id.clone(),
                cert_dir.clone(),
            )
            .await
            {
                Ok(c) => {
                    *state.status.lock().unwrap() = "📋 Event collector initialized".to_string();
                    c
                }
                Err(e) => {
                    *state.status.lock().unwrap() =
                        format!("❌ Failed to initialize collector: {}", e);
                    state.append_log(format!("Collector initialization failed: {}", e));
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    continue;
                }
            };

        // Main collection loop
        let mut event_count = 0u64;
        *state.status.lock().unwrap() = "🔍 Collecting Windows Event Logs...".to_string();

        loop {
            // Check if still enrolled
            if !*state.enrolled.lock().unwrap() {
                break;
            }

            // Collect events from Windows Event Log
            #[cfg(windows)]
            let events = match collector.collect_events(100).await {
                Ok(evts) => evts,
                Err(e) => {
                    *state.status.lock().unwrap() = format!("⚠️  Collection error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            // Send events to server if any collected
            #[cfg(windows)]
            if !events.is_empty() {
                event_count += events.len() as u64;
                *state.status.lock().unwrap() = format!(
                    "📤 Sending {} events (total: {})...",
                    events.len(),
                    event_count
                );
                let batch_size = events.len();

                if let Err(e) = client_handle.send_events(events).await {
                    *state.status.lock().unwrap() = format!("⚠️  Send failed: {}", e);
                    state.append_log(format!("Send failed: {}", e));
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    break; // Reconnect
                }

                state.update_stats(|stats| {
                    stats.events_sent += batch_size as u64;
                    stats.last_batch = Some(batch_size);
                });
                state.append_log(format!(
                    "Sent {} events (cumulative {})",
                    batch_size, event_count
                ));
                *state.status.lock().unwrap() =
                    format!("✅ Active - Collected {} events", event_count);
            }

            // Wait before next collection cycle
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }

        // If we're here, connection was lost or enrollment removed
        *state.status.lock().unwrap() = "Connection lost, reconnecting...".to_string();
        state.append_log("Connection lost; retrying");
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}
