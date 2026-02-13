//! Web portal for agent download and enrollment

use crate::enroll::AppState;
use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    response::{Html, IntoResponse, Response},
};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::{Path as StdPath, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;
use zip::write::{FileOptions, ZipWriter};

const WINDOWS_INSTALLER_CANDIDATES: &[&str] = &[
    "server/agent_builds/percepta-agent-setup.exe", // when run from repo root
    "agent_builds/percepta-agent-setup.exe",        // when run from `cd server`
];
const WINDOWS_AGENT_CANDIDATES: &[&str] = &[
    // Prefer curated builds staged under server/agent_builds
    "server/agent_builds/percepta-agent-windows.exe",
    "server/agent_builds/percepta-agent_windows.exe",
    "server/agent_builds/percepta-agent.exe",
    "server/agent_builds/gui.exe",
    // Also accept a curated build staged under static/downloads (common in this repo)
    "server/static/downloads/percepta-agent-windows.exe",
    "static/downloads/percepta-agent-windows.exe",
    // Same paths when the server runs with CWD=server/
    "agent_builds/percepta-agent-windows.exe",
    "agent_builds/percepta-agent_windows.exe",
    "agent_builds/percepta-agent.exe",
    "agent_builds/gui.exe",
    // Fallback to direct cargo targets if operator built locally
    "target/x86_64-pc-windows-gnu/release/percepta-agent-windows.exe",
    "target/x86_64-pc-windows-gnu/release/percepta-agent.exe",
    "target/x86_64-pc-windows-gnu/release/gui.exe",
    "target/x86_64-pc-windows-msvc/release/percepta-agent-windows.exe",
    "target/x86_64-pc-windows-msvc/release/percepta-agent.exe",
    "target/x86_64-pc-windows-msvc/release/gui.exe",
];

const LINUX_AGENT_CANDIDATES: &[&str] = &[
    "server/static/downloads/percepta-agent-linux-x64", // when run from repo root
    "static/downloads/percepta-agent-linux-x64",        // when run from `cd server`
];

// Serve a small HTML portal and produce a ZIP containing the Windows agent, an
// install.ps1 script (dynamically generated with an OTK and server URL), and
// the CA certificate.

pub async fn serve_portal(State(_state): State<AppState>) -> Html<String> {
    let server_version = env!("CARGO_PKG_VERSION").to_string();
    let now = chrono::Utc::now();

    let windows_installer = artifact_info_first_existing(WINDOWS_INSTALLER_CANDIDATES).await;
    let windows_agent = artifact_info_first_existing(WINDOWS_AGENT_CANDIDATES).await;
    let linux_agent = artifact_info_first_existing(LINUX_AGENT_CANDIDATES).await;

    let windows_available = windows_installer.is_some() || windows_agent.is_some();

    Html(get_portal_html(
        windows_available,
        &server_version,
        now,
        windows_installer.as_ref(),
        windows_agent.as_ref(),
        linux_agent.as_ref(),
    ))
}

#[derive(Clone, Debug)]
struct ArtifactInfo {
    label: &'static str,
    path: String,
    size_bytes: u64,
    modified_unix: i64,
    sha256_hex: String,
}

#[derive(Clone, Debug)]
struct CachedArtifact {
    size_bytes: u64,
    modified_unix: i64,
    sha256_hex: String,
}

static ARTIFACT_HASH_CACHE: Lazy<Mutex<HashMap<String, CachedArtifact>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn system_time_to_unix_seconds(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn artifact_info_for_path(label: &'static str, path: &str) -> Option<ArtifactInfo> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    if !meta.is_file() {
        return None;
    }
    let size_bytes = meta.len();
    let modified_unix = meta
        .modified()
        .map(system_time_to_unix_seconds)
        .unwrap_or(0);

    // Cache by (path, size, mtime)
    if let Some(cached) = ARTIFACT_HASH_CACHE.lock().get(path) {
        if cached.size_bytes == size_bytes && cached.modified_unix == modified_unix {
            return Some(ArtifactInfo {
                label,
                path: path.to_string(),
                size_bytes,
                modified_unix,
                sha256_hex: cached.sha256_hex.clone(),
            });
        }
    }

    let bytes = tokio::fs::read(path).await.ok()?;
    let digest = openssl::sha::sha256(&bytes);
    let sha256_hex = hex::encode(digest);

    ARTIFACT_HASH_CACHE.lock().insert(
        path.to_string(),
        CachedArtifact {
            size_bytes,
            modified_unix,
            sha256_hex: sha256_hex.clone(),
        },
    );

    Some(ArtifactInfo {
        label,
        path: path.to_string(),
        size_bytes,
        modified_unix,
        sha256_hex,
    })
}

async fn artifact_info_first_existing(candidates: &[&str]) -> Option<ArtifactInfo> {
    for p in expand_artifact_candidates(candidates) {
        if let Some(info) = artifact_info_for_path("artifact", &p).await {
            return Some(ArtifactInfo { label: "artifact", ..info });
        }
    }
    None
}

/// Return CA certificate PEM for clients to use during enrollment
pub async fn get_ca_cert(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let ca_cert_pem = state.ca_service.get_ca_certificate_pem()?;
    let headers = [(header::CONTENT_TYPE, "text/plain".to_string())];
    Ok((headers, ca_cert_pem).into_response())
}

pub async fn download_agent(
    Path(os): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    info!("Agent download request for OS: {}", os);

    match os.as_str() {
        "windows" => download_windows_agent(state, headers).await,
        "linux" => download_linux_agent(state, headers).await,
        _ => Err(AppError(anyhow::anyhow!(
            "Unsupported OS: {}. Supported: windows, linux",
            os
        ))),
    }
}

async fn download_windows_agent(state: AppState, headers: HeaderMap) -> Result<Response, AppError> {
    // If a single-file installer exists, serve it directly.
    if let Some((_path, bytes)) = read_first_existing(WINDOWS_INSTALLER_CANDIDATES).await {
        let headers = [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"percepta-agent-setup.exe\"".to_string(),
            ),
        ];
        return Ok((headers, bytes).into_response());
    }

    // Determine server URL and gRPC address. Prefer explicit publish host if configured,
    // otherwise extract the hostname from the Host header.
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Request missing Host header"))?;
    // Allow an operator to override the published host/IP (useful when behind NAT)
    let server_host = std::env::var("PERCEPTA_PUBLIC_HOST")
        .ok()
        .unwrap_or_else(|| host.split(':').next().unwrap_or(host).to_string());
    // Use gRPC port (50051) for agent connection, HTTP port (8080) for enrollment
    let server_url = format!("http://{}:8080", server_host);
    let grpc_addr = format!("{}:50051", server_host);

    // Generate OTK
    let otk = state
        .otk_store
        .generate("portal-download".to_string())
        .await?;

    // Create PowerShell installer content (include gRPC address)
    // Note: refer to percepta-agent-core.exe explicitly to match packaged name
    let ps_script_content = get_install_ps1(&otk.otk, &server_url, &grpc_addr);

    // Primary Windows agent: unified GUI+service+collector binary (fall back across common locations)
    let (agent_path, windows_agent_bytes) =
        read_first_existing(WINDOWS_AGENT_CANDIDATES).await.ok_or_else(|| {
            anyhow::anyhow!(
                "Windows GUI agent not found. Looked for: {}. Build with 'cargo build --release --target x86_64-pc-windows-gnu -p percepta-agent --bin percepta-agent-windows --features gui' and copy the binary into server/agent_builds/.",
                WINDOWS_AGENT_CANDIDATES.join(", ")
            )
        })?;
    info!("serving Windows agent from {}", agent_path);

    // Get CA certificate
    let ca_cert_pem = state.ca_service.get_ca_certificate_pem()?;

    // Build ZIP in memory
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options = FileOptions::default().unix_permissions(0o755);

        // Write the unified Windows GUI agent
        zip.start_file("percepta-agent-windows.exe", options)?;
        zip.write_all(&windows_agent_bytes)?;

        // Also include the installer and CA cert separately
        zip.start_file("install.ps1", options)?;
        zip.write_all(ps_script_content.as_bytes())?;

        zip.start_file("ca_cert.pem", options)?;
        zip.write_all(ca_cert_pem.as_bytes())?;

        let server_config = format!(
            "enroll_url={}\nserver_url={}\ngrpc_server={}\nnote=Use these values when running the agent manually.\n",
            server_url, server_url, grpc_addr
        );
        zip.start_file("server-config.txt", options)?;
        zip.write_all(server_config.as_bytes())?;

        // Include the OTK in a separate file so GUI/installer can run enrollment automatically
        zip.start_file("otk.txt", options)?;
        zip.write_all(otk.otk.as_bytes())?;

        zip.finish()?;
    }

    let headers = [
        (header::CONTENT_TYPE, "application/zip".to_string()),
        (
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"percepta-agent-windows.zip\"".to_string(),
        ),
    ];

    Ok((headers, buf).into_response())
}

async fn download_linux_agent(state: AppState, headers: HeaderMap) -> Result<Response, AppError> {
    // Determine server URL. Prefer explicit publish host if configured,
    // otherwise extract hostname from the Host header.
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("Request missing Host header"))?;
    let server_host = std::env::var("PERCEPTA_PUBLIC_HOST")
        .ok()
        .unwrap_or_else(|| host.split(':').next().unwrap_or(host).to_string());
    // Use gRPC port (50051) for agent connection, HTTP port (8080) for enrollment
    let server_url = format!("http://{}:8080", server_host);
    let grpc_addr = format!("{}:50051", server_host);

    // Generate OTK
    let otk = state
        .otk_store
        .generate("portal-download".to_string())
        .await?;

    // Create bash installer content
    let install_sh_content = get_install_sh(&otk.otk, &server_url, &grpc_addr);

    // Read agent binary (support running from repo root or `cd server`)
    let (_agent_binary_path, agent_binary_bytes) =
        read_first_existing(LINUX_AGENT_CANDIDATES).await.ok_or_else(|| {
            anyhow::anyhow!(
                "Failed to read Linux agent binary. Looked for: {}. Build with 'cargo build --release -p percepta-agent' then copy to server/static/downloads/percepta-agent-linux-x64.",
                LINUX_AGENT_CANDIDATES.join(", ")
            )
        })?;

    // Get CA certificate
    let ca_cert_pem = state.ca_service.get_ca_certificate_pem()?;

    // Build ZIP in memory
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let options = FileOptions::default().unix_permissions(0o755);

        zip.start_file("percepta-agent", options)?;
        zip.write_all(&agent_binary_bytes)?;

        zip.start_file("install.sh", options)?;
        zip.write_all(install_sh_content.as_bytes())?;

        zip.start_file("ca_cert.pem", options)?;
        zip.write_all(ca_cert_pem.as_bytes())?;

        let server_config = format!(
            "enroll_url={}\nserver_url={}\ngrpc_server={}\nnote=Use these values when running the agent manually.\n",
            server_url, server_url, grpc_addr
        );
        zip.start_file("server-config.txt", options)?;
        zip.write_all(server_config.as_bytes())?;

        zip.finish()?;
    }

    let headers = [
        (header::CONTENT_TYPE, "application/zip".to_string()),
        (
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"percepta-agent-linux.zip\"".to_string(),
        ),
    ];

    Ok((headers, buf).into_response())
}

fn fmt_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    let nf = n as f64;
    if nf >= GB {
        format!("{:.2} GB", nf / GB)
    } else if nf >= MB {
        format!("{:.2} MB", nf / MB)
    } else if nf >= KB {
        format!("{:.2} KB", nf / KB)
    } else {
        format!("{} B", n)
    }
}

fn fmt_unix(ts: i64) -> String {
    if ts <= 0 {
        return "unknown".to_string();
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "unknown".to_string())
}

fn render_artifact_row(info: &ArtifactInfo) -> String {
    format!(
        r#"<div class="artifact">
  <div><strong>{}</strong></div>
  <div class="muted">Path: <span class="mono">{}</span></div>
  <div class="muted">Size: {} · Modified: {}</div>
  <div class="muted">SHA256: <span class="mono">{}</span></div>
</div>"#,
        info.label,
        info.path,
        fmt_bytes(info.size_bytes),
        fmt_unix(info.modified_unix),
        info.sha256_hex
    )
}

fn get_portal_html(
    windows_available: bool,
    server_version: &str,
    generated_at: chrono::DateTime<chrono::Utc>,
    windows_installer: Option<&ArtifactInfo>,
    windows_agent: Option<&ArtifactInfo>,
    linux_agent: Option<&ArtifactInfo>,
) -> String {
    let windows_button = if windows_available {
        r#"<a href="/api/download/agent/windows" class="button" style="background-color: #007bff; margin: 0.5rem;">Download for Windows (Single EXE)</a>"#
    } else {
        r#"<a class="button" style="background-color: #6c757d; margin: 0.5rem; pointer-events: none; opacity: 0.7;">Windows build not found</a>"#
    };

    let mut integrity_rows = String::new();
    if let Some(wi) = windows_installer {
        let mut row = wi.clone();
        row.label = "Windows installer (served directly if present)";
        integrity_rows.push_str(&render_artifact_row(&row));
    }
    if let Some(wa) = windows_agent {
        let mut row = wa.clone();
        row.label = "Windows agent binary (embedded in ZIP)";
        integrity_rows.push_str(&render_artifact_row(&row));
    }
    if let Some(la) = linux_agent {
        let mut row = la.clone();
        row.label = "Linux agent binary (embedded in ZIP)";
        integrity_rows.push_str(&render_artifact_row(&row));
    }

    if integrity_rows.is_empty() {
        integrity_rows.push_str(
            r#"<div class="artifact"><div><strong>No staged agent artifacts found</strong></div><div class="muted">Stage builds under <span class="mono">server/agent_builds</span> (Windows) and <span class="mono">server/static/downloads</span> (Linux).</div></div>"#,
        );
    }

        let header_line = format!(
                "Server version: <span class=\"mono\">{}</span> · Page generated: <span class=\"mono\">{}</span>",
                server_version,
                generated_at.to_rfc3339(),
        );

        let integrity_section = format!(
                r#"<div class="artifact">
    <div><strong>Download integrity</strong></div>
    <div class="muted">ZIP bundles include a per-download One-Time Token (OTK), so ZIP checksums will vary. Verify the embedded agent binary checksum instead:</div>
    {}
</div>"#,
                integrity_rows
        );

        let host_note = r#"<div class="artifact">
    <div><strong>Host consistency note</strong></div>
    <div class="muted">Use the same hostname for portal + dashboard + logins (cookies are host-bound). Prefer <span class="mono">PERCEPTA_PUBLIC_HOST</span> when behind NAT/reverse proxy.</div>
</div>"#;

        format!(
                r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Percepta SIEM Agent Download</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background: #f0f2f5;
            margin: 0;
            padding: 18px;
        }}
        .container {{
            background: white;
            padding: 2.2rem;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.10);
            text-align: center;
            max-width: 760px;
            width: 100%;
        }}
        h1 {{ color: #1d2129; margin: 0 0 0.2rem; }}
        p {{ color: #606770; margin-top: 0.4rem; margin-bottom: 1.4rem; }}
        .button {{
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 0.95rem 1.6rem;
            text-decoration: none;
            border-radius: 8px;
            font-size: 1.05rem;
            font-weight: 650;
            transition: background-color 0.2s, transform 0.15s;
            margin: 0.5rem;
        }}
        .button:hover {{ background-color: #0056b3; transform: translateY(-1px); }}
        .muted {{ color: #566; font-size: 0.95rem; }}
        .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92rem; }}
        .artifact {{
            text-align: left;
            border: 1px solid #e6e9ee;
            border-radius: 10px;
            padding: 0.95rem;
            margin-top: 0.9rem;
            background: #fbfcff;
        }}
        .artifact strong {{ font-size: 0.98rem; }}
        code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Percepta SIEM Agent</h1>
        <div class="muted">{}</div>
        <p>Download the agent for your operating system. Bundles are pre-configured for this server.</p>

        {}
        <a href="/api/download/agent/linux" class="button" style="background-color: #28a745;">Download for Linux (ZIP)</a>

        {}
        {}

        <div class="artifact">
            <div><strong>Build note</strong></div>
            <div class="muted">Windows builds can be staged under <span class="mono">server/agent_builds</span>. Linux builds under <span class="mono">server/static/downloads</span>.</div>
            <div class="muted">Example Windows build: <code>cargo build --release --target x86_64-pc-windows-gnu -p percepta-agent --bin percepta-agent-windows --features \"gui windows-service\"</code></div>
        </div>
    </div>
</body>
</html>"#,
        header_line,
        windows_button,
        integrity_section,
        host_note,
    )
}

fn compute_artifact_bases() -> Vec<PathBuf> {
    let mut bases = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        bases.push(cwd);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            bases.push(dir.to_path_buf());

            // Also search a few parent directories. This makes downloads work when
            // the server is launched as a service (CWD may be /) or from a packaged
            // folder like server/static/downloads.
            let mut p = dir.to_path_buf();
            for _ in 0..4 {
                if let Some(parent) = p.parent() {
                    p = parent.to_path_buf();
                    bases.push(p.clone());
                } else {
                    break;
                }
            }
        }
    }

    bases
}

fn expand_artifact_candidates(candidates: &[&str]) -> Vec<String> {
    let bases = compute_artifact_bases();
    let mut out: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut push_unique = |p: String| {
        if seen.insert(p.clone()) {
            out.push(p);
        }
    };

    // Preserve original ordering first.
    for c in candidates {
        push_unique((*c).to_string());
    }

    // Then add variants relative to where the server binary is located.
    for c in candidates {
        let basename = StdPath::new(c)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        if basename.is_empty() {
            continue;
        }

        for base in &bases {
            // Try the original candidate relative to base.
            push_unique(base.join(c).to_string_lossy().to_string());

            // Try common staging locations relative to base.
            let rels = [
                PathBuf::from(basename),
                PathBuf::from("agent_builds").join(basename),
                PathBuf::from("static").join("downloads").join(basename),
                PathBuf::from("server").join("agent_builds").join(basename),
                PathBuf::from("server")
                    .join("static")
                    .join("downloads")
                    .join(basename),
            ];
            for rel in rels {
                push_unique(base.join(rel).to_string_lossy().to_string());
            }
        }
    }

    out
}

async fn read_first_existing(paths: &[&str]) -> Option<(String, Vec<u8>)> {
    for path in expand_artifact_candidates(paths) {
        match tokio::fs::read(&path).await {
            Ok(bytes) => return Some((path, bytes)),
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(_) => continue,
        }
    }
    None
}

fn get_install_ps1(otk: &str, server_url: &str, grpc_addr: &str) -> String {
    let template = r###"#

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs and enrolls the Percepta SIEM Agent.
.DESCRIPTION
    This script prepares certificates, enrolls the agent with the server,
    and then installs the agent as a persistent Windows service.
#>

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "[+] Percepta SIEM Agent Installer" -ForegroundColor Green

# --- Configuration ---
$Otk = "__OTK__"
$ServerUrl = "__SERVER__"
$GrpcAddr = "__GRPC__"
$AgentExe = Join-Path $ScriptDir "percepta-agent-windows.exe"
$CertDir = r"C:\ProgramData\percepta_agent\certs"
$CaCertSource = Join-Path $ScriptDir "ca_cert.pem"
$CaCertDest = Join-Path $CertDir "ca_cert.pem"

# --- Certificate Setup ---
Write-Host "[+] Setting up certificate directory: $CertDir"
New-Item -ItemType Directory -Force -Path $CertDir
Write-Host "[+] Copying CA certificate to $CaCertDest"
Copy-Item -Path $CaCertSource -Destination $CaCertDest -Force

# --- Enrollment ---
Write-Host "[+] Enrolling agent with server: $ServerUrl"
try {
    # Enrollment uses the web portal (HTTP). Runtime uses gRPC.
    & $AgentExe --enroll $Otk --server $ServerUrl
}
catch {
    Write-Host "[!] Enrollment failed. The error was:" -ForegroundColor Red
    Write-Host $_
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[+] Enrollment successful!" -ForegroundColor Green

# --- Service Installation ---
Write-Host "[+] Installing agent as a Windows Service..."
# Export runtime server env for the service (the service will inherit this when started via sc create binPath)
Write-Host "[+] Setting PERCEPTA_SERVER environment for the service: $GrpcAddr"
[Environment]::SetEnvironmentVariable("PERCEPTA_SERVER", $GrpcAddr, "Machine")

# Use sc.exe to create the service with a binPath that includes --server so the agent auto-connects
$ServiceName = "PerceptaAgent"
$BinPath = "`"$AgentExe`" --server $GrpcAddr --service"
try {
    sc.exe create $ServiceName binPath= $BinPath start= auto
    sc.exe description $ServiceName "Percepta SIEM Agent service"
    sc.exe start $ServiceName
}
catch {
    Write-Host "[!] Service installation failed. The error was:" -ForegroundColor Red
    Write-Host $_
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "[+] Agent service installed successfully." -ForegroundColor Green
Write-Host "The agent will now run in the background and start automatically with Windows."
Read-Host "Press Enter to exit"

# End of script
"###;

    template
        .replace("__OTK__", otk)
        .replace("__SERVER__", server_url)
        .replace("__GRPC__", grpc_addr)
}

fn get_install_sh(otk: &str, server_url: &str, grpc_addr: &str) -> String {
    let template = r###"#!/bin/bash
#
# Percepta SIEM Agent Installer for Linux
# This script prepares certificates, enrolls the agent with the server,
# and installs the agent as a systemd service.

set -e

if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root (use sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OTK="__OTK__"
ENROLL_URL="__ENROLL_URL__"
GRPC_SERVER="__GRPC_SERVER__"
AGENT_BIN="$SCRIPT_DIR/percepta-agent"
INSTALL_DIR="/opt/percepta-agent"
CERT_DIR="/etc/percepta-agent/certs"
DATA_DIR="/var/lib/percepta-agent"
CA_CERT_SOURCE="$SCRIPT_DIR/ca_cert.pem"

echo "[+] Percepta SIEM Agent Installer"

# --- Setup directories ---
echo "[+] Creating installation directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CERT_DIR"
mkdir -p "$DATA_DIR/outgoing/archives"

# --- Install binary ---
echo "[+] Installing agent binary to $INSTALL_DIR/percepta-agent"
cp "$AGENT_BIN" "$INSTALL_DIR/percepta-agent"
chmod +x "$INSTALL_DIR/percepta-agent"

# --- Certificate Setup ---
echo "[+] Copying CA certificate to $CERT_DIR/ca_cert.pem"
cp "$CA_CERT_SOURCE" "$CERT_DIR/ca_cert.pem"

# --- Enrollment ---
echo "[+] Enrolling agent with server: $ENROLL_URL"
# Set cert dir environment variable for enrollment
export PERCEPTA_CERT_DIR="$CERT_DIR"
if ! "$INSTALL_DIR/percepta-agent" --enroll "$OTK" --server "$ENROLL_URL"; then
    echo "[!] Enrollment failed"
    echo "[!] Check that the server is accessible at: $ENROLL_URL"
    echo "[!] Try: curl -v $ENROLL_URL/healthz"
    exit 1
fi

echo "[+] Enrollment successful!"

# --- Systemd Service Installation ---
echo "[+] Creating systemd service..."

cat > /etc/systemd/system/percepta-agent.service <<EOF
[Unit]
Description=Percepta SIEM Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$DATA_DIR
Environment="PERCEPTA_SERVER=$GRPC_SERVER"
Environment="PERCEPTA_CERT_DIR=$CERT_DIR"
Environment="PERCEPTA_OUT=$DATA_DIR/outgoing"
ExecStart=$INSTALL_DIR/percepta-agent
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# --- Enable and start service ---
echo "[+] Enabling and starting percepta-agent service..."
systemctl daemon-reload
systemctl enable percepta-agent.service
systemctl start percepta-agent.service

echo "[+] Agent service installed successfully!"
echo "[+] The agent is now running and will start automatically on boot."
echo ""
echo "Useful commands:"
echo "  Check status:  sudo systemctl status percepta-agent"
echo "  View logs:     sudo journalctl -u percepta-agent -f"
echo "  Restart:       sudo systemctl restart percepta-agent"
echo "  Stop:          sudo systemctl stop percepta-agent"

# End of script
"###;

    template
        .replace("__OTK__", otk)
        .replace("__ENROLL_URL__", server_url)
        .replace("__GRPC_SERVER__", grpc_addr)
}

// --- Error Handling --- //

pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Something went wrong: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
