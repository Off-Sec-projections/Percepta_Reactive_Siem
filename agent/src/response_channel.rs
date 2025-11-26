use anyhow::{Context, Result};
use std::path::Path;
use std::{path::PathBuf, time::Duration};
use tokio::sync::{broadcast, mpsc};
use tonic::Request;
use tracing::{debug, error, info, warn};

use std::net::ToSocketAddrs;

use crate::client;
use crate::percepta::{
    response_service_client::ResponseServiceClient, CommandKind, ResponseCommand, ResponseResult,
    ResultStatus,
};

trait CommandExtNoWindow {
    fn no_window(&mut self) -> &mut Self;
}

impl CommandExtNoWindow for std::process::Command {
    fn no_window(&mut self) -> &mut Self {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

// ── Input Validation ─────────────────────────────────────────────────────

/// Validate an IP address (v4 or v6). Rejects anything that isn't a clean IP.
fn validate_ip(ip: &str) -> Result<&str> {
    let ip = ip.trim();
    if ip.is_empty() {
        return Err(anyhow::anyhow!("missing ip"));
    }
    // Must parse as a valid IP address — no shell metacharacters can survive this.
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| anyhow::anyhow!("invalid IP address: {}", ip))?;
    Ok(ip)
}

/// Validate a username. Only allows alphanumeric, underscore, hyphen, dot, dollar sign (Linux).
/// Max 64 chars. Rejects shell metacharacters, spaces, quotes, semicolons, etc.
fn validate_username(username: &str) -> Result<&str> {
    let user = username.trim();
    if user.is_empty() {
        return Err(anyhow::anyhow!("missing username"));
    }
    if user.len() > 64 {
        return Err(anyhow::anyhow!("username too long (max 64 chars)"));
    }
    // POSIX usernames: start with letter or underscore, contain [a-zA-Z0-9._-$]
    // Windows allows more but we restrict to a safe set.
    if !user
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '$')
    {
        return Err(anyhow::anyhow!(
            "username contains invalid characters: {}",
            user
        ));
    }
    // Must start with letter or underscore
    if !user.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_') {
        return Err(anyhow::anyhow!(
            "username must start with a letter or underscore"
        ));
    }
    Ok(user)
}

fn now_ts() -> prost_types::Timestamp {
    let now = chrono::Utc::now();
    prost_types::Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    }
}

async fn send_result(
    tx: &mpsc::Sender<ResponseResult>,
    agent_id: &str,
    command_id: &str,
    status: ResultStatus,
    message: impl Into<String>,
    artifact_name: Option<String>,
    artifact: Vec<u8>,
) {
    if tx
        .send(ResponseResult {
            command_id: command_id.to_string(),
            agent_id: agent_id.to_string(),
            status: status as i32,
            message: message.into(),
            artifact_name: artifact_name.unwrap_or_default(),
            artifact,
            completed_at: Some(now_ts()),
        })
        .await
        .is_err()
    {
        warn!("[response] outbound channel full or closed — result dropped");
    }
}

async fn send_hello(tx: &mpsc::Sender<ResponseResult>, agent_id: &str) {
    if tx
        .send(ResponseResult {
            command_id: String::new(),
            agent_id: agent_id.to_string(),
            status: ResultStatus::Heartbeat as i32,
            message: "hello".to_string(),
            artifact_name: String::new(),
            artifact: Vec::new(),
            completed_at: Some(now_ts()),
        })
        .await
        .is_err()
    {
        warn!("[response] outbound channel full or closed — hello dropped");
    }
}

pub fn spawn_response_channel(
    server_addr: String,
    cert_dir: PathBuf,
    agent_id: String,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        let max_backoff = Duration::from_secs(30);

        loop {
            match run_once(&server_addr, &cert_dir, &agent_id, &mut shutdown_rx).await {
                Ok(()) => {
                    info!("[response] channel stopped");
                    return;
                }
                Err(e) => {
                    warn!("[response] channel error: {:#}", e);
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("[response] shutdown requested during backoff");
                            return;
                        }
                        _ = tokio::time::sleep(backoff) => {
                            backoff = std::cmp::min(backoff * 2, max_backoff);
                        }
                    }
                }
            }
        }
    });
}

async fn run_once(
    server_addr: &str,
    cert_dir: &Path,
    agent_id: &str,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> Result<()> {
    let channel = client::create_grpc_channel(server_addr, cert_dir)
        .await
        .context("create_grpc_channel for response")?;

    let mut client = ResponseServiceClient::new(channel)
        .max_decoding_message_size(10 * 1024 * 1024)
        .max_encoding_message_size(10 * 1024 * 1024);

    // Outbound results stream — bounded to avoid unbounded memory growth under flood
    let (tx, rx) = mpsc::channel::<ResponseResult>(256);
    let outbound = tokio_stream::wrappers::ReceiverStream::new(rx);
    let request = Request::new(outbound);

    let mut inbound = client
        .command_stream(request)
        .await
        .context("open CommandStream")?
        .into_inner();

    info!("🛰️  Response channel connected (agent_id={})", agent_id);

    // Let the server learn our agent_id quickly (useful in dev/plaintext and for debugging).
    send_hello(&tx, agent_id).await;

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("[response] shutting down active command stream");
                return Ok(());
            }
            inbound_result = inbound.message() => {
                match inbound_result.transpose() {
                    Some(Ok(cmd)) => {
                        let tx = tx.clone();
                        let agent_id = agent_id.to_string();
                        let server_addr = server_addr.to_string();
                        tokio::spawn(async move {
                            handle_command(tx, agent_id, cmd, server_addr).await;
                        });
                    }
                    Some(Err(e)) => {
                        return Err(anyhow::anyhow!("response inbound stream error: {e}"));
                    }
                    None => {
                        return Err(anyhow::anyhow!("response stream closed"));
                    }
                }
            }
        }
    }
}

async fn handle_command(
    tx: mpsc::Sender<ResponseResult>,
    agent_id: String,
    cmd: ResponseCommand,
    server_addr: String,
) {
    let command_id = cmd.command_id.clone();
    if command_id.is_empty() {
        return;
    }

    let kind = CommandKind::try_from(cmd.kind).unwrap_or(CommandKind::CommandUnknown);
    debug!(
        "[response] cmd received: id={} kind={:?} ip='{}' user='{}' ttl={}s",
        command_id, kind, cmd.ip, cmd.username, cmd.duration_seconds
    );

    send_result(
        &tx,
        &agent_id,
        &command_id,
        ResultStatus::Started,
        "started",
        None,
        Vec::new(),
    )
    .await;

    let res: Result<(Option<String>, Vec<u8>, String)> = match kind {
        CommandKind::BlockIp => block_ip(&cmd.ip, cmd.duration_seconds).await,
        CommandKind::UnblockIp => unblock_ip(&cmd.ip).await,
        CommandKind::DisableUser => disable_user(&cmd.username, cmd.duration_seconds).await,
        CommandKind::EnableUser => enable_user(&cmd.username).await,
        CommandKind::LogoffUser => logoff_user(&cmd.username).await,
        CommandKind::TriageBundle => triage_bundle(&command_id).await,
        CommandKind::IsolateHost => isolate_host(cmd.duration_seconds, &server_addr).await,
        CommandKind::RestoreNetwork => restore_network().await,
        CommandKind::LogoffActiveUser => logoff_active_user().await,
        CommandKind::LockWorkstation => lock_workstation().await,
        CommandKind::Custom => dispatch_custom(&cmd, &server_addr).await,
        _ => Err(anyhow::anyhow!("unsupported command")),
    };

    match res {
        Ok((artifact_name, artifact, message)) => {
            send_result(
                &tx,
                &agent_id,
                &command_id,
                ResultStatus::Succeeded,
                message,
                artifact_name,
                artifact,
            )
            .await;
        }
        Err(e) => {
            error!("[response] cmd failed: id={} err={:#}", command_id, e);
            send_result(
                &tx,
                &agent_id,
                &command_id,
                ResultStatus::Failed,
                format!("{e:#}"),
                None,
                Vec::new(),
            )
            .await;
        }
    }
}

fn parse_server_host_port(server_addr: &str) -> Option<(String, u16)> {
    let mut s = server_addr.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((_, rest)) = s.split_once("://") {
        s = rest;
    }
    if let Some((hostport, _path)) = s.split_once('/') {
        s = hostport;
    }
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    // [ipv6]:port
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let tail = tail.trim();
        let port = if let Some(p) = tail.strip_prefix(':') {
            p.trim().parse::<u16>().ok()?
        } else {
            50051
        };
        return Some((host.to_string(), port));
    }

    // host:port (last ':')
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if !host.trim().is_empty() {
            if let Ok(port) = port_str.trim().parse::<u16>() {
                return Some((host.trim().to_string(), port));
            }
        }
    }

    // host only
    Some((s.to_string(), 50051))
}

async fn dispatch_custom(
    cmd: &ResponseCommand,
    server_addr: &str,
) -> Result<(Option<String>, Vec<u8>, String)> {
    let k = cmd.custom_kind.trim().to_lowercase();
    if k.is_empty() {
        return Err(anyhow::anyhow!("missing custom_kind"));
    }
    match k.as_str() {
        "isolate_host" => isolate_host(cmd.duration_seconds, server_addr).await,
        "restore_network" => restore_network().await,
        "logoff_active_user" => logoff_active_user().await,
        "lock_workstation" => lock_workstation().await,
        _ => Err(anyhow::anyhow!("unsupported custom command '{k}'")),
    }
}

#[cfg(target_os = "windows")]
async fn isolate_host(
    duration_seconds: u32,
    server_addr: &str,
) -> Result<(Option<String>, Vec<u8>, String)> {
    let ttl = duration_seconds as u64;
    let (host, port) = parse_server_host_port(server_addr)
        .ok_or_else(|| anyhow::anyhow!("invalid server_addr"))?;

    // Resolve before isolation policy is applied.
    let mut server_ips: Vec<std::net::IpAddr> = Vec::new();
    if let Ok(iter) = (host.as_str(), port).to_socket_addrs() {
        for sa in iter {
            if !server_ips.contains(&sa.ip()) {
                server_ips.push(sa.ip());
            }
        }
    }

    // Remove any previous allow rules for safety/idempotency.
    let _ = run_capture(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "group=PerceptaHostIsolation",
        ],
    );

    // Apply strict policy: block inbound + outbound.
    run_capture(
        "netsh",
        &[
            "advfirewall",
            "set",
            "allprofiles",
            "firewallpolicy",
            "blockinbound,blockoutbound",
        ],
    )?;

    // Failsafe: allow SIEM server connectivity so we can receive restore commands.
    // Note: if resolution failed, TTL auto-restore still prevents bricking.
    for ip in &server_ips {
        let ip_s = ip.to_string();
        let name = format!("PerceptaAllowSIEM_{}_{}", ip_s.replace(':', "_"), port);
        let remoteip = format!("remoteip={ip_s}");
        let remoteport = format!("remoteport={port}");
        let name_arg = format!("name={name}");
        run_capture(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &name_arg,
                "group=PerceptaHostIsolation",
                "dir=out",
                "action=allow",
                "protocol=TCP",
                &remoteip,
                &remoteport,
                "profile=any",
            ],
        )?;
    }

    if ttl > 0 {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(ttl)).await;
            let _ = restore_network().await;
        });
    }

    Ok((
        None,
        Vec::new(),
        format!(
            "host isolated (ttl={}s, allow_to_siem_ips={})",
            duration_seconds,
            server_ips.len()
        ),
    ))
}

#[cfg(not(target_os = "windows"))]
async fn isolate_host(
    duration_seconds: u32,
    server_addr: &str,
) -> Result<(Option<String>, Vec<u8>, String)> {
    let ttl = duration_seconds as u64;
    let (host, port) = parse_server_host_port(server_addr)
        .ok_or_else(|| anyhow::anyhow!("invalid server_addr"))?;

    // Resolve server IPs before applying isolation.
    let mut server_ips: Vec<std::net::IpAddr> = Vec::new();
    if let Ok(iter) = (host.as_str(), port).to_socket_addrs() {
        for sa in iter {
            if !server_ips.contains(&sa.ip()) {
                server_ips.push(sa.ip());
            }
        }
    }

    // Use a dedicated iptables chain for clean teardown.
    let chain = "PERCEPTA_ISOLATE";

    // Remove any previous isolation (idempotent).
    let _ = run_capture("iptables", &["-D", "INPUT", "-j", chain]);
    let _ = run_capture("iptables", &["-D", "OUTPUT", "-j", chain]);
    let _ = run_capture("iptables", &["-F", chain]);
    let _ = run_capture("iptables", &["-X", chain]);

    // Create chain.
    run_capture("iptables", &["-N", chain])?;

    // Allow loopback.
    run_capture("iptables", &["-A", chain, "-i", "lo", "-j", "ACCEPT"])?;
    run_capture("iptables", &["-A", chain, "-o", "lo", "-j", "ACCEPT"])?;

    // Allow established connections (so we don't break the current gRPC stream).
    run_capture(
        "iptables",
        &[
            "-A",
            chain,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )?;

    // Allow SIEM server connectivity.
    for ip in &server_ips {
        let ip_s = ip.to_string();
        run_capture(
            "iptables",
            &[
                "-A",
                chain,
                "-d",
                &ip_s,
                "-p",
                "tcp",
                "--dport",
                &port.to_string(),
                "-j",
                "ACCEPT",
            ],
        )?;
        run_capture(
            "iptables",
            &[
                "-A",
                chain,
                "-s",
                &ip_s,
                "-p",
                "tcp",
                "--sport",
                &port.to_string(),
                "-j",
                "ACCEPT",
            ],
        )?;
    }

    // Drop everything else.
    run_capture("iptables", &["-A", chain, "-j", "DROP"])?;

    // Insert chain into INPUT and OUTPUT.
    run_capture("iptables", &["-I", "INPUT", "1", "-j", chain])?;
    run_capture("iptables", &["-I", "OUTPUT", "1", "-j", chain])?;

    if ttl > 0 {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(ttl)).await;
            let _ = restore_network().await;
        });
    }

    Ok((
        None,
        Vec::new(),
        format!(
            "host isolated via iptables (ttl={}s, allow_to_siem_ips={})",
            duration_seconds,
            server_ips.len()
        ),
    ))
}

#[cfg(target_os = "windows")]
async fn restore_network() -> Result<(Option<String>, Vec<u8>, String)> {
    // Restore a safe default: block inbound, allow outbound.
    run_capture(
        "netsh",
        &[
            "advfirewall",
            "set",
            "allprofiles",
            "firewallpolicy",
            "blockinbound,allowoutbound",
        ],
    )?;

    // Remove our allow rules.
    let _ = run_capture(
        "netsh",
        &[
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            "group=PerceptaHostIsolation",
        ],
    );

    Ok((None, Vec::new(), "network policy restored".to_string()))
}

#[cfg(not(target_os = "windows"))]
async fn restore_network() -> Result<(Option<String>, Vec<u8>, String)> {
    let chain = "PERCEPTA_ISOLATE";
    // Remove chain references from INPUT/OUTPUT, then flush and delete chain.
    let _ = run_capture("iptables", &["-D", "INPUT", "-j", chain]);
    let _ = run_capture("iptables", &["-D", "OUTPUT", "-j", chain]);
    let _ = run_capture("iptables", &["-F", chain]);
    let _ = run_capture("iptables", &["-X", chain]);
    Ok((
        None,
        Vec::new(),
        "network policy restored (iptables PERCEPTA_ISOLATE chain removed)".to_string(),
    ))
}

#[cfg(target_os = "windows")]
fn run_capture(program: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(program).no_window()
        .args(args)
        .output()
        .with_context(|| format!("exec {program}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "command failed: {} {:?} (status={})\nstdout={}\nstderr={}",
            program,
            args,
            out.status,
            stdout,
            stderr
        ));
    }
    Ok(stdout)
}

#[cfg(not(target_os = "windows"))]
fn run_capture(program: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(program).no_window()
        .args(args)
        .output()
        .with_context(|| format!("exec {program}"))?;

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "command failed: {} {:?} (status={})\nstdout={}\nstderr={}",
            program,
            args,
            out.status,
            stdout,
            stderr
        ));
    }
    Ok(stdout)
}

fn firewall_rule_name_for_ip(ip: &str) -> String {
    // Keep rule name stable so `unblock_ip` can delete it later.
    // Replace characters that may confuse netsh/display.
    let safe = ip
        .trim()
        .replace([':', '.', '/', '\\'], "_")
        .replace(['[', ']', ' '], "");
    format!("PerceptaBlockIp_{safe}")
}

async fn block_ip(ip: &str, duration_seconds: u32) -> Result<(Option<String>, Vec<u8>, String)> {
    let ip = validate_ip(ip)?;
    let rule_name = firewall_rule_name_for_ip(ip);

    #[cfg(target_os = "windows")]
    {
        let _ = run_capture(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={rule_name}"),
            ],
        );
        run_capture(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                "dir=in",
                "action=block",
                &format!("remoteip={ip}"),
            ],
        )?;
        run_capture(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={rule_name}"),
                "dir=out",
                "action=block",
                &format!("remoteip={ip}"),
            ],
        )?;
        if duration_seconds > 0 {
            let rule_name2 = rule_name.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(duration_seconds as u64)).await;
                let _ = run_capture(
                    "netsh",
                    &[
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name={rule_name2}"),
                    ],
                );
            });
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // iptables: block inbound + outbound for this IP.
        // Use comment module to tag rules for clean removal.
        let comment = format!("percepta:{rule_name}");
        // Idempotent: remove existing rules first (ignore errors if absent).
        let _ = run_capture(
            "iptables",
            &[
                "-D",
                "INPUT",
                "-s",
                ip,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "DROP",
            ],
        );
        let _ = run_capture(
            "iptables",
            &[
                "-D",
                "OUTPUT",
                "-d",
                ip,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "DROP",
            ],
        );
        run_capture(
            "iptables",
            &[
                "-A",
                "INPUT",
                "-s",
                ip,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "DROP",
            ],
        )?;
        run_capture(
            "iptables",
            &[
                "-A",
                "OUTPUT",
                "-d",
                ip,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "DROP",
            ],
        )?;
        if duration_seconds > 0 {
            let ip_owned = ip.to_string();
            let comment2 = comment.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(duration_seconds as u64)).await;
                let _ = run_capture(
                    "iptables",
                    &[
                        "-D",
                        "INPUT",
                        "-s",
                        &ip_owned,
                        "-m",
                        "comment",
                        "--comment",
                        &comment2,
                        "-j",
                        "DROP",
                    ],
                );
                let _ = run_capture(
                    "iptables",
                    &[
                        "-D",
                        "OUTPUT",
                        "-d",
                        &ip_owned,
                        "-m",
                        "comment",
                        "--comment",
                        &comment2,
                        "-j",
                        "DROP",
                    ],
                );
            });
        }
    }

    Ok((
        None,
        Vec::new(),
        format!("blocked ip {ip} (rule={rule_name})"),
    ))
}

async fn unblock_ip(ip: &str) -> Result<(Option<String>, Vec<u8>, String)> {
    let ip = validate_ip(ip)?;
    let rule_name = firewall_rule_name_for_ip(ip);
    #[cfg(target_os = "windows")]
    {
        let _ = run_capture(
            "netsh",
            &[
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={rule_name}"),
            ],
        );
    }
    #[cfg(not(target_os = "windows"))]
    {
        let comment = format!("percepta:{rule_name}");
        let _ = run_capture(
            "iptables",
            &[
                "-D",
                "INPUT",
                "-s",
                ip,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "DROP",
            ],
        );
        let _ = run_capture(
            "iptables",
            &[
                "-D",
                "OUTPUT",
                "-d",
                ip,
                "-m",
                "comment",
                "--comment",
                &comment,
                "-j",
                "DROP",
            ],
        );
    }
    Ok((
        None,
        Vec::new(),
        format!("unblocked ip {ip} (rule={rule_name})"),
    ))
}

async fn disable_user(
    username: &str,
    duration_seconds: u32,
) -> Result<(Option<String>, Vec<u8>, String)> {
    let user = validate_username(username)?;
    #[cfg(target_os = "windows")]
    {
        run_capture("net", &["user", user, "/active:no"])?;
        if duration_seconds > 0 {
            let user2 = user.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(duration_seconds as u64)).await;
                let _ = run_capture("net", &["user", &user2, "/active:yes"]);
            });
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Lock the user account via usermod (disallows password login).
        run_capture("usermod", &["--lock", user])?;
        // Expire the account to also block SSH key-based login.
        run_capture("usermod", &["--expiredate", "1", user])?;
        if duration_seconds > 0 {
            let user2 = user.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(duration_seconds as u64)).await;
                let _ = run_capture("usermod", &["--unlock", &user2]);
                let _ = run_capture("usermod", &["--expiredate", "", &user2]);
            });
        }
    }
    Ok((None, Vec::new(), format!("disabled user {user}")))
}

async fn enable_user(username: &str) -> Result<(Option<String>, Vec<u8>, String)> {
    let user = validate_username(username)?;
    #[cfg(target_os = "windows")]
    {
        run_capture("net", &["user", user, "/active:yes"])?;
    }
    #[cfg(not(target_os = "windows"))]
    {
        run_capture("usermod", &["--unlock", user])?;
        // Remove account expiry.
        run_capture("usermod", &["--expiredate", "", user])?;
    }
    Ok((None, Vec::new(), format!("enabled user {user}")))
}

#[cfg(target_os = "windows")]
fn find_session_ids_for_user(query_output: &str, username: &str) -> Vec<String> {
    let want = username.trim().to_lowercase();
    if want.is_empty() {
        return Vec::new();
    }
    let mut ids = Vec::new();
    for line in query_output.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        // Very rough parse of `query user` output; session id is typically the 3rd column.
        // We just search for a numeric token on a line containing the username.
        if !l.to_lowercase().contains(&want) {
            continue;
        }
        for tok in l.split_whitespace() {
            if tok.chars().all(|c| c.is_ascii_digit()) {
                ids.push(tok.to_string());
                break;
            }
        }
    }
    ids
}

async fn logoff_user(username: &str) -> Result<(Option<String>, Vec<u8>, String)> {
    let user = validate_username(username)?;
    #[cfg(target_os = "windows")]
    {
        let out = run_capture("query", &["user"]).context("query user")?;
        let ids = find_session_ids_for_user(&out, user);
        if ids.is_empty() {
            return Err(anyhow::anyhow!("no active session found for user '{user}'"));
        }
        for id in ids {
            let _ = run_capture("logoff", &[&id]);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Terminate all processes for the user (kills their sessions).
        // loginctl terminate-user is preferred (systemd), fallback to pkill.
        let loginctl_ok = run_capture("loginctl", &["terminate-user", user]).is_ok();
        if !loginctl_ok {
            run_capture("pkill", &["-u", user])
                .context("failed to terminate user sessions (tried loginctl + pkill)")?;
        }
    }
    Ok((None, Vec::new(), format!("logoff requested for {user}")))
}

#[cfg(target_os = "windows")]
fn find_active_session_ids(query_output: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in query_output.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        // Prefer the active session line.
        // Common patterns: ">username ... <id> Active" or "username ... <id> Active".
        let is_active = l.to_lowercase().contains(" active");
        if !is_active {
            continue;
        }
        for tok in l.split_whitespace() {
            if tok.chars().all(|c| c.is_ascii_digit()) {
                ids.push(tok.to_string());
                break;
            }
        }
    }
    ids
}

async fn logoff_active_user() -> Result<(Option<String>, Vec<u8>, String)> {
    #[cfg(target_os = "windows")]
    {
        let out = run_capture("query", &["user"]).context("query user")?;
        let ids = find_active_session_ids(&out);
        if ids.is_empty() {
            return Err(anyhow::anyhow!("no active interactive session found"));
        }
        for id in &ids {
            let _ = run_capture("logoff", &[id]);
        }
        return Ok((
            None,
            Vec::new(),
            format!("logoff requested for active session(s): {}", ids.join(",")),
        ));
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Terminate all graphical/TTY sessions via loginctl.
        // List sessions, parse IDs, terminate each.
        let output = run_capture("loginctl", &["list-sessions", "--no-legend"])
            .context("loginctl list-sessions")?;
        let mut terminated = Vec::new();
        for line in output.lines() {
            let session_id = line.split_whitespace().next().unwrap_or("");
            if session_id.is_empty() || !session_id.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let _ = run_capture("loginctl", &["terminate-session", session_id]);
            terminated.push(session_id.to_string());
        }
        if terminated.is_empty() {
            return Err(anyhow::anyhow!("no active loginctl sessions found"));
        }
        Ok((
            None,
            Vec::new(),
            format!("logoff requested for session(s): {}", terminated.join(",")),
        ))
    }
}

async fn lock_workstation() -> Result<(Option<String>, Vec<u8>, String)> {
    #[cfg(target_os = "windows")]
    {
        run_capture("rundll32.exe", &["user32.dll,LockWorkStation"]).context("LockWorkStation")?;
        return Ok((None, Vec::new(), "workstation locked".to_string()));
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Lock all sessions via loginctl (systemd).
        run_capture("loginctl", &["lock-sessions"]).context("loginctl lock-sessions")?;
        Ok((
            None,
            Vec::new(),
            "all sessions locked via loginctl".to_string(),
        ))
    }
}

async fn triage_bundle(_command_id: &str) -> Result<(Option<String>, Vec<u8>, String)> {
    #[cfg(not(target_os = "windows"))]
    {
        use std::io::Write;
        use zip::write::FileOptions;

        let command_id = _command_id;

        let mut items: Vec<(&str, Vec<u8>)> = Vec::new();

        let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
        if !os_release.trim().is_empty() {
            items.push(("os-release.txt", os_release.into_bytes()));
        }

        let capture_txt = |program: &str, args: &[&str]| -> Vec<u8> {
            match run_capture(program, args) {
                Ok(s) => s.into_bytes(),
                Err(e) => format!("{e:#}\n").into_bytes(),
            }
        };

        items.push(("uname.txt", capture_txt("uname", &["-a"])));
        items.push(("id.txt", capture_txt("id", &[])));
        items.push(("who.txt", capture_txt("who", &[])));
        items.push(("uptime.txt", capture_txt("uptime", &[])));
        items.push(("ps_aux.txt", capture_txt("ps", &["aux"])));

        // Network snapshot (best-effort fallbacks)
        let ss_out = run_capture("ss", &["-tulpn"]);
        match ss_out {
            Ok(s) => items.push(("ss_tulpn.txt", s.into_bytes())),
            Err(_) => items.push(("netstat_tulpn.txt", capture_txt("netstat", &["-tulpn"]))),
        }
        let ip_addr = run_capture("ip", &["addr"]);
        match ip_addr {
            Ok(s) => items.push(("ip_addr.txt", s.into_bytes())),
            Err(_) => items.push(("ifconfig_a.txt", capture_txt("ifconfig", &["-a"]))),
        }
        items.push(("ip_route.txt", capture_txt("ip", &["route"])));

        // Filesystem snapshot
        items.push(("df_h.txt", capture_txt("df", &["-h"])));
        items.push(("mount.txt", capture_txt("mount", &[])));

        // Journal tail (may require privileges depending on distro)
        items.push((
            "journalctl_tail.txt",
            capture_txt("journalctl", &["-n", "500", "--no-pager"]),
        ));

        // Zip into memory
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            for (name, bytes) in items {
                zip.start_file(name, opts)?;
                zip.write_all(&bytes)?;
            }

            let _cursor = zip.finish()?;
        }

        let filename = format!("percepta_triage_{command_id}.zip");
        Ok((Some(filename), buf, "triage bundle collected".to_string()))
    }

    #[cfg(target_os = "windows")]
    {
        use std::io::Write;
        use zip::write::FileOptions;

        let command_id = _command_id;

        let tmp = tempfile::tempdir().context("tempdir")?;
        let base = tmp.path();
        let security = base.join("Security.evtx");
        let system = base.join("System.evtx");
        let application = base.join("Application.evtx");
        let ipcfg = base.join("ipconfig_all.txt");

        // Export core logs (best-effort)
        let _ = run_capture(
            "wevtutil",
            &["epl", "Security", security.to_string_lossy().as_ref()],
        );
        let _ = run_capture(
            "wevtutil",
            &["epl", "System", system.to_string_lossy().as_ref()],
        );
        let _ = run_capture(
            "wevtutil",
            &["epl", "Application", application.to_string_lossy().as_ref()],
        );

        // Capture ipconfig
        let ip_out = run_capture("ipconfig", &["/all"]).unwrap_or_else(|e| format!("{e:#}"));
        std::fs::write(&ipcfg, ip_out).ok();

        // Zip into memory
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor = std::io::Cursor::new(&mut buf);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

            for p in [&security, &system, &application, &ipcfg] {
                if !p.exists() {
                    continue;
                }
                let name = p
                    .file_name()
                    .and_then(|s: &std::ffi::OsStr| s.to_str())
                    .unwrap_or("artifact.bin");
                zip.start_file(name, opts)?;
                let bytes = std::fs::read(p).unwrap_or_default();
                zip.write_all(&bytes)?;
            }

            let _cursor = zip.finish()?;
        }

        let filename = format!("percepta_triage_{command_id}.zip");
        return Ok((Some(filename), buf, "triage bundle collected".to_string()));
    }
}
