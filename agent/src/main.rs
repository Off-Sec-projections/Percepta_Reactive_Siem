//!
//! A production-ready agent for collecting system events and forwarding them to
//! the Percepta SIEM server via gRPC. Supports both Windows Event Log collection
//! and simulation mode for testing on non-Windows systems.
//!
//! ## Environment Variables
//!
//! * `PERCEPTA_SERVER` (required): Server address in `host:port` format
//! * `PERCEPTA_CERT_DIR` (optional): Certificate directory path
//!   - Windows default: `C:\ProgramData\percepta_agent\certs`
//!   - Linux default: `./certs`
//! * `PERCEPTA_OUT` (optional): Outgoing files directory
//!   - Windows default: `C:\ProgramData\percepta_agent\outgoing`
//!   - Linux default: `./outgoing`
//! * `PERCEPTA_AGENT_ID` (optional): Agent identifier (auto-generated if not set)
//! * `PERCEPTA_ENROLL_ENDPOINT` (optional): Custom enrollment base URL (not commonly used; enrollment typically uses `--server`)
//!   - Default: `http://localhost:8080`
//! * `PERCEPTA_LOG_LEVEL` (optional): Logging level (default: `info`)
//!
//! ## Usage
//!
//! ```bash
//! # Normal operation (Windows Event Log collection)
//! percepta-agent
//!
//! # Simulation mode (dummy event generation)
//! percepta-agent --simulate
//! ```

use anyhow::{anyhow, bail, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::{
    env,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs,
    sync::{broadcast, mpsc},
    time::{interval, sleep, timeout, Instant},
};
use tracing::{debug, error, info, level_filters::LevelFilter, warn};
use tracing_subscriber::{fmt, EnvFilter};
use uuid::Uuid;

use percepta_agent::config_store;
use percepta_agent::identity;

// Generated protobuf definitions
pub mod percepta {
    tonic::include_proto!("percepta.siem.ingestion.v1");
}

// Application modules
mod client;
mod collector;
mod files;
mod system_info;
mod tls;
mod windows_service;

#[cfg(all(windows, target_os = "windows"))]
mod windows_eventlog;

#[cfg(target_os = "linux")]
mod linux_logs;

use percepta::Event;

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
struct Config {
    server_addr: String,
    cert_dir: PathBuf,
    outgoing_dir: PathBuf,
    agent_id: String,
    #[allow(dead_code)] // Replaced by --server arg during enrollment
    enroll_endpoint: String,
    log_level: LevelFilter,
    simulate_mode: bool,
}

impl Config {
    /// Load configuration from environment variables with platform-specific defaults
    async fn load(simulate_override: bool) -> Result<Self> {
        // Try to get server address from environment, or discover automatically
        let server_addr_raw = match env::var("PERCEPTA_SERVER") {
            Ok(addr) if !addr.is_empty() => {
                info!("🔌 Using server address from PERCEPTA_SERVER: {}", addr);
                addr
            }
            _ => {
                // Try to discover server automatically
                info!("🔍 PERCEPTA_SERVER not set, attempting automatic discovery via mDNS...");
                Self::discover_server().await.context(
                    "Failed to discover server automatically. Please set PERCEPTA_SERVER.",
                )?
            }
        };

        // Normalize to a gRPC address (host:port). This intentionally accepts common
        // inputs like enrollment URLs (http://host:8080) and converts them to host:50051.
        let server_addr = config_store::normalize_grpc_server_from_enroll_arg(&server_addr_raw)
            .ok_or_else(|| anyhow!("PERCEPTA_SERVER was empty or invalid"))?;
        if server_addr != server_addr_raw {
            warn!(
                "Normalized PERCEPTA_SERVER '{}' -> '{}' for gRPC connection",
                server_addr_raw, server_addr
            );
        }

        // Hard validation: at this point we must have host:port.
        if !server_addr.contains(':') {
            bail!(
                "PERCEPTA_SERVER must resolve to 'host:port' for gRPC, got: '{}'",
                server_addr
            );
        }

        // Platform-specific default paths
        let (default_cert_dir, default_out_dir) = if cfg!(windows) {
            (
                r"C:\ProgramData\percepta_agent\certs",
                r"C:\ProgramData\percepta_agent\outgoing",
            )
        } else {
            ("./certs", "./outgoing")
        };

        let cert_dir = PathBuf::from(
            env::var("PERCEPTA_CERT_DIR").unwrap_or_else(|_| default_cert_dir.to_string()),
        );

        let outgoing_dir =
            PathBuf::from(env::var("PERCEPTA_OUT").unwrap_or_else(|_| default_out_dir.to_string()));

        // NOTE: `enroll_endpoint` is kept for backwards compatibility/config symmetry.
        // Actual enrollment uses CLI args: `--enroll <OTK> --server <base-url-or-host>`.
        let enroll_endpoint = env::var("PERCEPTA_ENROLL_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        // Parse log level
        let log_level_str = env::var("PERCEPTA_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
        let log_level = match log_level_str.to_lowercase().as_str() {
            "trace" => LevelFilter::TRACE,
            "debug" => LevelFilter::DEBUG,
            "info" => LevelFilter::INFO,
            "warn" => LevelFilter::WARN,
            "error" => LevelFilter::ERROR,
            _ => {
                eprintln!(
                    "Invalid PERCEPTA_LOG_LEVEL '{}', using 'info'",
                    log_level_str
                );
                LevelFilter::INFO
            }
        };

        // Load or generate agent ID
        let agent_id_path = cert_dir.join("agent_id.txt");
        let agent_id = if let Ok(existing_id) = env::var("PERCEPTA_AGENT_ID") {
            if !existing_id.is_empty() {
                existing_id
            } else {
                Self::load_or_generate_agent_id(&agent_id_path)?
            }
        } else {
            Self::load_or_generate_agent_id(&agent_id_path)?
        };

        // Simulation mode OFF by default - use real log collection
        // Only enable with explicit --simulate flag
        let simulate_mode = simulate_override;

        Ok(Config {
            server_addr,
            cert_dir,
            outgoing_dir,
            agent_id,
            enroll_endpoint,
            log_level,
            simulate_mode,
        })
    }

    /// Load existing agent ID from file or generate a new one
    fn load_or_generate_agent_id(agent_id_path: &Path) -> Result<String> {
        if agent_id_path.exists() {
            let content =
                std::fs::read_to_string(agent_id_path).context("Failed to read agent_id.txt")?;
            let agent_id = content.trim().to_string();
            if !agent_id.is_empty() {
                return Ok(agent_id);
            }
        }

        // Generate new agent ID
        let hostname = hostname::get()
            .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
            .to_string_lossy()
            .to_string();
        let uuid = Uuid::new_v4();
        let agent_id = format!("{}-{}", hostname, uuid);

        info!("Generated new agent ID: {}", agent_id);
        Ok(agent_id)
    }

    /// Save agent ID to file (will be called after cert directory is created)
    async fn save_agent_id(&self) -> Result<()> {
        let agent_id_path = self.cert_dir.join("agent_id.txt");
        fs::write(&agent_id_path, &self.agent_id)
            .await
            .context("Failed to save agent_id.txt")?;
        Ok(())
    }

    /// Attempt to discover the Percepta SIEM server automatically via mDNS.
    async fn discover_server() -> Result<String> {
        let service_type = "_percepta-siem._tcp.local.";
        let mdns = ServiceDaemon::new().context("Failed to create mDNS daemon")?;
        let receiver = mdns
            .browse(service_type)
            .context("Failed to browse for mDNS services")?;

        info!("Browsing for mDNS service: {}", service_type);

        let discovery_timeout = Duration::from_secs(5);
        let start_time = Instant::now();

        while start_time.elapsed() < discovery_timeout {
            match timeout(
                discovery_timeout - start_time.elapsed(),
                receiver.recv_async(),
            )
            .await
            {
                Ok(Ok(ServiceEvent::ServiceResolved(info))) => {
                    let addr =
                        info.get_addresses().iter().next().ok_or_else(|| {
                            anyhow!("mDNS service resolved without an IP address")
                        })?;
                    let port = info.get_port();
                    let server_addr = format!("{}:{}", addr, port);
                    info!("✅ Discovered server at: {}", server_addr);
                    return Ok(server_addr);
                }
                Ok(Ok(_)) => {
                    // Ignore other service events (like ServiceFound, ServiceRemoved)
                    continue;
                }
                Ok(Err(e)) => {
                    warn!("mDNS receiver error: {}", e);
                    break;
                }
                Err(_) => {
                    // Timeout
                    break;
                }
            }
        }

        bail!(
            "mDNS discovery timed out after {} seconds. No Percepta SIEM server found.",
            discovery_timeout.as_secs()
        )
    }
}

/// Exponential backoff state for retry logic
struct BackoffState {
    current_delay: Duration,
    max_delay: Duration,
}

impl BackoffState {
    fn new() -> Self {
        Self {
            current_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
        }
    }

    async fn wait_and_increase(&mut self) {
        sleep(self.current_delay).await;
        self.current_delay = std::cmp::min(self.current_delay * 2, self.max_delay);
    }

    fn reset(&mut self) {
        self.current_delay = Duration::from_secs(1);
    }
}

/// Main application entry point
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let _simulate_mode = args.contains(&"--simulate".to_string());

    // Check for service management commands
    if args.contains(&"--install-service".to_string()) {
        windows_service::install_service()?;
        return Ok(());
    }

    if args.contains(&"--uninstall-service".to_string()) {
        windows_service::uninstall_service()?;
        return Ok(());
    }

    // Check if running as Windows service
    let is_service = args.contains(&"--service".to_string());

    if is_service {
        // Run as Windows service
        windows_service::run_as_service(|| async { run_agent_main().await }).await
    } else {
        // Run as regular application
        run_agent_main().await
    }
}

/// Main agent logic (separated for service support)
async fn run_agent_main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let simulate_mode = args.contains(&"--simulate".to_string());
    let is_service = args.contains(&"--service".to_string());

    // If user passed --enroll, handle enrollment first (before full config load)
    if let Some(enroll_pos) = args.iter().position(|arg| arg == "--enroll") {
        let otk = args
            .get(enroll_pos + 1)
            .context("Missing OTK after --enroll")?
            .to_string();
        let server_pos = args
            .iter()
            .position(|arg| arg == "--server")
            .context("Missing --server argument for enrollment")?;
        let server_addr = args
            .get(server_pos + 1)
            .context("Missing server URL after --server")?
            .to_string();

        // Normalize enrollment base URL:
        // - If caller passed an HTTP(S) URL already, use it as-is.
        // - If caller passed a bare host or host:port (typically gRPC 50051), convert to http://host:8080
        let enroll_base =
            if server_addr.starts_with("http://") || server_addr.starts_with("https://") {
                server_addr.clone()
            } else {
                // Extract host portion before ':' if present
                let host = server_addr.split(':').next().unwrap_or(&server_addr);
                format!("http://{}:8080", host)
            };

        println!("Attempting enrollment with OTK to server: {}", enroll_base);

        // Determine cert and outgoing dirs (respect env vars if set)
        let default_cert_dir = if cfg!(windows) {
            r"C:\ProgramData\percepta_agent\certs".to_string()
        } else {
            "./certs".to_string()
        };
        let default_out_dir = if cfg!(windows) {
            r"C:\ProgramData\percepta_agent\outgoing".to_string()
        } else {
            "./outgoing".to_string()
        };

        let cert_dir = PathBuf::from(env::var("PERCEPTA_CERT_DIR").unwrap_or(default_cert_dir));
        let outgoing_dir = PathBuf::from(env::var("PERCEPTA_OUT").unwrap_or(default_out_dir));

        // Ensure directories exist
        files::init(&outgoing_dir).await?;
        if !cert_dir.exists() {
            fs::create_dir_all(&cert_dir)
                .await
                .context("Failed to create cert dir for enrollment")?;
        }

        // Determine or generate agent_id.
        // If PERCEPTA_AGENT_ID is explicitly set, honor it; otherwise use stable identity.json.
        let agent_id = match env::var("PERCEPTA_AGENT_ID") {
            Ok(id) if !id.trim().is_empty() => id,
            _ => identity::load_or_create(&cert_dir).await?.agent_id,
        };

        // Attempt enrollment using normalized enrollment base URL
        match tls::enroll_with_otk(&enroll_base, &otk, &agent_id, &cert_dir).await {
            Ok(_) => {
                println!("Enrollment successful!");

                // Persist server for future runs (service/autostart) so the agent can connect
                // without requiring PERCEPTA_SERVER env var.
                if let Some(grpc) = config_store::normalize_grpc_server_from_enroll_arg(&server_addr)
                {
                    let _ = config_store::set_server_addr(&grpc);
                }

                return Ok(());
            }
            Err(e) => {
                // Provide extra context to help diagnose common mistakes
                bail!(
                    "Enrollment failed: {:#}. Note: --server for enrollment should point to the web port (http://host:8080). \
If you passed a gRPC address like host:50051, we automatically converted it to http://host:8080.",
                    e
                );
            }
        }
    }

    // If user passed --renew, request a certificate renewal and optionally poll for approval.
    if args.iter().any(|a| a == "--renew") {
        let server_pos = args
            .iter()
            .position(|arg| arg == "--server")
            .context("Missing --server argument for renewal")?;
        let server_addr = args
            .get(server_pos + 1)
            .context("Missing server URL after --server")?
            .to_string();

        let renew_base =
            if server_addr.starts_with("http://") || server_addr.starts_with("https://") {
                server_addr.clone()
            } else {
                let host = server_addr.split(':').next().unwrap_or(&server_addr);
                format!("http://{}:8080", host)
            };

        println!("Requesting certificate renewal via: {}", renew_base);

        let default_cert_dir = if cfg!(windows) {
            r"C:\ProgramData\percepta_agent\certs".to_string()
        } else {
            "./certs".to_string()
        };
        let cert_dir = PathBuf::from(env::var("PERCEPTA_CERT_DIR").unwrap_or(default_cert_dir));
        if !cert_dir.exists() {
            fs::create_dir_all(&cert_dir)
                .await
                .context("Failed to create cert dir for renewal")?;
        }

        let agent_id = match env::var("PERCEPTA_AGENT_ID") {
            Ok(id) if !id.trim().is_empty() => id,
            _ => identity::load_or_create(&cert_dir).await?.agent_id,
        };

        let pickup_token = tls::request_certificate_renewal(&renew_base, &agent_id, &cert_dir)
            .await
            .context("Failed to create renewal request")?;

        // Persist token so an operator can re-run pickup later if desired.
        let token_path = cert_dir.join("renewal_token.txt");
        let _ = fs::write(&token_path, &pickup_token).await;

        println!("Renewal requested for agent_id={}", agent_id);
        println!("Pickup token saved at: {}", token_path.display());
        println!("Waiting for admin approval...");

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10 * 60);
        loop {
            if tokio::time::Instant::now() > deadline {
                println!("Timed out waiting for approval. You can rerun --renew later to retry pickup.");
                return Ok(());
            }

            match tls::pickup_certificate_renewal(&renew_base, &cert_dir, &pickup_token).await {
                Ok(true) => {
                    println!("✅ Renewal installed successfully.");
                    let _ = fs::remove_file(&token_path).await;
                    return Ok(());
                }
                Ok(false) => {
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => {
                    bail!("Renewal pickup failed: {:#}", e);
                }
            }
        }
    }

    // Load configuration (normal startup)
    // If a --server CLI argument was provided (e.g. when launched from the GUI), honor it
    if let Some(pos) = args.iter().position(|arg| arg == "--server") {
        if let Some(addr) = args.get(pos + 1) {
            // Set PERCEPTA_SERVER so Config::load picks it up. This avoids changing many call-sites.
            env::set_var("PERCEPTA_SERVER", addr);
            info!("Using server from CLI --server: {}", addr);
        }
    }

    // If PERCEPTA_SERVER is still not set, try persisted config.json.
    let server_env = env::var("PERCEPTA_SERVER").ok().unwrap_or_default();
    if server_env.trim().is_empty() {
        if let Some(addr) = config_store::load_server_addr() {
            env::set_var("PERCEPTA_SERVER", &addr);
            info!(
                "Using server from config.json ({}): {}",
                config_store::default_config_path().display(),
                addr
            );
        }
    }

    let mut config = Config::load(simulate_mode)
        .await
        .context("Failed to load configuration")?;

    // Initialize structured logging
    let filter = EnvFilter::from_default_env().add_directive(config.log_level.into());

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .init();

    // Ensure directories exist with secure permissions before finalizing identity.
    // This keeps identity.json and agent_id.txt in the secure cert directory.
    create_secure_directories(&config)
        .await
        .context("Failed to create required directories")?;

    // Finalize stable identity-based agent_id unless explicitly overridden.
    if env::var("PERCEPTA_AGENT_ID").ok().unwrap_or_default().trim().is_empty() {
        let ident = identity::load_or_create(&config.cert_dir).await?;
        config.agent_id = ident.agent_id;
    }

    // Show startup information
    println!("🚀 Percepta SIEM Agent v{}", env!("CARGO_PKG_VERSION"));
    println!("📋 Configuration:");
    println!("   Server: {}", config.server_addr);
    println!("   Agent ID: {}", config.agent_id);
    println!("   Simulate Mode: {}", config.simulate_mode);
    println!("   Service Mode: {}", is_service);
    println!("");

    info!(
        "Starting Percepta SIEM Agent v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!(
        "Configuration: server={}, agent_id={}, simulate={}",
        config.server_addr, config.agent_id, config.simulate_mode
    );

    // Initialize file system for buffering
    files::init(&config.outgoing_dir).await?;

    // Save agent ID to file
    config
        .save_agent_id()
        .await
        .context("Failed to save agent ID")?;

    // Setup graceful shutdown
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    tokio::spawn(async move {
        setup_signal_handlers(shutdown_tx_clone).await;
    });

    // Run main application loop
    println!("🔄 Starting agent loop...");
    if let Err(e) = run_agent(config, shutdown_rx).await {
        println!("❌ Agent failed: {:#}", e);
        error!("Agent failed: {:#}", e);

        if !is_service {
            println!("Press Enter to exit...");
            let _ = std::io::stdin().read_line(&mut String::new());
        }

        std::process::exit(1);
    }

    println!("✅ Percepta SIEM Agent shutdown complete");
    info!("Percepta SIEM Agent shutdown complete");

    if !is_service {
        println!("Press Enter to exit...");
        let _ = std::io::stdin().read_line(&mut String::new());
    }

    Ok(())
}

/// Create required directories with secure permissions
async fn create_secure_directories(config: &Config) -> Result<()> {
    for dir in [&config.cert_dir, &config.outgoing_dir] {
        if !dir.exists() {
            fs::create_dir_all(dir)
                .await
                .with_context(|| format!("Failed to create directory: {}", dir.display()))?;
            info!("Created directory: {}", dir.display());
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(dir).await?;
            let mut perms = metadata.permissions();
            // Owner read/write/execute only
            if perms.mode() & 0o077 != 0 {
                warn!(
                    "Directory {} has permissive mode {:o}; tightening to 700",
                    dir.display(),
                    perms.mode()
                );
            }
            perms.set_mode(0o700);
            fs::set_permissions(dir, perms).await?;
        }
    }
    Ok(())
}

/// Setup signal handlers for graceful shutdown
async fn setup_signal_handlers(shutdown_tx: broadcast::Sender<()>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal as unix_signal, SignalKind};
        let sigint_res = unix_signal(SignalKind::interrupt());
        let sigterm_res = unix_signal(SignalKind::terminate());

        match (sigint_res, sigterm_res) {
            (Ok(mut sigint), Ok(mut sigterm)) => {
                tokio::select! {
                    _ = sigint.recv() => {
                        info!("Received SIGINT, initiating graceful shutdown");
                    }
                    _ = sigterm.recv() => {
                        info!("Received SIGTERM, initiating graceful shutdown");
                    }
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                warn!("Failed to setup signal handlers: {}", e);
            }
        }
    }

    #[cfg(windows)]
    {
        // For Windows service, check for service stop request
        loop {
            if windows_service::is_service_stop_requested() {
                info!("Windows service stop requested, initiating graceful shutdown");
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    let _ = shutdown_tx.send(());
}

/// Main agent runtime loop
async fn run_agent(config: Config, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
    let config = Arc::new(config);

    // Initialize components
    let files_handler = files::FilesHandler::new(config.outgoing_dir.clone())?;
    let mut backoff = BackoffState::new();

    // Event channels
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Vec<Event>>();

    loop {
        // Attempt to establish connection with retry
        println!("🔍 Attempting to connect to server: {}", config.server_addr);
        let client_handle = loop {
            match client::connect_and_stream(
                &config.server_addr,
                &config.cert_dir,
                &config.agent_id,
            )
            .await
            {
                Ok(handle) => {
                    println!("✅ Successfully connected to server!");
                    info!("Successfully connected to server");
                    backoff.reset();
                    break handle;
                }
                Err(e) => {
                    println!("⚠️ Failed to connect to server: {:#}", e);
                    println!(
                        "🔄 Retrying in {} seconds...",
                        backoff.current_delay.as_secs()
                    );
                    warn!("Failed to connect to server: {:#}", e);
                    tokio::select! {
                        _ = shutdown_rx.recv() => return Ok(()),
                        _ = backoff.wait_and_increase() => continue,
                    }
                }
            }
        };

        // --- Start background tasks ---
        println!("📊 Starting event collection...");
        let collector_handle = {
            let collector_config = config.clone();
            let event_tx_clone = event_tx.clone();
            tokio::spawn(async move {
                collector::collect_loop(
                    collector_config.simulate_mode,
                    collector_config.agent_id.clone(),
                    collector_config.cert_dir.clone(),
                    event_tx_clone,
                )
                .await
            })
        };

        let health_handle = {
            let handle = client_handle.clone();
            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    info!(
                        "[Health] Connection Status: connected={}, id={}",
                        handle.is_connected(),
                        handle.connection_id()
                    );
                    let failed = handle.drain_failed().await;
                    if !failed.is_empty() {
                        error!(
                            "[Health] {} events failed permanently after all retries. Hashes: {:?}",
                            failed.len(),
                            failed
                        );
                    }
                }
            })
        };

        let shipper_handle = {
            let handle = client_handle.clone();
            let outgoing_dir = config.outgoing_dir.clone();
            tokio::spawn(async move {
                // Faster backlog drain after reconnect.
                // Env: PERCEPTA_SHIPPER_INTERVAL_MS (default 5000, min 1000, max 60000)
                let shipper_interval = {
                    let raw = std::env::var("PERCEPTA_SHIPPER_INTERVAL_MS").ok();
                    let ms = raw
                        .as_deref()
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .unwrap_or(5000);
                    Duration::from_millis(ms.clamp(1000, 60_000))
                };
                let mut interval = interval(shipper_interval);
                let archives_dir = outgoing_dir.join("archives");

                loop {
                    interval.tick().await;
                    if !handle.is_connected() {
                        debug!("[Shipper] Paused: client is not connected.");
                        continue;
                    }

                    debug!("[Shipper] Checking for rotated archive files to send...");
                    let mut read_dir = match fs::read_dir(&archives_dir).await {
                        Ok(rd) => rd,
                        Err(e) => {
                            error!("[Shipper] Failed to read archives directory: {}", e);
                            continue;
                        }
                    };

                    // Send a small bounded number per tick to drain backlog without
                    // monopolizing the runtime.
                    let mut sent_this_tick = 0usize;
                    const MAX_ARCHIVES_PER_TICK: usize = 5;

                    while let Ok(Some(entry)) = read_dir.next_entry().await {
                        if sent_this_tick >= MAX_ARCHIVES_PER_TICK {
                            break;
                        }
                        let path = entry.path();
                        if path.is_file()
                            && path
                                .file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or("")
                                .starts_with("rotated_")
                        {
                            info!("[Shipper] Found archive file to send: {}", path.display());

                            let content = match fs::read_to_string(&path).await {
                                Ok(c) => c,
                                Err(e) => {
                                    error!(
                                        "[Shipper] Failed to read archive file {}: {}",
                                        path.display(),
                                        e
                                    );
                                    continue;
                                }
                            };

                            let events: Vec<Event> = content
                                .lines()
                                .filter(|line| !line.trim().is_empty())
                                .filter_map(|line| serde_json::from_str(line).ok())
                                .collect();

                            if events.is_empty() {
                                warn!(
                                    "[Shipper] Archive file {} was empty or unreadable, deleting.",
                                    path.display()
                                );
                                let _ = fs::remove_file(&path).await;
                                continue;
                            }

                            if let Err(e) = handle.send_events(events).await {
                                error!(
                                    "[Shipper] Failed to send archive {}: {}. Will retry later.",
                                    path.display(),
                                    e
                                );
                            } else {
                                info!(
                                    "[Shipper] Successfully sent and deleted archive file: {}",
                                    path.display()
                                );
                                let _ = fs::remove_file(&path).await;
                                sent_this_tick += 1;
                            }
                        }
                    }
                }
            })
        };

        // Main coordination loop
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, cleaning up...");
                    collector_handle.abort();
                    health_handle.abort();
                    shipper_handle.abort();

                    info!("Shutting down gRPC client...");
                    if let Err(e) = client_handle.shutdown().await {
                        warn!("Error during client shutdown: {:#}", e);
                    }

                    // Final flush attempt
                    if let Err(e) = flush_final_events(&files_handler).await {
                        warn!("Error during final flush: {:#}", e);
                    }

                    return Ok(());
                }

                Some(events) = event_rx.recv() => {
                    if events.is_empty() {
                        continue;
                    }

                    // Primary path: send events immediately when connected.
                    // If sending fails, fall back to buffering and force reconnect.
                    let events_for_buffer = events.clone();
                    match client_handle.send_events(events).await {
                        Ok(()) => {
                            debug!("Sent {} collected events to server.", events_for_buffer.len());
                        }
                        Err(e) => {
                            error!("Failed to send events to server: {:#}. Buffering and reconnecting...", e);
                            if let Err(buf_e) = files_handler.write_archive(&events_for_buffer).await {
                                error!("Failed to write events to archive buffer after send failure: {:#}", buf_e);
                            }
                            // Rotate so the shipper can see it on next connection.
                            if let Err(flush_e) = files_handler.flush_archive().await {
                                warn!("Failed to rotate archive after send failure: {:#}", flush_e);
                            }
                            collector_handle.abort();
                            health_handle.abort();
                            shipper_handle.abort();
                            break;
                        }
                    }
                }

                else => {
                    warn!("Connection lost, attempting to reconnect");
                    collector_handle.abort();
                    health_handle.abort();
                    shipper_handle.abort();
                    break;
                }
            }
        }
    }
}

/// Flush any remaining events during shutdown
async fn flush_final_events(files_handler: &files::FilesHandler) -> Result<()> {
    info!("Flushing final events from archive...");
    // The new design doesn't require a complex flush. The shipper will handle rotated files on next startup.
    // We can, however, trigger one last rotation to ensure the current archive file is queued.
    if let Err(e) = files_handler.flush_archive().await {
        warn!("Failed to flush current archive on shutdown: {}", e);
    }
    Ok(())
}
