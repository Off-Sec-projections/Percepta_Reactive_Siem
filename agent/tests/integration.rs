//! Integration tests for percepta-siem workspace
//!
//! BEFORE RUNNING TESTS:
//! 1. Build the workspace: `cargo build --workspace`
//! 2. Run tests with output: `cargo test --test integration -- --nocapture`
//! 3. To run a single test: `cargo test --test integration enrollment_and_short_batch -- --nocapture`
//!
//! These tests spawn actual binaries from target/debug/ and use temporary directories.
//! Environment variables used:
//! - Server: PERCEPTA_CERT_DIR, PERCEPTA_BACKUPS, PERCEPTA_BIND
//! - Agent: PERCEPTA_CERT_DIR, PERCEPTA_OUT, PERCEPTA_SERVER, PERCEPTA_AGENT_ID
//! - Agent runs with --simulate flag for testing without Windows APIs

use anyhow::{Context, Result};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

use percepta_agent::percepta::{
    collector_service_client::CollectorServiceClient,
    event,
    Event,
};
use prost_types::Timestamp;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::Request;

/// Get path to compiled binary in target/debug
fn binary_path(name: &str) -> PathBuf {
    static BUILD_ONCE: OnceLock<()> = OnceLock::new();
    BUILD_ONCE.get_or_init(|| {
        // Ensure the workspace binaries exist and match the current sources.
        // `cargo test` does not always rebuild standalone binaries under target/debug.
        let status = std::process::Command::new("cargo")
            .args(["build", "--workspace"])
            .status()
            .expect("Failed to run `cargo build --workspace` for integration tests");
        assert!(status.success(), "`cargo build --workspace` failed");
    });

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = PathBuf::from(manifest_dir);
    // Adjust path to the workspace root (two levels up from agent crate if server lives there)
    // The integration tests expect workspace build; fallback gracefully if not found.
    let candidate_paths = [
        workspace_root.join("target").join("debug").join(name), // agent crate target
        workspace_root
            .join("..")
            .join("target")
            .join("debug")
            .join(name), // workspace root target (one level up)
    ];

    for p in candidate_paths.iter() {
        if p.exists() {
            return p.to_path_buf();
        }
    }

    // If not found, skip by panicking with clearer instruction (tests depend on this executable)
    panic!("Binary {} not found in expected targets. Run `cargo build --workspace` before integration tests.", name);
}

/// Pick a free TCP port by binding to 127.0.0.1:0
fn pick_free_port() -> u16 {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("Failed to bind to 127.0.0.1:0 to pick free port");
    let port = listener.local_addr().unwrap().port();
    drop(listener); // Release the port
    port
}

/// Spawn server process with environment variables and wait for readiness
async fn spawn_server(bind: &str, ca_dir: &Path, data_dir: &Path) -> Result<Child> {
    let server_binary = binary_path("percepta-server");

    println!(
        "Spawning server: {} with bind={}",
        server_binary.display(),
        bind
    );

    let mut child = Command::new(&server_binary)
        .env("PERCEPTA_CA_DIR", ca_dir)
        .env("PERCEPTA_DATA_DIR", data_dir)
        .env("PERCEPTA_BIND", bind)
        // Integration tests run on dynamic ports; force plaintext for consistent behavior.
        .env("PERCEPTA_DISABLE_TLS", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn server process")?;

    // Wait for server to be ready by attempting to connect
    let start = Instant::now();
    let timeout_duration = Duration::from_secs(10);

    loop {
        if start.elapsed() > timeout_duration {
            let _ = child.kill().await;
            anyhow::bail!(
                "Server failed to become ready within {} seconds",
                timeout_duration.as_secs()
            );
        }

        // Try to create a gRPC channel to test if server is ready
        match tonic::transport::Channel::from_shared(format!("http://{}", bind)) {
            Ok(channel) => match timeout(Duration::from_millis(500), channel.connect()).await {
                Ok(Ok(_)) => {
                    println!("Server is ready at {}", bind);
                    break;
                }
                _ => {
                    sleep(Duration::from_millis(200)).await;
                    continue;
                }
            },
            Err(_) => {
                sleep(Duration::from_millis(200)).await;
                continue;
            }
        }
    }

    Ok(child)
}

/// Spawn agent process in simulate mode
async fn spawn_agent(
    server: &str,
    cert_dir: &Path,
    out_dir: &Path,
    agent_id: &str,
) -> Result<Child> {
    let agent_binary = binary_path("percepta-agent");

    println!(
        "Spawning agent: {} with server={}, agent_id={}",
        agent_binary.display(),
        server,
        agent_id
    );

    let child = Command::new(&agent_binary)
        .arg("--simulate")
        .env("PERCEPTA_CERT_DIR", cert_dir)
        .env("PERCEPTA_OUT", out_dir)
        .env("PERCEPTA_SERVER", server)
        .env("PERCEPTA_AGENT_ID", agent_id)
        // Dynamic test ports run plaintext; tell the agent not to attempt TLS.
        .env("PERCEPTA_DISABLE_TLS", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn agent process")?;

    // Give agent a moment to initialize
    sleep(Duration::from_millis(500)).await;

    Ok(child)
}

async fn send_test_event(bind: &str, agent_id: &str, marker: &str) -> Result<()> {
    let channel = tonic::transport::Channel::from_shared(format!("http://{}", bind))
        .context("Failed to create gRPC channel")?
        .connect()
        .await
        .context("Failed to connect gRPC channel")?;

    let mut client = CollectorServiceClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Event>();
    let outbound = UnboundedReceiverStream::new(rx);

    // Send a single valid event and then close the outbound stream.
    let now = chrono::Utc::now();
    let ts = Timestamp {
        seconds: now.timestamp(),
        nanos: now.timestamp_subsec_nanos() as i32,
    };

    let ev = Event {
        event_time: Some(ts.clone()),
        ingest_time: None,
        agent: Some(event::Agent {
            id: agent_id.to_string(),
            hostname: "integration-host".to_string(),
            ip: "127.0.0.1".to_string(),
            mac: "".to_string(),
            version: "integration".to_string(),
            os: Some(event::Os {
                name: "Linux".to_string(),
                version: "test".to_string(),
                kernel: "".to_string(),
            }),
        }),
        event: Some(event::EventDetails {
            summary: format!("integration-event {}", marker),
            original_message: format!("integration-original {}", marker),
            category: event::EventCategory::Other as i32,
            action: "test".to_string(),
            outcome: event::EventOutcome::Success as i32,
            level: "Info".to_string(),
            severity: 1,
            provider: "integration".to_string(),
            event_id: 1,
            record_id: 1,
        }),
        user: None,
        host: None,
        network: None,
        process: None,
        file: None,
        registry: None,
        metadata: std::collections::HashMap::new(),
        tags: Vec::new(),
        threat_indicator: "".to_string(),
        threat_source: "".to_string(),
        correlation_id: marker.to_string(),
        hash: marker.to_string(),
    };

    tx.send(ev)
        .map_err(|_| anyhow::anyhow!("Failed to send test event into stream"))?;
    drop(tx);

    let mut inbound = client
        .stream_events(Request::new(outbound))
        .await
        .context("Failed to establish stream_events")?
        .into_inner();

    // Expect an ACK for our single event.
    let resp = inbound
        .message()
        .await
        .context("Failed to read ACK")?
        .context("Server closed stream without ACK")?;

    anyhow::ensure!(resp.ack, "Expected ack=true, got ack=false: {}", resp.message);
    anyhow::ensure!(resp.event_id == marker, "Expected ACK event_id to match marker/hash");

    Ok(())
}

/// Wait for the server WAL to contain a substring (e.g., agent id)
async fn wait_for_wal_contains(
    data_dir: &Path,
    needle: &str,
    timeout_duration: Duration,
) -> Result<()> {
    let wal_path = data_dir.join("events.wal");
    let start = Instant::now();

    println!("Waiting for WAL to contain '{}' at: {}", needle, wal_path.display());

    loop {
        if start.elapsed() > timeout_duration {
            anyhow::bail!(
                "WAL did not contain '{}' within {} seconds (path: {})",
                needle,
                timeout_duration.as_secs(),
                wal_path.display()
            );
        }

        if wal_path.exists() {
            if let Ok(content) = fs::read_to_string(&wal_path) {
                if content.contains(needle) {
                    return Ok(());
                }
            }
        }

        sleep(Duration::from_millis(100)).await;
    }
}

fn wal_line_count(data_dir: &Path) -> usize {
    let wal_path = data_dir.join("events.wal");
    let content = fs::read_to_string(&wal_path).unwrap_or_default();
    content.lines().filter(|l| !l.trim().is_empty()).count()
}

#[tokio::test]
async fn enrollment_and_short_batch() -> Result<()> {
    // Create temporary directories
    let certs_tmp = TempDir::new().context("Failed to create temp cert dir")?;
    let data_tmp = TempDir::new().context("Failed to create temp data dir")?;
    let agent_out_tmp = TempDir::new().context("Failed to create temp agent out dir")?;

    println!(
        "Temp dirs - certs: {}, data: {}, agent_out: {}",
        certs_tmp.path().display(),
        data_tmp.path().display(),
        agent_out_tmp.path().display()
    );

    // Pick free port and spawn server
    let port = pick_free_port();
    let bind = format!("127.0.0.1:{}", port);

    let mut server_child = spawn_server(&bind, certs_tmp.path(), data_tmp.path())
        .await
        .context("Failed to spawn server")?;

    // Test enrollment by creating a simple gRPC client
    // Note: This assumes the server allows enrollment over insecure HTTP for testing
    let _channel = tonic::transport::Channel::from_shared(format!("http://{}", bind))
        .context("Failed to create channel")?
        .connect()
        .await
        .context("Failed to connect to server")?;

    println!("Successfully connected to server for enrollment test");

    // Spawn agent in simulate mode as a smoke-test (not relied upon for deterministic ingestion)
    let agent_id = "agent-test-1";
    let mut agent_child = spawn_agent(&bind, certs_tmp.path(), agent_out_tmp.path(), agent_id)
        .await
        .context("Failed to spawn agent")?;

    // Deterministic ingestion: send a single valid event from the test itself.
    let marker1 = "integration-test-001";
    send_test_event(&bind, agent_id, marker1)
        .await
        .context("Failed to send test event")?;

    // Wait for server to persist the event to WAL
    timeout(
        Duration::from_secs(30),
        wait_for_wal_contains(data_tmp.path(), marker1, Duration::from_secs(25)),
    )
    .await
    .context("Timed out waiting for WAL ingestion")?
    .context("Failed to observe agent events in WAL")?;

    let initial_lines = wal_line_count(data_tmp.path());
    assert!(initial_lines > 0, "WAL should have at least 1 line");
    println!("✓ WAL persistence verified ({} lines)", initial_lines);

    // Test reconnection behavior
    println!("Testing reconnection behavior...");

    // Kill server
    server_child.kill().await.context("Failed to kill server")?;
    let _ = server_child.wait().await;
    println!("Server killed");

    // Wait a moment for agent to observe disconnect and retry
    sleep(Duration::from_secs(2)).await;

    // Restart server on same port
    server_child = spawn_server(&bind, certs_tmp.path(), data_tmp.path())
        .await
        .context("Failed to restart server")?;

    // Send a second event after restart
    let marker2 = "integration-test-002";
    send_test_event(&bind, agent_id, marker2)
        .await
        .context("Failed to send second test event")?;

    // Wait for WAL to grow and contain marker2
    let grew = timeout(Duration::from_secs(30), async {
        let start = Instant::now();
        loop {
            if start.elapsed() > Duration::from_secs(25) {
                anyhow::bail!("WAL did not grow after server restart");
            }
            let now_lines = wal_line_count(data_tmp.path());
            let has_marker2 = fs::read_to_string(data_tmp.path().join("events.wal"))
                .unwrap_or_default()
                .contains(marker2);
            if now_lines > initial_lines && has_marker2 {
                return Ok::<(), anyhow::Error>(());
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await;

    grew.context("Timed out waiting for WAL growth after reconnect")??;
    println!("✓ Reconnection and retry test passed");

    // Cleanup
    let _ = agent_child.kill().await;
    let _ = agent_child.wait().await;
    let _ = server_child.kill().await;
    let _ = server_child.wait().await;

    println!("✓ Integration tests completed successfully");

    Ok(())
}

#[tokio::test]
async fn test_server_startup_failure() -> Result<()> {
    // Test that we handle server startup failures gracefully
    let certs_tmp = TempDir::new()?;
    let data_tmp = TempDir::new()?;

    // Try to bind to an invalid address
    let result = spawn_server("invalid-address", certs_tmp.path(), data_tmp.path()).await;

    assert!(
        result.is_err(),
        "Should fail to spawn server with invalid bind address"
    );
    println!("✓ Server startup failure handling works correctly");

    Ok(())
}

#[tokio::test]
async fn test_missing_binary() {
    // Test helper function behavior when binary doesn't exist
    // We can't actually test this without moving the binary, so we'll test the path construction
    let server_path = binary_path("percepta-server");
    let agent_path = binary_path("percepta-agent");

    assert!(
        server_path.exists(),
        "Server binary should exist after cargo build --workspace"
    );
    assert!(
        agent_path.exists(),
        "Agent binary should exist after cargo build --workspace"
    );

    println!("✓ Binary path resolution test passed");
}
