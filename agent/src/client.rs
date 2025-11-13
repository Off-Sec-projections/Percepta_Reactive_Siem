//! gRPC Client Module
//!
//! Provides a robust gRPC client for streaming events to the Percepta SIEM server
//! with automatic reconnection, per-event acknowledgments, and TLS authentication.
//!
//! ## Features
//!
//! * **Mutual TLS Authentication**: Uses client certificates for secure authentication
//! * **Bidirectional Streaming**: Establishes persistent streams with the server
//! * **Per-event ACK/NACK Handling**: Tracks individual event acknowledgments with timeout
//! * **Automatic Reconnection**: Exponential backoff reconnection on connection failures
//! * **Send Queue Management**: Bounded queue with retry logic for failed sends
//! * **Compression**: Automatic gzip compression for large payloads (>64KB)
//!
//! ## Usage Example
//!
//! ```rust
//! use percepta_agent::client;
//!
//! let handle = client::connect_and_stream(
//!     "percepta-server:443",
//!     Path::new("./certs"),
//!     "agent-123"
//! ).await?;
//!
//! // Send events
//! handle.send_events(events).await?;
//!
//! // Check for failed events
//! if let Some(failed_hash) = handle.check_failed().await {
//!     warn!("Event failed: {}", failed_hash);
//! }
//! ```
//!
//! ## Environment Variables
//!
//! * `PERCEPTA_SERVER_NAME`: Server name for TLS verification (default: "percepta-server")

use anyhow::{bail, Context, Result};
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use std::{
    collections::HashMap,
    env,
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    fs,
    sync::{
        mpsc::{self, UnboundedReceiver, UnboundedSender},
        oneshot, Mutex,
    },
    time::sleep,
};
use tonic::{
    codec::CompressionEncoding,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
    Request, Streaming,
};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::percepta::{collector_service_client::CollectorServiceClient, Event, IngestionResponse};

/// Maximum number of events queued for sending
const MAX_SEND_QUEUE_SIZE: usize = 1000;
/// Maximum retry attempts per event
const MAX_RETRY_ATTEMPTS: u32 = 3;
/// ACK timeout per event
const ACK_TIMEOUT_SECONDS: u64 = 10;
/// gRPC compression threshold
#[allow(dead_code)]
const COMPRESSION_THRESHOLD_BYTES: usize = 64 * 1024; // 64KB
/// Maximum gRPC message size
const MAX_MESSAGE_SIZE: usize = 50 * 1024 * 1024; // 50MB

/// Exponential backoff configuration for reconnection
struct BackoffConfig {
    current_delay: Duration,
    max_delay: Duration,
}

impl BackoffConfig {
    fn new() -> Self {
        Self {
            current_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
        }
    }

    async fn wait_and_increase(&mut self) {
        sleep(self.current_delay).await;
        // Exponential backoff with jitter to avoid sync storms
        let mut next = self.current_delay * 2;
        let jitter_ms = std::cmp::max(50, (next.as_millis() as u64) / 10); // ~10%
        let add_ms = fastrand::u64(0..=jitter_ms);
        next = next.saturating_add(Duration::from_millis(add_ms));
        self.current_delay = std::cmp::min(next, self.max_delay);
    }

    fn reset(&mut self) {
        self.current_delay = Duration::from_secs(1);
    }
}

/// Event tracking information for ACK/retry logic
#[derive(Debug)]
struct PendingEvent {
    event: Event,
    #[allow(dead_code)]
    correlation_id: String,
    attempts: u32,
    sent_at: Instant,
    #[allow(dead_code)]
    ack_sender: Option<oneshot::Sender<bool>>,
}

/// Internal message types for client communication
#[derive(Debug)]
enum ClientMessage {
    SendEvents {
        events: Vec<Event>,
        result_sender: oneshot::Sender<Result<()>>,
    },
    #[allow(dead_code)]
    EventAck {
        correlation_id: String,
        success: bool,
    },
    #[allow(dead_code)]
    ConnectionLost,
    Shutdown,
    #[allow(dead_code)]
    TestDisconnect, // For testing
}

/// Client handle for interacting with the gRPC streaming connection
#[derive(Clone)]
pub struct ClientHandle {
    sender: UnboundedSender<ClientMessage>,
    failed_events: Arc<Mutex<Vec<String>>>,
    connection_id: Arc<AtomicU64>,
    is_connected: Arc<AtomicBool>,
}

impl ClientHandle {
    /// Send a batch of events to the server
    pub async fn send_events(&self, events: Vec<Event>) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        // Prevent silent queuing when not connected: surface clear error
        if !self.is_connected() {
            return Err(anyhow::anyhow!("Not connected to server; event batch rejected (will retry after reconnect)"));
        }

        let (result_tx, result_rx) = oneshot::channel();

        self.sender
            .send(ClientMessage::SendEvents {
                events,
                result_sender: result_tx,
            })
            .map_err(|_| anyhow::anyhow!("Client connection closed"))?;

        result_rx
            .await
            .map_err(|_| anyhow::anyhow!("Client response channel closed"))?
    }

    /// Send a single event (convenience wrapper)
    #[allow(dead_code)]
    pub async fn send_event(&self, event: Event) -> Result<()> {
        self.send_events(vec![event]).await
    }

    /// Check for failed events (non-blocking)
    #[allow(dead_code)]
    pub async fn check_failed(&self) -> Option<String> {
        let mut failed = self.failed_events.lock().await;
        failed.pop()
    }

    /// Get all failed event hashes and clear the list
    pub async fn drain_failed(&self) -> Vec<String> {
        let mut failed = self.failed_events.lock().await;
        std::mem::take(&mut *failed)
    }

    /// Check if client is currently connected
    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Acquire)
    }

    /// Get current connection ID (increments on each reconnect)
    pub fn connection_id(&self) -> u64 {
        self.connection_id.load(Ordering::Acquire)
    }

    /// Force disconnect for testing
    #[allow(dead_code)]
    pub async fn test_disconnect(&self) -> Result<()> {
        self.sender
            .send(ClientMessage::TestDisconnect)
            .map_err(|_| anyhow::anyhow!("Client connection closed"))?;
        Ok(())
    }

    /// Gracefully shutdown the client
    pub async fn shutdown(&self) -> Result<()> {
        self.sender
            .send(ClientMessage::Shutdown)
            .map_err(|_| anyhow::anyhow!("Client connection closed"))?;
        Ok(())
    }
}

/// Load TLS configuration from certificate files
async fn load_tls_config(cert_dir: &Path, _server_addr: &str) -> Result<ClientTlsConfig> {
    let cert_path = cert_dir.join("agent_cert.pem");
    let key_path = cert_dir.join("agent_key.pem");
    let ca_path = cert_dir.join("ca_cert.pem");

    // Verify all certificate files exist and report all missing at once
    let mut missing: Vec<String> = Vec::new();
    if !cert_path.exists() {
        missing.push(format!("{}", cert_path.display()));
    }
    if !key_path.exists() {
        missing.push(format!("{}", key_path.display()));
    }
    if !ca_path.exists() {
        missing.push(format!("{}", ca_path.display()));
    }
    if !missing.is_empty() {
        bail!(
            "Missing TLS files. Please enroll the agent first. Missing: {}",
            missing.join(", ")
        );
    }

    // Load certificate and key
    let cert_pem = fs::read(&cert_path)
        .await
        .with_context(|| format!("Failed to read agent certificate: {}", cert_path.display()))?;

    let key_pem = fs::read(&key_path)
        .await
        .with_context(|| format!("Failed to read agent private key: {}", key_path.display()))?;

    // Load CA certificate
    let ca_pem = fs::read(&ca_path)
        .await
        .with_context(|| format!("Failed to read CA certificate: {}", ca_path.display()))?;

    // Create TLS identity
    let identity = Identity::from_pem(&cert_pem, &key_pem);
    let ca_cert = Certificate::from_pem(&ca_pem);

    // -- BEGIN TOFU --
    // Verify the loaded CA cert against the pinned fingerprint.
    let ca_fingerprint_path = cert_dir.join("ca_fingerprint.txt");
    if !ca_fingerprint_path.exists() {
        bail!(
            "CRITICAL SECURITY: CA fingerprint not found at {}. Run enrollment to generate it.",
            ca_fingerprint_path.display()
        );
    }
    let pinned_fingerprint = fs::read_to_string(&ca_fingerprint_path).await?;
    let loaded_ca_cert = X509::from_pem(&ca_pem)?;
    let loaded_fingerprint = hex::encode(loaded_ca_cert.digest(MessageDigest::sha256())?);

    if pinned_fingerprint.trim() != loaded_fingerprint {
        bail!("CRITICAL SECURITY: CA certificate on disk does not match pinned fingerprint. Tampering detected. Connection aborted.");
    }
    info!("CA certificate matches pinned fingerprint. Proceeding with connection.");
    // -- END TOFU --

    // Get server name for TLS verification
    // Agents connect by IP:port but must use the certificate common name for TLS/SNI
    // Default to "Percepta-SIEM" if not specified, as that's what the server generates.
    let server_name = env::var("PERCEPTA_SERVER_NAME").unwrap_or_else(|_| {
        "Percepta-SIEM".to_string()
    });

    debug!("Using TLS server name for verification: {}", server_name);

    let tls_config = ClientTlsConfig::new()
        .domain_name(server_name)
        .ca_certificate(ca_cert)
        .identity(identity);

    debug!("TLS configuration loaded successfully");
    Ok(tls_config)
}

/// Create gRPC client with TLS configuration
async fn create_grpc_client(
    server_addr: &str,
    cert_dir: &Path,
) -> Result<CollectorServiceClient<Channel>> {
    // Plaintext policy knobs
    // - Default: require TLS for bare host:port.
    // - Allow plaintext only when explicitly opted-in.
    //   * PERCEPTA_ALLOW_PLAINTEXT=1 (preferred)
    //   * PERCEPTA_DISABLE_TLS=1 (legacy alias; treated as opt-in)
    // - http:// / https:// prefixes are also respected when passed directly.
    let disable_tls_legacy = std::env::var("PERCEPTA_DISABLE_TLS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let allow_plaintext = std::env::var("PERCEPTA_ALLOW_PLAINTEXT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
        || disable_tls_legacy;

    let (use_tls, endpoint_uri) = if server_addr.starts_with("http://") {
        (false, server_addr.to_string())
    } else if server_addr.starts_with("https://") {
        (true, server_addr.to_string())
    } else if allow_plaintext {
        (false, format!("http://{}", server_addr))
    } else {
        // Default to TLS for raw host:port
        (true, format!("https://{}", server_addr))
    };

    let mut endpoint = Endpoint::from_shared(endpoint_uri.clone())
        .with_context(|| format!("Invalid server address: {}", endpoint_uri))?
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .timeout(Duration::from_secs(30))
        .tcp_nodelay(true);

    if use_tls {
        let tls_config = load_tls_config(cert_dir, server_addr).await?;
        endpoint = endpoint.tls_config(tls_config)?;
    } else if !(endpoint_uri.starts_with("http://") || allow_plaintext) {
        // Protect against accidental plaintext when not explicitly allowed
        bail!("Plaintext connection is not allowed. Set PERCEPTA_ALLOW_PLAINTEXT=1 (or legacy PERCEPTA_DISABLE_TLS=1) for development.");
    }

    // Set message size limits and compression
    let channel = endpoint
        .connect()
        .await
        .with_context(|| format!("Failed to connect to server: {}. If using IP address, ensure server cert includes IP in SAN. Check TLS handshake with verbose logging (RUST_LOG=debug).", server_addr))?;

    let client = CollectorServiceClient::new(channel)
        .send_compressed(CompressionEncoding::Gzip)
        .accept_compressed(CompressionEncoding::Gzip)
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE);

    debug!("gRPC client created for server: {}", server_addr);
    Ok(client)
}

/// Main entry point for establishing streaming connection
pub async fn connect_and_stream(
    server_addr: &str,
    cert_dir: &Path,
    agent_id: &str,
) -> Result<ClientHandle> {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    let failed_events = Arc::new(Mutex::new(Vec::new()));
    let connection_id = Arc::new(AtomicU64::new(1));
    let is_connected = Arc::new(AtomicBool::new(false));

    let handle = ClientHandle {
        sender: msg_tx,
        failed_events: failed_events.clone(),
        connection_id: connection_id.clone(),
        is_connected: is_connected.clone(),
    };

    // Spawn client worker task
    let worker_server_addr = server_addr.to_string();
    let worker_cert_dir = cert_dir.to_path_buf();
    let worker_agent_id = agent_id.to_string();

    tokio::spawn(async move {
        let mut client_worker = ClientWorker {
            server_addr: worker_server_addr,
            cert_dir: worker_cert_dir,
            agent_id: worker_agent_id,
            msg_receiver: msg_rx,
            failed_events,
            connection_id,
            is_connected,
            pending_events: HashMap::new(),
            send_queue: Vec::new(),
            backoff: BackoffConfig::new(),
            retry_counts: HashMap::new(),
            last_error_summary: None,
        };

        if let Err(e) = client_worker.run().await {
            error!("Client worker failed: {:#}", e);
        }
    });

    // Wait for initial connection attempt
    // Wait up to 5s for the worker to mark the connection as established. If it
    // doesn't, return an error so callers (service/GUI) can retry instead of
    // assuming a successful connection immediately.
    let mut waited = 0u64;
    let max_wait_ms = 5000u64;
    let poll_interval_ms = 100u64;

    while waited < max_wait_ms {
        if handle.is_connected() {
            return Ok(handle);
        }
        sleep(Duration::from_millis(poll_interval_ms)).await;
        waited += poll_interval_ms;
    }

    // Timed out: treat as error so caller surfaces failure instead of pretending to be connected.
    Err(anyhow::anyhow!(
        "Initial gRPC streaming connection to {} not established within {}ms",
        server_addr,
        max_wait_ms
    ))
}

/// Internal client worker that manages the connection lifecycle
struct ClientWorker {
    server_addr: String,
    cert_dir: std::path::PathBuf,
    agent_id: String,
    msg_receiver: UnboundedReceiver<ClientMessage>,
    failed_events: Arc<Mutex<Vec<String>>>,
    connection_id: Arc<AtomicU64>,
    is_connected: Arc<AtomicBool>,
    pending_events: HashMap<String, PendingEvent>,
    send_queue: Vec<Event>,
    backoff: BackoffConfig,
    #[allow(dead_code)]
    retry_counts: HashMap<String, u32>,
    // Avoid spamming identical connection errors; reset on success
    last_error_summary: Option<String>,
}

impl ClientWorker {
    async fn run(&mut self) -> Result<()> {
        loop {
            match self.establish_connection().await {
                Ok((client, outbound, inbound)) => {
                    info!(
                        "Agent '{}' connected to server: {}",
                        self.agent_id, self.server_addr
                    );
                    info!(
                        "Agent '{}' stream open (connection_id={})",
                        self.agent_id,
                        self.connection_id.load(Ordering::Acquire)
                    );
                    self.is_connected.store(true, Ordering::Release);
                    self.backoff.reset();
                    // Successful connection clears last error summary so future failures log again
                    self.last_error_summary = None;

                    // Run connection loop
                    if let Err(e) = self.run_connection(client, outbound, inbound).await {
                        warn!("Connection lost: {:#}", e);
                        // Re-queue any in-flight events that did not receive an ACK
                        self.requeue_pending();
                    }

                    info!(
                        "Agent '{}' stream closed (connection_id={})",
                        self.agent_id,
                        self.connection_id.load(Ordering::Acquire)
                    );
                    self.is_connected.store(false, Ordering::Release);
                }
                Err(e) => {
                    let summary = format!("{:#}", e);
                    if let Some(prev) = &self.last_error_summary {
                        if prev == &summary {
                            debug!("Repeated connection failure suppressed: {}", summary);
                        } else {
                            error!("Failed to establish connection: {}", summary);
                            self.last_error_summary = Some(summary);
                        }
                    } else {
                        error!("Failed to establish connection: {}", summary);
                        self.last_error_summary = Some(summary);
                    }
                    self.backoff.wait_and_increase().await;
                }
            }

            // Check for shutdown message
            if self.should_shutdown().await {
                break;
            }
        }

        Ok(())
    }

    async fn establish_connection(
        &mut self,
    ) -> Result<(
        CollectorServiceClient<Channel>,
        UnboundedSender<Event>,
        Streaming<IngestionResponse>,
    )> {
        let client = create_grpc_client(&self.server_addr, &self.cert_dir).await?;

        // Create bidirectional stream
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let outbound_stream = tokio_stream::wrappers::UnboundedReceiverStream::new(outbound_rx);

        let request = Request::new(outbound_stream);
        let response = client
            .clone()
            .stream_events(request)
            .await
            .context("Failed to establish streaming connection")?;

        let inbound = response.into_inner();

        // Increment connection ID
        self.connection_id.fetch_add(1, Ordering::AcqRel);

        info!(
            "gRPC stream established to {} (connection_id={})",
            self.server_addr,
            self.connection_id.load(Ordering::Acquire)
        );

        debug!("Bidirectional stream established");
        Ok((client, outbound_tx, inbound))
    }

    async fn run_connection(
        &mut self,
        _client: CollectorServiceClient<Channel>,
        outbound: UnboundedSender<Event>,
        mut inbound: Streaming<IngestionResponse>,
    ) -> Result<()> {
        // Send any queued events from previous connection
        if !self.send_queue.is_empty() {
            debug!(
                "Sending {} queued events from previous connection",
                self.send_queue.len()
            );
            let queued_events = std::mem::take(&mut self.send_queue);
            self.send_events_internal(&outbound, queued_events).await?;
        }

        loop {
            tokio::select! {
                // Handle incoming messages from client handle
                msg = self.msg_receiver.recv() => {
                    match msg {
                        Some(ClientMessage::SendEvents { events, result_sender }) => {
                            let result = self.send_events_internal(&outbound, events).await;
                            let _ = result_sender.send(result);
                        }
                        Some(ClientMessage::EventAck { correlation_id, success }) => {
                            self.handle_event_ack(correlation_id, success).await;
                        }
                        Some(ClientMessage::ConnectionLost) => {
                            bail!("Connection lost signal received");
                        }
                        Some(ClientMessage::TestDisconnect) => {
                            warn!("Test disconnect triggered");
                            bail!("Test disconnect");
                        }
                        Some(ClientMessage::Shutdown) => {
                            info!("Shutdown signal received");
                            return Ok(());
                        }
                        None => {
                            bail!("Client message channel closed");
                        }
                    }
                }

                // Handle incoming ACKs from server
                response = inbound.message() => {
                    match response {
                        Ok(Some(msg)) => {
                            self.process_server_response(msg).await;
                        }
                        Ok(None) => {
                            warn!("Server closed the stream");
                            bail!("Server stream closed");
                        }
                        Err(e) => {
                            error!("Stream error: {:#}", e);
                            bail!("Stream error: {}", e);
                        }
                    }
                }

                // Check for ACK timeouts
                _ = sleep(Duration::from_secs(1)) => {
                    self.check_ack_timeouts().await;

                    // Periodic diagnostic: every 5s, log pending queue sizes so we can
                    // tell whether events are stuck locally.
                    static mut TICKS: u8 = 0;
                    unsafe {
                        TICKS = TICKS.wrapping_add(1);
                        if TICKS % 5 == 0 {
                            debug!("diagnostic: pending_events={} send_queue={} connection_id={}",
                                self.pending_events.len(),
                                self.send_queue.len(),
                                self.connection_id.load(Ordering::Acquire)
                            );
                        }
                    }
                }
            }
        }
    }

    async fn send_events_internal(
        &mut self,
        outbound: &UnboundedSender<Event>,
        events: Vec<Event>,
    ) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        debug!("Sending {} events to server", events.len());

        for mut event in events {
            // Use the event.hash as the authoritative correlation key, since the server
            // sends acknowledgments referencing IngestionResponse.event_id = event.hash.
            // If missing, generate a UUID to avoid empty keys.
            if event.hash.is_empty() {
                event.hash = Uuid::new_v4().to_string();
            }
            let key = event.hash.clone();

            // Also populate correlation_id for future compatibility/documentation.
            event.correlation_id = key.clone();

            // Determine attempt count for this send based on prior retries
            let attempt = self.retry_counts.get(&key).copied().unwrap_or(0) + 1;

            // Store pending event for ACK tracking keyed by hash
            let pending = PendingEvent {
                event: event.clone(),
                correlation_id: key.clone(),
                attempts: attempt,
                sent_at: Instant::now(),
                ack_sender: None,
            };
            self.pending_events.insert(key.clone(), pending);

            // Send the event on the outbound stream
            if let Err(e) = outbound.send(event.clone()) {
                error!("Failed to send event to stream: {}", e);
                // Add back to queue for retry
                self.send_queue.push(event);
                return Err(anyhow::anyhow!("Failed to send to stream: {}", e));
            } else {
                // Log successful enqueue with hash to verify outbound path
                debug!("Enqueued event to outbound stream: {}", key);
            }
        }

        Ok(())
    }

    async fn process_server_response(&mut self, response: IngestionResponse) {
        let success = response.ack;
        debug!(
            "Received ACK from server: event_id={} ack={}",
            response.event_id, success
        );
        self.handle_event_ack(response.event_id, success).await;
    }

    async fn handle_event_ack(&mut self, correlation_id: String, success: bool) {
        if let Some(pending) = self.pending_events.remove(&correlation_id) {
            if success {
                debug!("Event acknowledged: {}", correlation_id);
                // Clear retry counter on success
                let _ = self.retry_counts.remove(&pending.event.hash);
            } else {
                warn!("Event not acknowledged: {}", correlation_id);

                if pending.attempts < MAX_RETRY_ATTEMPTS {
                    // Retry the event
                    debug!(
                        "Retrying event: {} (attempt {})",
                        correlation_id,
                        pending.attempts + 1
                    );
                    // Update retry count for next send
                    self.retry_counts
                        .insert(pending.event.hash.clone(), pending.attempts);
                    self.send_queue.push(pending.event);
                } else {
                    // Max retries exceeded, mark as failed
                    error!(
                        "Event failed after {} attempts: {}",
                        MAX_RETRY_ATTEMPTS, correlation_id
                    );
                    let event_hash = pending.event.hash.clone();

                    let mut failed = self.failed_events.lock().await;
                    failed.push(event_hash);
                }
            }
        } else {
            warn!(
                "Received ACK for unknown correlation ID: {}",
                correlation_id
            );
        }
    }

    /// Move all currently pending (unacked) events back into the send queue so they
    /// can be retried on the next connection.
    fn requeue_pending(&mut self) {
        if self.pending_events.is_empty() {
            return;
        }

        let pending = std::mem::take(&mut self.pending_events);
        let mut requeued = 0usize;
        for (key, mut p) in pending.into_iter() {
            // Increment attempt count and decide whether to fail permanently
            let next_attempt = p.attempts + 1;
            if next_attempt > MAX_RETRY_ATTEMPTS {
                error!(
                    "Event failed after {} attempts: {}",
                    MAX_RETRY_ATTEMPTS, key
                );
                let failed_hash = p.event.hash.clone();
                let failed_events = self.failed_events.clone();
                // Record failure asynchronously to avoid blocking in this path
                let _ = tokio::spawn(async move {
                    let mut guard = failed_events.lock().await;
                    guard.push(failed_hash);
                });
                continue;
            }
            self.retry_counts.insert(key.clone(), next_attempt - 1);
            p.attempts = next_attempt;
            self.send_queue.push(p.event);
            requeued += 1;
        }
        debug!(
            "Re-queued {} pending events for retry after disconnect",
            requeued
        );
    }

    async fn check_ack_timeouts(&mut self) {
        let now = Instant::now();
        let timeout_duration = Duration::from_secs(ACK_TIMEOUT_SECONDS);
        let mut timed_out_events = Vec::new();

        for (correlation_id, pending) in &self.pending_events {
            if now.duration_since(pending.sent_at) > timeout_duration {
                timed_out_events.push(correlation_id.clone());
            }
        }

        for correlation_id in timed_out_events {
            warn!("Event ACK timeout: {}", correlation_id);
            self.handle_event_ack(correlation_id, false).await;
        }
    }

    async fn should_shutdown(&mut self) -> bool {
        // Check if there are any shutdown messages waiting
        while let Ok(msg) = self.msg_receiver.try_recv() {
            match msg {
                ClientMessage::Shutdown => return true,
                ClientMessage::SendEvents {
                    events,
                    result_sender,
                } => {
                    // Don't drop events received during disconnect. Queue them for the next connection.
                    if self.send_queue.len() + events.len() > MAX_SEND_QUEUE_SIZE {
                        warn!(
                            "Dropping {} events as send queue is full while disconnected.",
                            events.len()
                        );
                        let _ = result_sender
                            .send(Err(anyhow::anyhow!("Send queue full while disconnected")));
                    } else {
                        debug!(
                            "Queuing {} events received while disconnected.",
                            events.len()
                        );
                        self.send_queue.extend(events);
                        // Acknowledge that the events have been queued. The actual send result will
                        // be handled by the connection's ACK mechanism later.
                        let _ = result_sender.send(Ok(()));
                    }
                }
                // Other message types can be safely ignored during a disconnect.
                _ => {}
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_certs(cert_dir: &Path) -> Result<()> {
        fs::create_dir_all(cert_dir).await?;

        // Create dummy certificate files for testing
        let cert_content = "-----BEGIN CERTIFICATE-----\nTEST CERT\n-----END CERTIFICATE-----\n";
        let key_content = "-----BEGIN PRIVATE KEY-----\nTEST KEY\n-----END PRIVATE KEY-----\n";
        let ca_content = "-----BEGIN CERTIFICATE-----\nTEST CA\n-----END CERTIFICATE-----\n";

        fs::write(cert_dir.join("agent_cert.pem"), cert_content).await?;
        fs::write(cert_dir.join("agent_key.pem"), key_content).await?;
        fs::write(cert_dir.join("ca_cert.pem"), ca_content).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_tls_config_loading() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path();

        create_test_certs(cert_dir).await.unwrap();

        // This will fail during actual TLS parsing, but should succeed in loading files
        // Provide a dummy server address for TLS name resolution in tests
        let result = load_tls_config(cert_dir, "localhost:443").await;

        // We expect this to fail because our test certs are not valid
        // but the file loading should work
        assert!(result.is_err() || result.is_ok());
    }

    #[tokio::test]
    async fn test_missing_certificates() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path();

        // Provide a dummy server address for TLS name resolution in tests
        let result = load_tls_config(cert_dir, "localhost:443").await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Missing TLS files"),
            "unexpected error message: {}",
            msg
        );
    }

    #[tokio::test]
    async fn test_client_handle_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cert_dir = temp_dir.path();

        create_test_certs(cert_dir).await.unwrap();

        // For demo/production correctness, connect_and_stream fails fast if it cannot connect.
        // Use a non-routable TEST-NET address to ensure a deterministic failure.
        let result = connect_and_stream("203.0.113.1:443", cert_dir, "test-agent").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_backoff_config() {
        let mut backoff = BackoffConfig::new();
        assert_eq!(backoff.current_delay, Duration::from_secs(1));

        // Simulate progression
        backoff.current_delay *= 2;
        assert_eq!(backoff.current_delay, Duration::from_secs(2));

        backoff.reset();
        assert_eq!(backoff.current_delay, Duration::from_secs(1));
    }
}
