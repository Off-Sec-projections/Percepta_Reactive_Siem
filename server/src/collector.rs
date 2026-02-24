use anyhow::Result;
use async_stream::try_stream;
use futures::Stream;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Global ingestion counters (useful for cross-task stats)
pub static GLOBAL_EVENTS_RECEIVED: Lazy<Arc<AtomicU64>> = Lazy::new(|| Arc::new(AtomicU64::new(0)));
pub static GLOBAL_EVENTS_ACKED: Lazy<Arc<AtomicU64>> = Lazy::new(|| Arc::new(AtomicU64::new(0)));
/// Global connected agents count (updated on connect/disconnect)
pub static GLOBAL_CONNECTED_AGENTS: Lazy<Arc<AtomicU64>> =
    Lazy::new(|| Arc::new(AtomicU64::new(0)));
/// Global map of agent_id -> active stream count.
///
/// This avoids flapping when an agent opens multiple concurrent streams or reconnects quickly.
pub static GLOBAL_AGENT_CONNECTIONS: Lazy<Arc<Mutex<HashMap<String, usize>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

const RECENT_HASH_CACHE_SIZE: usize = 5_000;

struct RecentHashTracker {
    queue: VecDeque<String>,
    set: HashSet<String>,
    capacity: usize,
}

impl RecentHashTracker {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            set: HashSet::with_capacity(capacity),
            capacity,
        }
    }

    fn insert(&mut self, hash: &str) -> bool {
        if self.set.contains(hash) {
            return false;
        }

        if self.queue.len() >= self.capacity {
            if let Some(oldest) = self.queue.pop_front() {
                self.set.remove(&oldest);
            }
        }

        self.queue.push_back(hash.to_string());
        self.set.insert(hash.to_string());
        true
    }
}
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};
use tracing::{debug, error, info, warn};

use crate::certificate_authority::CAService;
use crate::ingest_utils;
use crate::storage::StorageService;
use crate::websocket::{EventBroadcaster, StreamMessage};
use percepta_server::percepta::{
    collector_service_server::CollectorService as CollectorServiceTrait, Event, IngestionResponse,
};
use percepta_server::rule_engine::RuleEngine;

/// CollectorService handles log ingestion for the SIEM system
#[derive(Clone)]
pub struct CollectorService {
    /// List of currently connected agents, protected by async mutex
    connected_agents: Arc<Mutex<HashMap<String, usize>>>,
    ca_service: Arc<CAService>,
    storage_service: Arc<StorageService>,
    rule_engine: Arc<RuleEngine>,
    event_broadcaster: EventBroadcaster,
    recent_hashes: Arc<Mutex<RecentHashTracker>>,
}

impl CollectorService {
    /// Create a new CollectorService instance
    pub async fn new(
        ca_service: Arc<CAService>,
        storage_service: Arc<StorageService>,
        rule_engine: Arc<RuleEngine>,
        event_broadcaster: EventBroadcaster,
    ) -> Result<Self> {
        info!("🔧 Initializing CollectorService...");

        Ok(Self {
            connected_agents: GLOBAL_AGENT_CONNECTIONS.clone(),
            ca_service,
            storage_service,
            rule_engine,
            event_broadcaster,
            recent_hashes: Arc::new(Mutex::new(RecentHashTracker::new(RECENT_HASH_CACHE_SIZE))),
        })
    }

    /// Get the current number of connected agents
    #[allow(dead_code)]
    pub async fn agent_count(&self) -> usize {
        self.connected_agents.lock().await.len()
    }

    /// Check if an agent is currently connected
    #[allow(dead_code)]
    pub async fn is_agent_connected(&self, agent_id: &str) -> bool {
        self.connected_agents.lock().await.contains_key(agent_id)
    }

    /// Remove an agent from the connected list
    #[allow(dead_code)]
    pub async fn disconnect_agent(&self, agent_id: &str) -> bool {
        let mut agents = self.connected_agents.lock().await;
        let removed = agents.remove(agent_id).is_some();
        if removed {
            info!("🔌 Agent disconnected: {}", agent_id);
            GLOBAL_CONNECTED_AGENTS.store(agents.len() as u64, Ordering::Relaxed);
        }
        removed
    }

    async fn mark_event_seen(&self, hash: &str) -> bool {
        let mut tracker = self.recent_hashes.lock().await;
        tracker.insert(hash)
    }
}

/// Snapshot of unique connected agent IDs (for stats endpoints/dashboard).
pub async fn connected_agent_ids_snapshot() -> Vec<String> {
    let guard = GLOBAL_AGENT_CONNECTIONS.lock().await;
    let mut ids: Vec<String> = guard.keys().cloned().collect();
    ids.sort();
    ids
}

#[tonic::async_trait]
impl CollectorServiceTrait for CollectorService {
    type StreamEventsStream =
        std::pin::Pin<Box<dyn Stream<Item = Result<IngestionResponse, Status>> + Send + 'static>>;

    /// Handle streaming events from agents
    async fn stream_events(
        &self,
        request: Request<tonic::Streaming<Event>>,
    ) -> Result<Response<Self::StreamEventsStream>, Status> {
        // --- Application-Layer CRL Check ---
        // Track agent CN from peer certificate for connection bookkeeping
        let mut agent_cn: Option<String> = None;
        if let Some(peer_cert) = request
            .peer_certs()
            .and_then(|certs| certs.iter().next().cloned())
        {
            match openssl::x509::X509::from_der(peer_cert.as_ref()) {
                Ok(cert) => {
                    let serial_bn = cert
                        .serial_number()
                        .to_bn()
                        .map_err(|e| Status::internal(format!("Failed to read serial: {}", e)))?;
                    let serial_dec = serial_bn
                        .to_dec_str()
                        .map_err(|e| Status::internal(format!("Failed to format serial: {}", e)))?;
                    if self.ca_service.is_certificate_revoked(&serial_dec).await {
                        warn!(
                            "Rejecting connection from revoked certificate. Serial: {}",
                            serial_dec
                        );
                        return Err(Status::permission_denied("Certificate has been revoked."));
                    }
                    debug!(
                        "Peer certificate is valid and not revoked. Serial: {}",
                        serial_dec
                    );

                    // Try to extract agent id from certificate subject CN for connected agents tracking
                    for entry in cert.subject_name().entries() {
                        if entry.object().nid().as_raw() == openssl::nid::Nid::COMMONNAME.as_raw() {
                            if let Ok(cn) = entry.data().as_utf8() {
                                agent_cn = Some(cn.to_string());
                                break;
                            }
                        }
                    }

                    if let Some(ref agent_id) = agent_cn {
                        // Ref-count per-agent streams to avoid connect/disconnect flapping.
                        let mut agents = self.connected_agents.lock().await;
                        let entry = agents.entry(agent_id.clone()).or_insert(0);
                        *entry += 1;

                        // Only announce/broadcast when transitioning 0 -> 1 (first active stream).
                        if *entry == 1 {
                            info!("🔗 Agent connected: {} (total: {})", agent_id, agents.len());
                            GLOBAL_CONNECTED_AGENTS.store(agents.len() as u64, Ordering::Relaxed);

                            let mut ids: Vec<String> = agents.keys().cloned().collect();
                            ids.sort();
                            let total_received =
                                crate::collector::GLOBAL_EVENTS_RECEIVED.load(Ordering::Relaxed);
                            let total_acked = crate::collector::GLOBAL_EVENTS_ACKED.load(Ordering::Relaxed);
                            let stats = serde_json::json!({
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                                "ingest_total_received": total_received,
                                "ingest_total_acked": total_acked,
                                "connected_agents": ids.len(),
                                "connected_agent_ids": ids,
                            });
                            let _ = self.event_broadcaster.send(StreamMessage::Stats(stats));
                        }
                    }
                }
                Err(_) => {
                    warn!("Could not parse peer certificate from mTLS connection.");
                    return Err(Status::invalid_argument("Invalid peer certificate"));
                }
            }
        } else {
            // When the gRPC server is running without TLS (e.g., dynamic ports in tests or
            // explicit PERCEPTA_DISABLE_TLS=1), there is no peer certificate to validate.
            // In that mode we accept the stream but cannot perform CRL checks or attribute the
            // connection to an mTLS identity (CN).
            debug!("No peer certificate presented; accepting plaintext stream.");
        }
        // --- End CRL Check ---

        let mut stream = request.into_inner();
        let service = self.clone();
        // Clone broadcaster early so we can move it into the CleanupStream without
        // attempting to borrow `service` after it has been moved into the stream.
        let broadcaster_for_cleanup = self.event_broadcaster.clone();

        debug!(
            "🌊 Starting event stream processing: agent={}",
            agent_cn.as_deref().unwrap_or("<unknown>")
        );

        // Clone agent id for use inside the response stream and for cleanup
        let agent_id_for_stream = std::sync::Arc::new(agent_cn.clone());

        let response_stream = try_stream! {
            // Track per-connection counters for logging
            let connection_received = std::sync::Arc::new(AtomicU64::new(0));
            let connection_acked = std::sync::Arc::new(AtomicU64::new(0));
            let conn_start = std::time::Instant::now();
            while let Some(event) = stream.next().await {
                match event {
                    Ok(mut event) => {
                        // Observability: increment counters
                        connection_received.fetch_add(1, Ordering::Relaxed);
                        GLOBAL_EVENTS_RECEIVED.fetch_add(1, Ordering::Relaxed);

                        // Log occasional progress (every 50 events)
                        let recv_count = connection_received.load(Ordering::Relaxed);
                        if recv_count % 50 == 0 {
                            info!("ingest_progress: agent={:?} received={} total_received={} elapsed_ms={}",
                                agent_id_for_stream.as_ref().as_deref().unwrap_or("<unknown>"),
                                recv_count,
                                GLOBAL_EVENTS_RECEIVED.load(Ordering::Relaxed),
                                conn_start.elapsed().as_millis());
                        }
                        // Ensure event has a hash
                        ingest_utils::ensure_event_hash(&mut event);

                        let agent_hint = agent_id_for_stream.as_ref().as_deref();
                        ingest_utils::enrich_event(&mut event, agent_hint);

                        if let Err(e) = ingest_utils::validate_event(&event) {
                            warn!("Discarding invalid event {}: {}", event.hash, e);
                            let response = IngestionResponse {
                                ack: false,
                                event_id: event.hash.clone(),
                                message: format!("Event validation failed: {}", e),
                            };
                            yield response;
                            continue;
                        }

                        if !service.mark_event_seen(&event.hash).await {
                            debug!("Dropping duplicate event {}", event.hash);
                            let response = IngestionResponse {
                                ack: true,
                                event_id: event.hash.clone(),
                                message: "Duplicate event suppressed".to_string(),
                            };
                            yield response;
                            continue;
                        }

                        // Evaluate event against detection rules and broadcast alerts
                        match service.rule_engine.evaluate_event(&event).await {
                            Ok(alerts) => {
                                for alert in alerts {
                                    debug!("🚨 Alert triggered: {}", alert.rule_name);
                                    let _ = service.event_broadcaster.send(StreamMessage::Alert(alert));
                                }
                            }
                            Err(e) => warn!("Failed to evaluate event against rules: {}", e),
                        }

                        // Store event using the new storage service
                        let (ack, message) = match service.storage_service.store_event(&event).await {
                            Ok(_) => {
                                debug!("✅ Event stored successfully: {}", event.hash);
                                // Broadcast to WebSocket subscribers
                                let _ = service.event_broadcaster.send(StreamMessage::Event(event.clone()));
                                (true, "Event received".to_string())
                            }
                            Err(e) => {
                                error!("❌ Failed to store event {}: {}", event.hash, e);
                                // Notify agent of storage failure
                                warn!("⚠️ Reporting storage failure for event: {}", event.hash);
                                (false, format!("Server failed to store event: {}", e))
                            }
                        };

                        // Send acknowledgment response
                        let response = IngestionResponse {
                            ack,
                            event_id: event.hash.clone(),
                            message,
                        };

                        if ack {
                            connection_acked.fetch_add(1, Ordering::Relaxed);
                            GLOBAL_EVENTS_ACKED.fetch_add(1, Ordering::Relaxed);
                        }

                        yield response;
                    }
                    Err(e) => {
                        error!("❌ Error receiving event from stream: {}", e);

                        let error_response = IngestionResponse {
                            ack: false,
                            event_id: String::new(),
                            message: format!("Error processing event: {}", e),
                        };

                        yield error_response;
                    }
                }
            }

            info!("🏁 Event stream processing completed");
            // Final connection summary
            info!("ingest_connection_closed: agent={:?} duration_ms={} received={} acked={} total_received={} total_acked={}",
                agent_id_for_stream.as_ref().as_deref().unwrap_or("<unknown>"),
                conn_start.elapsed().as_millis(),
                connection_received.load(Ordering::Relaxed),
                connection_acked.load(Ordering::Relaxed),
                GLOBAL_EVENTS_RECEIVED.load(Ordering::Relaxed),
                GLOBAL_EVENTS_ACKED.load(Ordering::Relaxed));
        };

        // Wrap the response stream so we can perform cleanup when the stream is dropped
        use futures::Stream as FuturesStream;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        struct CleanupStream {
            inner: Pin<
                Box<dyn FuturesStream<Item = Result<IngestionResponse, Status>> + Send + 'static>,
            >,
            agent_id: Option<String>,
            connected_agents: Arc<Mutex<HashMap<String, usize>>>,
            event_broadcaster: EventBroadcaster,
        }

        impl FuturesStream for CleanupStream {
            type Item = Result<IngestionResponse, Status>;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                Pin::new(&mut self.inner).poll_next(cx)
            }
        }

        impl Drop for CleanupStream {
            fn drop(&mut self) {
                if let Some(agent_id) = &self.agent_id {
                    let agents = self.connected_agents.clone();
                    let agent = agent_id.clone();
                    let broadcaster = self.event_broadcaster.clone();
                    // spawn a background task to remove the agent from the list
                    let _ = tokio::spawn(async move {
                        let mut map = agents.lock().await;
                        let mut removed = false;
                        if let Some(count) = map.get_mut(&agent) {
                            if *count > 1 {
                                *count -= 1;
                            } else {
                                map.remove(&agent);
                                removed = true;
                            }
                        }

                        // Only announce/broadcast on last disconnect (1 -> 0).
                        if removed {
                            tracing::info!("🔌 Agent disconnected (cleanup): {}", agent);
                            crate::collector::GLOBAL_CONNECTED_AGENTS
                                .store(map.len() as u64, Ordering::Relaxed);
                            let mut ids: Vec<String> = map.keys().cloned().collect();
                            ids.sort();
                            let total_received =
                                crate::collector::GLOBAL_EVENTS_RECEIVED.load(Ordering::Relaxed);
                            let total_acked = crate::collector::GLOBAL_EVENTS_ACKED.load(Ordering::Relaxed);
                            let stats = serde_json::json!({
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                                "ingest_total_received": total_received,
                                "ingest_total_acked": total_acked,
                                "connected_agents": ids.len(),
                                "connected_agent_ids": ids,
                            });
                            let _ = broadcaster.send(StreamMessage::Stats(stats));
                        }
                    });
                }
            }
        }

        let cleanup = CleanupStream {
            inner: Box::pin(response_stream),
            agent_id: agent_cn.clone(),
            connected_agents: self.connected_agents.clone(),
            event_broadcaster: broadcaster_for_cleanup,
        };

        Ok(Response::new(Box::pin(cleanup)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_authority::{CAConfig, CAService};
    use crate::ingest_utils;
    use tempfile::tempdir;
    use tokio::sync::broadcast;
    use uuid::Uuid;

    async fn create_test_service() -> CollectorService {
        let temp_dir = tempdir().unwrap();
        let ca_config = CAConfig {
            ca_storage_path: temp_dir.path().to_path_buf(),
            ..Default::default()
        };
        let ca_service = Arc::new(CAService::new(ca_config).await.unwrap());

        let storage_dir = tempdir().unwrap();
        let storage_service = Arc::new(StorageService::new(storage_dir.path()).await.unwrap());

        use percepta_server::alerts::AlertService;
        let alert_service = Arc::new(AlertService::new(300));
        let rule_engine = Arc::new(RuleEngine::new(alert_service));

        // Broadcaster for tests
        let (tx, _) = broadcast::channel(16);
        let broadcaster = Arc::new(tx);

        CollectorService::new(ca_service, storage_service, rule_engine, broadcaster)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_collector_service_creation() {
        let service = create_test_service().await;
        assert_eq!(service.agent_count().await, 0);
    }

    // The enrollment tests are removed as they are no longer part of the collector service directly
    // and are handled by the enroll.rs module.

    #[tokio::test]
    async fn test_agent_disconnect() {
        let service = create_test_service().await;

        // First enroll an agent
        {
            let mut agents = service.connected_agents.lock().await;
            agents.insert("test-agent".to_string(), 1);
        }

        assert_eq!(service.agent_count().await, 1);

        // Then disconnect it
        let disconnected = service.disconnect_agent("test-agent").await;
        assert!(disconnected);
        assert_eq!(service.agent_count().await, 0);
        assert!(!service.is_agent_connected("test-agent").await);
    }

    #[tokio::test]
    async fn test_ensure_event_hash() {
        let mut event = Event {
            ..Default::default()
        };

        ingest_utils::ensure_event_hash(&mut event);
        assert!(!event.hash.is_empty());

        // UUID format check
        assert!(Uuid::parse_str(&event.hash).is_ok());
    }

    #[tokio::test]
    async fn test_enrich_event_populates_core_fields() {
        let mut event = Event::default();
        ingest_utils::ensure_event_hash(&mut event);
        ingest_utils::enrich_event(&mut event, Some("agent-123"));

        assert!(event.ingest_time.is_some());
        assert!(event.event_time.is_some());
        assert_eq!(
            event
                .agent
                .as_ref()
                .map(|agent| agent.id.clone())
                .unwrap_or_default(),
            "agent-123"
        );
        assert_eq!(
            event.metadata.get("agent.id").cloned().unwrap_or_default(),
            "agent-123"
        );
    }

    #[tokio::test]
    async fn test_duplicate_detection() {
        let service = create_test_service().await;
        assert!(service.mark_event_seen("dup-hash").await);
        assert!(!service.mark_event_seen("dup-hash").await);
    }
}
