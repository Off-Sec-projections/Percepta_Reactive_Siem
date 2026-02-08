use anyhow::Result;
use parking_lot::RwLock;
use serde_json::Value as JsonValue;
use std::path::PathBuf;

use percepta_server::percepta::Event;
use percepta_server::rule_engine::RuleEngine;

use percepta_server::alerts::AlertService;

#[path = "../decoder_engine.rs"]
mod decoder_engine;
#[path = "../windows_mappings.rs"]
mod windows_mappings;
// Minimal stub to satisfy ingest_utils type signature in this standalone binary.
mod enrichment {
    use percepta_server::percepta::Event;

    #[derive(Clone)]
    pub struct EnrichmentOrchestrator;

    impl EnrichmentOrchestrator {
        pub async fn enrich_event(&self, _event: &mut Event) {}
    }
}
#[path = "../ingest_utils.rs"]
mod ingest_utils;

use decoder_engine::DecoderEngine;
use windows_mappings::WindowsEventMappings;

#[tokio::main]
async fn main() -> Result<()> {
    let base = PathBuf::from("server/testdata/windows_golden");
    if !base.exists() {
        println!("No testdata found at {}", base.display());
        return Ok(());
    }

    let decoder = RwLock::new(DecoderEngine::default());
    let windows = WindowsEventMappings::default();
    let alert_service = AlertService::new(300, 3600);
    let rule_engine = RuleEngine::new(std::sync::Arc::new(alert_service));

    let mut total = 0u64;
    let mut alerts = 0u64;

    for entry in std::fs::read_dir(base)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()).unwrap_or("") != "yaml" {
            continue;
        }
        let raw = std::fs::read_to_string(&path)?;
        let yaml_val: serde_yaml::Value = serde_yaml::from_str(&raw)?;
        let json_val: JsonValue = serde_json::to_value(yaml_val)?;

        let mut event: Event = serde_json::from_value(json_val).unwrap_or_default();
        normalize_event(&mut event);

        ingest_utils::apply_standard_pipeline(
            &mut event,
            Some("benchmark-agent"),
            &decoder,
            &windows,
            None,
        )
        .await;

        let found = rule_engine.evaluate_event(&event).await?;
        total += 1;
        alerts += found.len() as u64;
    }

    println!("Detection benchmark: files={} alerts={}", total, alerts);
    Ok(())
}

fn normalize_event(event: &mut Event) {
    // Ensure timestamps exist (use now if missing)
    let now = chrono::Utc::now().timestamp();
    if event.event_time.is_none() {
        event.event_time = Some(prost_types::Timestamp {
            seconds: now,
            nanos: 0,
        });
    }
    if event.ingest_time.is_none() {
        event.ingest_time = Some(prost_types::Timestamp {
            seconds: now,
            nanos: 0,
        });
    }
}
