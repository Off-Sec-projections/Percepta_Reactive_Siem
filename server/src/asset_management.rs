//! Asset Management / CMDB — Configuration Management Database.
//!
//! Full asset model with criticality, owner, department, tags, software inventory.
//! Auto-discovery from enrolled agents + manual CSV/JSON import.
//! Asset criticality affects alert risk score (high-value target multiplier).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::db::Db;

// ── Asset Model ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: String,
    pub hostname: String,
    pub ip: String,
    pub mac: String,
    pub os: String,
    pub os_version: String,
    pub asset_type: AssetType,
    pub criticality: u8, // 1-10 (10 = most critical)
    pub owner: String,
    pub department: String,
    pub location: String,
    pub tags: Vec<String>,
    pub software_inventory: Vec<SoftwareEntry>,
    pub agent_id: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub discovered_at: DateTime<Utc>,
    pub status: AssetStatus,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    Workstation,
    Server,
    Laptop,
    NetworkDevice,
    IoT,
    Printer,
    VirtualMachine,
    Container,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetStatus {
    Active,
    Inactive,
    Decommissioned,
    Maintenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareEntry {
    pub name: String,
    pub version: String,
    pub vendor: String,
}

// ── Asset Store ──────────────────────────────────────────────────────────

pub type AssetStoreHandle = Arc<RwLock<AssetStore>>;

pub struct AssetStore {
    /// Assets indexed by ID.
    assets: HashMap<String, Asset>,
    /// Quick lookup: hostname -> asset_id.
    hostname_index: HashMap<String, String>,
    /// Quick lookup: IP -> asset_id.
    ip_index: HashMap<String, String>,
    /// Quick lookup: MAC -> asset_id.
    mac_index: HashMap<String, String>,
    /// Quick lookup: agent_id -> asset_id.
    agent_index: HashMap<String, String>,
    /// Optional ClickHouse handle for persistence.
    db: Option<Db>,
}

impl AssetStore {
    pub fn new() -> Self {
        Self {
            assets: HashMap::new(),
            hostname_index: HashMap::new(),
            ip_index: HashMap::new(),
            mac_index: HashMap::new(),
            agent_index: HashMap::new(),
            db: None,
        }
    }

    /// Initialise ClickHouse persistence: create table + load existing rows.
    pub async fn init_persistence(&mut self, db: Db) -> anyhow::Result<()> {
        let client = db.client();
        client
            .query(
                "CREATE TABLE IF NOT EXISTS assets (\
                    id String,\
                    content String,\
                    updated_at Int64\
                ) ENGINE = ReplacingMergeTree(updated_at)\
                ORDER BY id",
            )
            .execute()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create assets table: {e}"))?;

        // Load existing rows.
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct AssetRow {
            #[allow(dead_code)]
            id: String,
            content: String,
        }

        let rows: Vec<AssetRow> = client
            .query(
                "SELECT id, argMax(content, updated_at) AS content \
                 FROM assets GROUP BY id",
            )
            .fetch_all::<AssetRow>()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load assets from ClickHouse: {e}"))?;

        let mut loaded = 0usize;
        for row in rows {
            match serde_json::from_str::<Asset>(&row.content) {
                Ok(asset) => {
                    self.upsert_no_persist(asset);
                    loaded += 1;
                }
                Err(e) => warn!("Failed to decode Asset from ClickHouse: {:#}", e),
            }
        }

        info!("CMDB: Loaded {} assets from ClickHouse", loaded);
        self.db = Some(db);
        Ok(())
    }

    /// Fire-and-forget persist a single asset to ClickHouse.
    fn persist_asset_bg(&self, asset: &Asset) {
        let Some(db) = self.db.clone() else { return };
        let content = match serde_json::to_string(asset) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to serialize asset for persistence: {:#}", e);
                return;
            }
        };
        let id = asset.id.clone();
        tokio::spawn(async move {
            #[derive(clickhouse::Row, serde::Serialize)]
            struct AssetPersistRow {
                id: String,
                content: String,
                updated_at: i64,
            }
            let row = AssetPersistRow {
                id,
                content,
                updated_at: Utc::now().timestamp(),
            };
            let client = db.client();
            if let Err(e) = async {
                let mut insert = client
                    .insert("assets")
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                insert
                    .write(&row)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                insert.end().await.map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok::<_, anyhow::Error>(())
            }
            .await
            {
                warn!("Failed to persist asset to ClickHouse: {:#}", e);
            }
        });
    }

    /// Internal upsert without triggering persistence (used during DB load).
    fn upsert_no_persist(&mut self, asset: Asset) {
        let id = asset.id.clone();
        if !asset.hostname.is_empty() {
            self.hostname_index
                .insert(asset.hostname.to_lowercase(), id.clone());
        }
        if !asset.ip.is_empty() {
            self.ip_index.insert(asset.ip.clone(), id.clone());
        }
        if !asset.mac.is_empty() {
            self.mac_index.insert(asset.mac.to_lowercase(), id.clone());
        }
        if let Some(ref agent_id) = asset.agent_id {
            self.agent_index.insert(agent_id.clone(), id.clone());
        }
        self.assets.insert(id, asset);
    }

    pub fn upsert(&mut self, asset: Asset) {
        self.persist_asset_bg(&asset);
        self.upsert_no_persist(asset);
    }

    #[allow(dead_code)]
    pub fn get_by_id(&self, id: &str) -> Option<&Asset> {
        self.assets.get(id)
    }

    #[allow(dead_code)]
    pub fn get_by_hostname(&self, hostname: &str) -> Option<&Asset> {
        self.hostname_index
            .get(&hostname.to_lowercase())
            .and_then(|id| self.assets.get(id))
    }

    #[allow(dead_code)]
    pub fn get_by_ip(&self, ip: &str) -> Option<&Asset> {
        self.ip_index.get(ip).and_then(|id| self.assets.get(id))
    }

    #[allow(dead_code)]
    pub fn get_by_agent_id(&self, agent_id: &str) -> Option<&Asset> {
        self.agent_index
            .get(agent_id)
            .and_then(|id| self.assets.get(id))
    }

    /// Get criticality multiplier for risk scoring.
    /// Returns 1.0-3.0 based on criticality (1-10).
    #[allow(dead_code)]
    pub fn criticality_multiplier(&self, hostname: &str, ip: &str) -> f64 {
        let asset = self
            .get_by_hostname(hostname)
            .or_else(|| self.get_by_ip(ip));
        match asset {
            Some(a) => {
                let c = a.criticality.clamp(1, 10) as f64;
                1.0 + (c - 1.0) * 0.222 // 1→1.0, 5→1.89, 10→3.0
            }
            None => 1.0, // Unknown asset = neutral multiplier
        }
    }

    pub fn list_all(&self) -> Vec<&Asset> {
        self.assets.values().collect()
    }

    pub fn remove(&mut self, id: &str) -> bool {
        if let Some(asset) = self.assets.remove(id) {
            self.hostname_index.remove(&asset.hostname.to_lowercase());
            self.ip_index.remove(&asset.ip);
            self.mac_index.remove(&asset.mac.to_lowercase());
            if let Some(ref agent_id) = asset.agent_id {
                self.agent_index.remove(agent_id);
            }
            true
        } else {
            false
        }
    }

    /// Auto-discover asset from agent system_info event.
    pub fn discover_from_agent(&mut self, agent_id: &str, metadata: &HashMap<String, String>) {
        let hostname = metadata.get("hostname").cloned().unwrap_or_default();
        let ip = metadata
            .get("ip_address")
            .or_else(|| metadata.get("host_ip"))
            .cloned()
            .unwrap_or_default();
        let mac = metadata.get("mac_address").cloned().unwrap_or_default();
        let os = metadata
            .get("os")
            .or_else(|| metadata.get("os_name"))
            .cloned()
            .unwrap_or_default();
        let os_version = metadata.get("os_version").cloned().unwrap_or_default();

        // Check if already exists by agent_id
        if let Some(existing_id) = self.agent_index.get(agent_id).cloned() {
            if let Some(asset) = self.assets.get_mut(&existing_id) {
                asset.last_seen = Utc::now();
                if !hostname.is_empty() {
                    asset.hostname = hostname;
                }
                if !ip.is_empty() {
                    asset.ip = ip;
                }
                if !os.is_empty() {
                    asset.os = os;
                }
                let snapshot = asset.clone();
                self.persist_asset_bg(&snapshot);
                return;
            }
        }

        let asset = Asset {
            id: uuid::Uuid::new_v4().to_string(),
            hostname,
            ip,
            mac,
            os,
            os_version,
            asset_type: AssetType::Unknown,
            criticality: 5, // Default middle
            owner: String::new(),
            department: String::new(),
            location: String::new(),
            tags: vec!["auto-discovered".into()],
            software_inventory: Vec::new(),
            agent_id: Some(agent_id.to_string()),
            last_seen: Utc::now(),
            discovered_at: Utc::now(),
            status: AssetStatus::Active,
            notes: String::new(),
        };
        info!(
            "CMDB: Auto-discovered asset '{}' from agent {}",
            asset.hostname, agent_id
        );
        self.upsert(asset);
    }

    /// Import assets from JSON array.
    pub fn import_json(&mut self, json_str: &str) -> Result<usize, String> {
        let assets: Vec<Asset> =
            serde_json::from_str(json_str).map_err(|e| format!("Invalid JSON: {}", e))?;
        let count = assets.len();
        for asset in assets {
            self.upsert(asset);
        }
        Ok(count)
    }

    pub fn stats(&self) -> serde_json::Value {
        let total = self.assets.len();
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_criticality: HashMap<u8, usize> = HashMap::new();
        let mut active = 0;

        for asset in self.assets.values() {
            *by_type
                .entry(format!("{:?}", asset.asset_type))
                .or_insert(0) += 1;
            *by_criticality.entry(asset.criticality).or_insert(0) += 1;
            if matches!(asset.status, AssetStatus::Active) {
                active += 1;
            }
        }

        let high_value = self.assets.values().filter(|a| a.criticality >= 8).count();

        serde_json::json!({
            "total_assets": total,
            "active_assets": active,
            "high_value_assets": high_value,
            "by_type": by_type,
            "by_criticality": by_criticality,
        })
    }
}

pub fn init_asset_store() -> AssetStoreHandle {
    Arc::new(RwLock::new(AssetStore::new()))
}

// ── API Handlers ─────────────────────────────────────────────────────────

use crate::enroll::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{extract::Path, Json};

/// GET /api/assets — list all assets.
pub async fn api_list_assets(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.asset_store.read().await;
    let assets: Vec<&Asset> = store.list_all();
    Json(serde_json::json!({
        "total": assets.len(),
        "assets": assets,
    }))
}

/// GET /api/assets/stats — asset statistics.
pub async fn api_asset_stats(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.asset_store.read().await;
    Json(store.stats())
}

/// POST /api/assets — upsert an asset.
pub async fn api_upsert_asset(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let asset: Asset = match serde_json::from_value(body) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let id = asset.id.clone();
    let mut store = state.asset_store.write().await;
    store.upsert(asset);
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "upserted", "id": id})),
    )
        .into_response()
}

/// POST /api/assets/import — bulk import assets from JSON array.
pub async fn api_import_assets(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let json_str = serde_json::to_string(&body.get("assets").unwrap_or(&body)).unwrap_or_default();
    let mut store = state.asset_store.write().await;
    match store.import_json(&json_str) {
        Ok(count) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "imported", "count": count})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

/// POST /api/assets/:id/criticality — update asset criticality.
pub async fn api_update_asset_criticality(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let criticality = body
        .get("criticality")
        .and_then(|v| v.as_u64())
        .unwrap_or(5) as u8;
    let mut store = state.asset_store.write().await;
    if let Some(asset_id) = store
        .hostname_index
        .get(&id.to_lowercase())
        .cloned()
        .or_else(|| store.ip_index.get(&id).cloned())
        .or_else(|| {
            if store.assets.contains_key(&id) {
                Some(id.clone())
            } else {
                None
            }
        })
    {
        if let Some(asset) = store.assets.get_mut(&asset_id) {
            asset.criticality = criticality.clamp(1, 10);
            return (
                StatusCode::OK,
                Json(serde_json::json!({"status": "updated"})),
            )
                .into_response();
        }
    }
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "Asset not found"})),
    )
        .into_response()
}

/// DELETE /api/assets/:id — remove an asset.
pub async fn api_delete_asset(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut store = state.asset_store.write().await;
    if store.remove(&id) {
        Json(serde_json::json!({"status": "deleted"})).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Asset not found"})),
        )
            .into_response()
    }
}
