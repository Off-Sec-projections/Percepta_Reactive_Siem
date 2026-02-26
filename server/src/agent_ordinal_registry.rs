use anyhow::{Context, Result};
use std::collections::HashMap;
use tokio::sync::RwLock;

use percepta_server::db::Db;

/// ClickHouse-backed registry for agent display names and ordinal numbers.
/// Persists agent numbering and friendly names across browsers and restarts.
pub struct AgentOrdinalRegistry {
    db: Db,
    cache: RwLock<AgentOrdinalState>,
}

#[derive(Clone, Default)]
struct AgentOrdinalState {
    next: i64,
    by_key: HashMap<String, i64>,
    name_by_id: HashMap<String, String>,
}

impl AgentOrdinalRegistry {
    pub async fn new(db: Db) -> Result<Self> {
        let registry = Self {
            db,
            cache: RwLock::new(AgentOrdinalState::default()),
        };
        registry.init_db().await?;
        registry.reload_cache().await?;
        Ok(registry)
    }

    async fn init_db(&self) -> Result<()> {
        let client = self.db.client();
        client
            .query(
                "CREATE TABLE IF NOT EXISTS agent_ordinal_registry (\
                    agent_key String,\
                    ordinal Int64,\
                    display_name String,\
                    updated_at Int64\
                ) ENGINE = ReplacingMergeTree(updated_at)\
                ORDER BY agent_key",
            )
            .execute()
            .await
            .context("Failed to create agent_ordinal_registry table")?;
        Ok(())
    }

    async fn reload_cache(&self) -> Result<()> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            agent_key: String,
            ordinal: i64,
            display_name: String,
        }

        let rows = self
            .db
            .client()
            .query(
                "SELECT agent_key, argMax(ordinal, updated_at) AS ordinal, \
                 argMax(display_name, updated_at) AS display_name \
                 FROM agent_ordinal_registry GROUP BY agent_key",
            )
            .fetch_all::<Row>()
            .await
            .context("Failed to query agent_ordinal_registry")?;

        let mut state = self.cache.write().await;
        state.by_key.clear();
        state.name_by_id.clear();
        state.next = 1;

        for row in rows {
            let key = row.agent_key.trim().to_string();
            if key.is_empty() || row.ordinal <= 0 {
                continue;
            }
            state.by_key.insert(key.clone(), row.ordinal);
            if row.ordinal >= state.next {
                state.next = row.ordinal + 1;
            }
            let name = row.display_name.trim().to_string();
            if !name.is_empty() {
                state.name_by_id.insert(key, name);
            }
        }

        Ok(())
    }

    /// Returns all ordinals + names as a JSON-friendly struct.
    pub async fn snapshot(&self) -> (i64, HashMap<String, i64>, HashMap<String, String>) {
        let state = self.cache.read().await;
        (state.next, state.by_key.clone(), state.name_by_id.clone())
    }

    /// Bulk upsert from dashboard. Replaces the entire registry.
    pub async fn bulk_upsert(
        &self,
        next: i64,
        by_key: HashMap<String, i64>,
        name_by_id: HashMap<String, String>,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let client = self.db.client();

        #[derive(clickhouse::Row, serde::Serialize)]
        struct InsertRow {
            agent_key: String,
            ordinal: i64,
            display_name: String,
            updated_at: i64,
        }

        let mut insert = client
            .insert("agent_ordinal_registry")
            .context("prepare agent_ordinal_registry insert")?;

        // Collect all keys (ordinals + names may reference different keys).
        let mut all_keys: std::collections::HashSet<String> = by_key.keys().cloned().collect();
        for k in name_by_id.keys() {
            all_keys.insert(k.clone());
        }

        for key in &all_keys {
            let ordinal = by_key.get(key).copied().unwrap_or(0);
            let display_name = name_by_id.get(key).cloned().unwrap_or_default();
            insert
                .write(&InsertRow {
                    agent_key: key.clone(),
                    ordinal,
                    display_name,
                    updated_at: now,
                })
                .await
                .context("write agent_ordinal_registry row")?;
        }

        insert
            .end()
            .await
            .context("finalize agent_ordinal_registry insert")?;

        // Update in-memory cache.
        let mut state = self.cache.write().await;
        state.next = next.max(1);
        state.by_key = by_key;
        state.name_by_id = name_by_id;

        Ok(())
    }

    /// Clear all ordinals (reset).
    pub async fn clear_all(&self) -> Result<()> {
        self.db
            .client()
            .query("TRUNCATE TABLE agent_ordinal_registry")
            .execute()
            .await
            .context("Failed to truncate agent_ordinal_registry")?;

        let mut state = self.cache.write().await;
        state.next = 1;
        state.by_key.clear();
        state.name_by_id.clear();
        Ok(())
    }

    /// Remove a single agent from the ordinal registry.
    pub async fn remove_agent(&self, agent_id: &str) -> Result<()> {
        let agent_id = agent_id.trim();
        if agent_id.is_empty() {
            return Ok(());
        }
        self.db
            .client()
            .query("ALTER TABLE agent_ordinal_registry DELETE WHERE agent_key = ?")
            .bind(agent_id)
            .execute()
            .await
            .context("Failed to delete from agent_ordinal_registry")?;

        let mut state = self.cache.write().await;
        state.by_key.remove(agent_id);
        state.name_by_id.remove(agent_id);
        Ok(())
    }
}
