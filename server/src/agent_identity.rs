use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::PathBuf;
use tokio::task;

#[derive(Debug, Clone)]
pub struct AgentIdentityStore {
    db_path: PathBuf,
}

fn canonicalize_mac(mac: &str) -> Option<String> {
    let raw = mac.trim().to_lowercase();
    if raw.is_empty() {
        return None;
    }

    let hex_only: String = raw
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if hex_only.len() == 12 {
        let parts: Vec<&str> = (0..6)
            .map(|i| &hex_only[(i * 2)..(i * 2 + 2)])
            .collect();
        return Some(parts.join(":"));
    }

    Some(raw.replace('-', ":"))
}

impl AgentIdentityStore {
    pub async fn new(db_path: PathBuf) -> Result<Self> {
        let store = Self { db_path };
        store.init_db().await?;
        Ok(store)
    }

    async fn init_db(&self) -> Result<()> {
        let db_path = self.db_path.clone();
        task::spawn_blocking(move || -> Result<()> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_identity (
                    agent_id TEXT PRIMARY KEY,
                    primary_mac TEXT NOT NULL,
                    first_user TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )",
                [],
            )
            .context("Failed to create agent_identity table")?;
            Ok(())
        })
        .await
        .context("init_db join failed")??;
        Ok(())
    }

    /// Enforce permanent identity binding for an agent_id.
    /// - First claim inserts binding.
    /// - Subsequent claims must match.
    pub async fn upsert_or_verify(
        &self,
        agent_id: &str,
        primary_mac: &str,
        first_user: &str,
    ) -> Result<()> {
        let agent_id = agent_id.trim().to_string();
        if agent_id.is_empty() {
            bail!("agent_id is empty");
        }

        let mac = canonicalize_mac(primary_mac)
            .ok_or_else(|| anyhow::anyhow!("primary_mac is empty"))?;
        let first_user = first_user.trim().to_string();
        if first_user.is_empty() {
            bail!("first_user is empty");
        }

        let db_path = self.db_path.clone();
        task::spawn_blocking(move || -> Result<()> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            let now = chrono::Utc::now().timestamp();

            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT primary_mac, first_user FROM agent_identity WHERE agent_id = ?1",
                    params![agent_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .context("Failed to query agent_identity")?;

            match row {
                None => {
                    conn.execute(
                        "INSERT INTO agent_identity(agent_id, primary_mac, first_user, created_at, updated_at)
                         VALUES(?1, ?2, ?3, ?4, ?5)",
                        params![agent_id, mac, first_user, now, now],
                    )
                    .context("Failed to insert agent_identity")?;
                }
                Some((existing_mac, existing_user)) => {
                    let existing_mac = canonicalize_mac(&existing_mac).unwrap_or(existing_mac);
                    if existing_mac != mac || existing_user != first_user {
                        bail!(
                            "Identity mismatch for agent_id. Stored(mac={}, user={}) vs claimed(mac={}, user={})",
                            existing_mac,
                            existing_user,
                            mac,
                            first_user
                        );
                    }

                    conn.execute(
                        "UPDATE agent_identity SET updated_at = ?2 WHERE agent_id = ?1",
                        params![agent_id, now],
                    )
                    .context("Failed to update agent_identity")?;
                }
            }

            Ok(())
        })
        .await
        .context("upsert_or_verify join failed")??;

        Ok(())
    }
}
