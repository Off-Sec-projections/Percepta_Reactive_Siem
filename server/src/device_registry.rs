use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;

#[derive(Debug)]
pub struct DeviceRegistry {
    db_path: PathBuf,
    cache: RwLock<HashMap<String, String>>, // mac -> display name
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

    // Already in some other canonical form; best-effort normalize separators.
    let cleaned = raw.replace('-', ":");
    Some(cleaned)
}

impl DeviceRegistry {
    pub async fn new(db_path: PathBuf) -> Result<Self> {
        let registry = Self {
            db_path,
            cache: RwLock::new(HashMap::new()),
        };

        registry.init_db().await?;
        registry.reload_cache().await?;
        Ok(registry)
    }

    async fn init_db(&self) -> Result<()> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS device_registry (
                    mac TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                )",
                [],
            )
            .context("Failed to create device_registry table")?;
            Ok(())
        })
        .await
        .context("init_db task join failed")??;
        Ok(())
    }

    pub async fn reload_cache(&self) -> Result<()> {
        let db_path = self.db_path.clone();
        let rows: Vec<(String, String)> = tokio::task::spawn_blocking(move || -> Result<_> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            let mut stmt = conn
                .prepare("SELECT mac, name FROM device_registry")
                .context("Failed to prepare device_registry select")?;

            let mut out = Vec::new();
            let iter = stmt
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
                .context("Failed to query device_registry")?;
            for row in iter {
                out.push(row?);
            }
            Ok(out)
        })
        .await
        .context("reload_cache task join failed")??;

        let mut cache = self.cache.write().await;
        cache.clear();
        for (mac, name) in rows {
            if let Some(k) = canonicalize_mac(&mac) {
                let v = name.trim();
                if !v.is_empty() {
                    cache.insert(k, v.to_string());
                }
            }
        }
        Ok(())
    }

    pub async fn lookup_many(&self, macs: &[String]) -> HashMap<String, String> {
        let cache = self.cache.read().await;
        let mut out = HashMap::new();
        for mac in macs {
            let Some(k) = canonicalize_mac(mac) else { continue };
            if let Some(name) = cache.get(&k) {
                out.insert(k, name.clone());
            }
        }
        out
    }

    pub async fn set(&self, mac: &str, name: &str) -> Result<()> {
        let Some(k) = canonicalize_mac(mac) else {
            return Ok(());
        };
        let v = name.trim();
        if v.is_empty() {
            return self.clear(&k).await;
        }

        let db_path = self.db_path.clone();
        let k2 = k.clone();
        let v2 = v.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO device_registry(mac, name, updated_at) VALUES(?1, ?2, ?3)
                 ON CONFLICT(mac) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at",
                params![k2, v2, now],
            )
            .context("Failed to upsert device_registry row")?;
            Ok(())
        })
        .await
        .context("set task join failed")??;

        self.cache.write().await.insert(k, v.to_string());
        Ok(())
    }

    pub async fn clear(&self, mac: &str) -> Result<()> {
        let Some(k) = canonicalize_mac(mac) else {
            return Ok(());
        };

        let db_path = self.db_path.clone();
        let k2 = k.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            conn.execute("DELETE FROM device_registry WHERE mac = ?1", params![k2])
                .context("Failed to delete device_registry row")?;
            Ok(())
        })
        .await
        .context("clear task join failed")??;

        self.cache.write().await.remove(&k);
        Ok(())
    }
}
