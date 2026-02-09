use anyhow::{bail, Context, Result};
use rand::{distributions::Alphanumeric, Rng};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::task;

#[derive(Debug, Clone)]
pub struct RenewalStore {
    db_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalRequestRow {
    pub id: String,
    pub agent_id: String,
    pub primary_mac: String,
    pub first_user: String,
    pub created_at_unix: i64,
    pub status: String, // pending|approved|rejected
    pub decision_by: Option<String>,
    pub decision_at_unix: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct CreateRenewalResult {
    pub request_id: String,
    pub pickup_token: String,
}

impl RenewalStore {
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
                "CREATE TABLE IF NOT EXISTS renewal_requests (
                    id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    primary_mac TEXT NOT NULL,
                    first_user TEXT NOT NULL,
                    csr_pem TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    decision_by TEXT,
                    decision_at INTEGER,
                    pickup_token TEXT NOT NULL,
                    picked_up_at INTEGER,
                    issued_cert_pem TEXT
                )",
                [],
            )
            .context("Failed to create renewal_requests table")?;
            Ok(())
        })
        .await
        .context("init_db join failed")??;
        Ok(())
    }

    pub async fn create_request(
        &self,
        agent_id: &str,
        primary_mac: &str,
        first_user: &str,
        csr_pem: &str,
    ) -> Result<CreateRenewalResult> {
        let agent_id = agent_id.trim().to_string();
        if agent_id.is_empty() {
            bail!("agent_id is empty");
        }
        if csr_pem.trim().is_empty() {
            bail!("csr is empty");
        }

        let request_id = uuid::Uuid::new_v4().to_string();
        let pickup_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();

        let mac = primary_mac.trim().to_string();
        let user = first_user.trim().to_string();
        let csr = csr_pem.to_string();

        let db_path = self.db_path.clone();
        let request_id2 = request_id.clone();
        let pickup_token2 = pickup_token.clone();

        task::spawn_blocking(move || -> Result<()> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            let now = chrono::Utc::now().timestamp();
            conn.execute(
                "INSERT INTO renewal_requests(
                    id, agent_id, primary_mac, first_user, csr_pem, created_at, status, pickup_token
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, 'pending', ?7)",
                params![request_id2, agent_id, mac, user, csr, now, pickup_token2],
            )
            .context("Failed to insert renewal_requests row")?;
            Ok(())
        })
        .await
        .context("create_request join failed")??;

        Ok(CreateRenewalResult {
            request_id,
            pickup_token,
        })
    }

    pub async fn list_recent(&self, limit: usize) -> Result<Vec<RenewalRequestRow>> {
        let limit = limit.clamp(1, 500) as i64;
        let db_path = self.db_path.clone();
        let rows = task::spawn_blocking(move || -> Result<Vec<RenewalRequestRow>> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            let mut stmt = conn
                .prepare(
                    "SELECT id, agent_id, primary_mac, first_user, created_at, status, decision_by, decision_at
                     FROM renewal_requests
                     ORDER BY created_at DESC
                     LIMIT ?1",
                )
                .context("Failed to prepare renewal_requests select")?;

            let iter = stmt
                .query_map(params![limit], |row| {
                    Ok(RenewalRequestRow {
                        id: row.get(0)?,
                        agent_id: row.get(1)?,
                        primary_mac: row.get(2)?,
                        first_user: row.get(3)?,
                        created_at_unix: row.get(4)?,
                        status: row.get(5)?,
                        decision_by: row.get(6).ok(),
                        decision_at_unix: row.get(7).ok(),
                    })
                })
                .context("Failed to query renewal_requests")?;

            let mut out = Vec::new();
            for row in iter {
                out.push(row?);
            }
            Ok(out)
        })
        .await
        .context("list_recent join failed")??;
        Ok(rows)
    }

    pub async fn approve(
        &self,
        request_id: &str,
        decision_by: &str,
        issued_cert_pem: &str,
    ) -> Result<()> {
        let request_id = request_id.trim().to_string();
        if request_id.is_empty() {
            bail!("request_id is empty");
        }
        if issued_cert_pem.trim().is_empty() {
            bail!("issued_cert_pem is empty");
        }
        let decision_by = decision_by.trim().to_string();
        let issued_cert_pem = issued_cert_pem.to_string();

        let db_path = self.db_path.clone();
        task::spawn_blocking(move || -> Result<()> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            let now = chrono::Utc::now().timestamp();
            let changed = conn
                .execute(
                    "UPDATE renewal_requests
                     SET status='approved', decision_by=?2, decision_at=?3, issued_cert_pem=?4
                     WHERE id=?1",
                    params![request_id, decision_by, now, issued_cert_pem],
                )
                .context("Failed to update renewal_requests")?;
            if changed == 0 {
                bail!("Unknown renewal request id");
            }
            Ok(())
        })
        .await
        .context("approve join failed")??;

        Ok(())
    }

    pub async fn get_for_pickup(
        &self,
        pickup_token: &str,
    ) -> Result<Option<(String /*status*/, Option<String> /*cert_pem*/)>> {
        let token = pickup_token.trim().to_string();
        if token.is_empty() {
            bail!("pickup_token is empty");
        }

        let db_path = self.db_path.clone();
        let row = task::spawn_blocking(move || -> Result<Option<(String, Option<String>, String)>> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;

            conn.query_row(
                "SELECT status, issued_cert_pem, id FROM renewal_requests WHERE pickup_token=?1",
                params![token],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .context("Failed to query renewal_requests by pickup_token")
        })
        .await
        .context("get_for_pickup join failed")??;

        let Some((status, cert_opt, request_id)) = row else {
            return Ok(None);
        };

        // If approved and cert available, mark picked_up_at and invalidate token (one-time pickup).
        if status == "approved" {
            if let Some(ref cert) = cert_opt {
                if !cert.trim().is_empty() {
                    let db_path = self.db_path.clone();
                    task::spawn_blocking(move || -> Result<()> {
                        let conn = Connection::open(&db_path).with_context(|| {
                            format!("Failed to open SQLite database at {}", db_path.display())
                        })?;
                        let now = chrono::Utc::now().timestamp();
                        conn.execute(
                            "UPDATE renewal_requests SET picked_up_at=?2, pickup_token='' WHERE id=?1",
                            params![request_id, now],
                        )
                        .context("Failed to mark renewal request picked up")?;
                        Ok(())
                    })
                    .await
                    .context("mark picked up join failed")??;
                }
            }
        }

        Ok(Some((status, cert_opt)))
    }

    pub async fn get_csr_and_agent_id(&self, request_id: &str) -> Result<(String, String)> {
        let request_id = request_id.trim().to_string();
        if request_id.is_empty() {
            bail!("request_id is empty");
        }
        let db_path = self.db_path.clone();
        let row = task::spawn_blocking(move || -> Result<Option<(String, String)>> {
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open SQLite database at {}", db_path.display()))?;
            conn.query_row(
                "SELECT agent_id, csr_pem FROM renewal_requests WHERE id=?1",
                params![request_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .context("Failed to query renewal_requests by id")
        })
        .await
        .context("get_csr_and_agent_id join failed")??;

        row.ok_or_else(|| anyhow::anyhow!("Unknown renewal request id"))
    }
}
