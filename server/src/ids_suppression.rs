use anyhow::{Context, Result};
use std::collections::HashMap;
use tokio::sync::RwLock;

use percepta_server::db::Db;
use percepta_server::percepta::Event;

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdsSuppressionEntry {
    pub key: String,
    pub until_unix: i64,
    pub reason: String,
}

pub struct IdsSuppressionStore {
    db: Option<Db>,
    cache: RwLock<HashMap<String, IdsSuppressionEntry>>, // key -> entry
}

impl IdsSuppressionStore {
    pub async fn new(db: Db) -> Result<Self> {
        let store = Self {
            db: Some(db),
            cache: RwLock::new(HashMap::new()),
        };
        store.reload_cache().await?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn new_in_memory() -> Self {
        Self {
            db: None,
            cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn reload_cache(&self) -> Result<()> {
        let Some(db) = &self.db else {
            return Ok(());
        };
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct SuppressionRow {
            k: String,
            until: i64,
            reason: String,
        }

        let client = db.client();
        let rows = client
            .query(
                "SELECT k, argMax(until, updated_at) AS until, argMax(reason, updated_at) AS reason \
                 FROM ids_suppressions \
                 GROUP BY k",
            )
            .fetch_all::<SuppressionRow>()
            .await
            .context("Failed to query ids_suppressions")?;

        let mut cache = self.cache.write().await;
        cache.clear();
        for r in rows {
            if !r.k.trim().is_empty() && r.until > 0 {
                cache.insert(
                    r.k.clone(),
                    IdsSuppressionEntry {
                        key: r.k,
                        until_unix: r.until,
                        reason: r.reason,
                    },
                );
            }
        }
        Ok(())
    }

    pub async fn add(&self, key: &str, seconds: i64, reason: &str) -> Result<()> {
        let k = key.trim();
        if k.is_empty() {
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp();
        let until = now + seconds.max(60);
        let reason = reason.trim();

        if let Some(db) = &self.db {
            #[derive(clickhouse::Row, serde::Serialize)]
            struct SuppressionRow<'a> {
                k: &'a str,
                until: i64,
                reason: &'a str,
                created_at: i64,
                updated_at: i64,
            }

            let row = SuppressionRow {
                k,
                until,
                reason,
                created_at: now,
                updated_at: now,
            };

            let client = db.client();
            let mut insert = client
                .insert("ids_suppressions")
                .context("prepare ids_suppressions insert")?;
            insert
                .write(&row)
                .await
                .context("Failed to upsert ids_suppressions")?;
            insert
                .end()
                .await
                .context("Failed to finalize ids_suppressions insert")?;
        }

        let mut cache = self.cache.write().await;
        cache.insert(
            k.to_string(),
            IdsSuppressionEntry {
                key: k.to_string(),
                until_unix: until,
                reason: reason.to_string(),
            },
        );
        Ok(())
    }

    pub async fn remove(&self, key: &str) -> Result<()> {
        let k = key.trim();
        if k.is_empty() {
            return Ok(());
        }
        if let Some(db) = &self.db {
            let client = db.client();
            client
                .query("ALTER TABLE ids_suppressions DELETE WHERE k = ?")
                .bind(k)
                .execute()
                .await
                .context("Failed to delete ids_suppressions")?;
        }
        let mut cache = self.cache.write().await;
        cache.remove(k);
        Ok(())
    }

    pub async fn list(&self) -> Vec<IdsSuppressionEntry> {
        let now = chrono::Utc::now().timestamp();
        let cache = self.cache.read().await;
        let mut out: Vec<IdsSuppressionEntry> = cache
            .values()
            .filter(|e| e.until_unix > now)
            .cloned()
            .collect();
        out.sort_by_key(|e| e.until_unix);
        out
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let Some(db) = &self.db else {
            return Ok(0);
        };
        let now = chrono::Utc::now().timestamp();
        let client = db.client();
        client
            .query("ALTER TABLE ids_suppressions DELETE WHERE until < ?")
            .bind(now)
            .execute()
            .await
            .context("Failed to cleanup ids_suppressions")?;
        let _ = self.reload_cache().await;
        Ok(0)
    }

    pub async fn is_suppressed(&self, key: &str) -> bool {
        let k = key.trim();
        if k.is_empty() {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.get(k) {
            if entry.until_unix > now {
                return true;
            }
            cache.remove(k);
        }
        false
    }

    pub async fn match_event_suppression(&self, event: &Event) -> Option<String> {
        let now = chrono::Utc::now().timestamp();
        let direct_keys = ids_suppression_keys_from_event(event);
        let context = suppression_context_from_event(event);
        let mut cache = self.cache.write().await;

        let mut expired: Vec<String> = Vec::new();
        for (k, entry) in cache.iter() {
            if entry.until_unix <= now {
                expired.push(k.clone());
                continue;
            }

            if direct_keys.iter().any(|dk| dk == k) {
                return Some(k.clone());
            }

            if let Some(expr) = k.strip_prefix("expr:") {
                if suppression_expr_matches(expr, &context) {
                    return Some(k.clone());
                }
            }
        }

        for key in expired {
            cache.remove(&key);
        }
        None
    }
}

fn suppression_context_from_event(event: &Event) -> HashMap<String, String> {
    let mut ctx = HashMap::new();

    if let Some(sid) = event
        .metadata
        .get("ids.sid")
        .or_else(|| event.metadata.get("suricata.sid"))
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
    {
        ctx.insert("sid".to_string(), sid.to_string());
    }

    if let Some(sig) = event
        .metadata
        .get("ids.signature")
        .or_else(|| event.metadata.get("suricata.signature"))
        .or_else(|| event.metadata.get("signature"))
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
    {
        ctx.insert("sig".to_string(), sig);
    }

    if let Some(agent_id) = event
        .agent
        .as_ref()
        .map(|a| a.id.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        ctx.insert("agent".to_string(), agent_id);
    }

    if let Some(src_ip) = event
        .network
        .as_ref()
        .map(|n| n.src_ip.trim().to_string())
        .or_else(|| {
            event
                .metadata
                .get("src_ip")
                .or_else(|| event.metadata.get("source_ip"))
                .or_else(|| event.metadata.get("attacker_ip"))
                .map(|v| v.trim().to_string())
        })
        .filter(|v| !v.is_empty())
    {
        ctx.insert("src_ip".to_string(), src_ip);
    }

    if let Some(dst_ip) = event
        .network
        .as_ref()
        .map(|n| n.dst_ip.trim().to_string())
        .or_else(|| {
            event
                .metadata
                .get("dest_ip")
                .or_else(|| event.metadata.get("dst_ip"))
                .map(|v| v.trim().to_string())
        })
        .filter(|v| !v.is_empty())
    {
        ctx.insert("dst_ip".to_string(), dst_ip);
    }

    if let Some(process) = event
        .process
        .as_ref()
        .map(|p| p.name.trim().to_lowercase())
        .or_else(|| {
            event
                .metadata
                .get("process.name")
                .or_else(|| event.metadata.get("proc"))
                .map(|v| v.trim().to_lowercase())
        })
        .filter(|v| !v.is_empty())
    {
        ctx.insert("process".to_string(), process);
    }

    if let Some(user) = event
        .user
        .as_ref()
        .map(|u| u.name.trim().to_lowercase())
        .or_else(|| {
            event
                .metadata
                .get("user")
                .or_else(|| event.metadata.get("username"))
                .or_else(|| event.metadata.get("account_name"))
                .map(|v| v.trim().to_lowercase())
        })
        .filter(|v| !v.is_empty())
    {
        ctx.insert("user".to_string(), user);
    }

    ctx
}

fn suppression_expr_matches(expr: &str, ctx: &HashMap<String, String>) -> bool {
    let mut matched_any = false;
    for raw_clause in expr.split(',') {
        let clause = raw_clause.trim();
        if clause.is_empty() {
            continue;
        }
        let (field_raw, expected_raw) = match clause.split_once('=') {
            Some(v) => v,
            None => return false,
        };
        let field = field_raw.trim().to_lowercase();
        let expected = expected_raw.trim().to_lowercase();
        if field.is_empty() || expected.is_empty() {
            return false;
        }

        let Some(actual) = ctx.get(&field) else {
            return false;
        };
        if actual.to_lowercase() != expected {
            return false;
        }
        matched_any = true;
    }
    matched_any
}

pub fn ids_suppression_keys_from_event(event: &Event) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();

    let sid = event
        .metadata
        .get("ids.sid")
        .or_else(|| event.metadata.get("suricata.sid"))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    let sig = event
        .metadata
        .get("ids.signature")
        .or_else(|| event.metadata.get("suricata.signature"))
        .or_else(|| event.metadata.get("signature"))
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty());

    let agent = event
        .agent
        .as_ref()
        .map(|a| a.id.trim().to_string())
        .filter(|v| !v.is_empty());

    let src_ip = event
        .network
        .as_ref()
        .map(|n| n.src_ip.trim().to_string())
        .or_else(|| {
            event
                .metadata
                .get("src_ip")
                .or_else(|| event.metadata.get("source_ip"))
                .or_else(|| event.metadata.get("attacker_ip"))
                .map(|v| v.trim().to_string())
        })
        .filter(|v| !v.is_empty());

    let dst_ip = event
        .network
        .as_ref()
        .map(|n| n.dst_ip.trim().to_string())
        .or_else(|| {
            event
                .metadata
                .get("dest_ip")
                .or_else(|| event.metadata.get("dst_ip"))
                .map(|v| v.trim().to_string())
        })
        .filter(|v| !v.is_empty());

    let process = event
        .process
        .as_ref()
        .map(|p| p.name.trim().to_lowercase())
        .or_else(|| {
            event
                .metadata
                .get("process.name")
                .or_else(|| event.metadata.get("proc"))
                .map(|v| v.trim().to_lowercase())
        })
        .filter(|v| !v.is_empty());

    let username = event
        .user
        .as_ref()
        .map(|u| u.name.trim().to_lowercase())
        .or_else(|| {
            event
                .metadata
                .get("user")
                .or_else(|| event.metadata.get("username"))
                .or_else(|| event.metadata.get("account_name"))
                .map(|v| v.trim().to_lowercase())
        })
        .filter(|v| !v.is_empty());

    if let Some(s) = sid.as_deref() {
        keys.push(format!("sid:{}", s));
    }
    if let Some(s) = sig.as_deref() {
        keys.push(format!("sig:{}", s));
    }

    if let (Some(s), Some(a)) = (sid.as_deref(), agent.as_deref()) {
        keys.push(format!("sid:{}:agent:{}", s, a));
    }
    if let (Some(s), Some(ip)) = (sid.as_deref(), src_ip.as_deref()) {
        keys.push(format!("sid:{}:src_ip:{}", s, ip));
    }
    if let (Some(s), Some(ip)) = (sid.as_deref(), dst_ip.as_deref()) {
        keys.push(format!("sid:{}:dst_ip:{}", s, ip));
    }
    if let (Some(s), Some(p)) = (sid.as_deref(), process.as_deref()) {
        keys.push(format!("sid:{}:process:{}", s, p));
    }
    if let (Some(s), Some(u)) = (sid.as_deref(), username.as_deref()) {
        keys.push(format!("sid:{}:user:{}", s, u));
    }

    if let (Some(s), Some(a)) = (sig.as_deref(), agent.as_deref()) {
        keys.push(format!("sig:{}:agent:{}", s, a));
    }
    if let (Some(s), Some(ip)) = (sig.as_deref(), src_ip.as_deref()) {
        keys.push(format!("sig:{}:src_ip:{}", s, ip));
    }
    if let (Some(s), Some(ip)) = (sig.as_deref(), dst_ip.as_deref()) {
        keys.push(format!("sig:{}:dst_ip:{}", s, ip));
    }
    if let (Some(s), Some(p)) = (sig.as_deref(), process.as_deref()) {
        keys.push(format!("sig:{}:process:{}", s, p));
    }
    if let (Some(s), Some(u)) = (sig.as_deref(), username.as_deref()) {
        keys.push(format!("sig:{}:user:{}", s, u));
    }

    keys
}

pub fn ids_suppression_key_from_event(event: &Event) -> Option<String> {
    ids_suppression_keys_from_event(event).into_iter().next()
}
