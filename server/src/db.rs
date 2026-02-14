use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};

const CH_MODE_NONE: u8 = 0;
const CH_MODE_EMBEDDED: u8 = 1;
const CH_MODE_DOCKER: u8 = 2;
const CH_MODE_SYSTEMD: u8 = 3;

/// Tracks how ClickHouse was started (if at all).
static CH_MANAGED_MODE: AtomicU8 = AtomicU8::new(CH_MODE_NONE);

/// ClickHouse database handle with basic health-check and retry.
///
/// Percepta SIEM uses ClickHouse for durable event storage and metadata.
#[derive(Clone)]
pub struct Db {
    client: clickhouse::Client,
    url: String,
    database: String,
    ch_user: String,
    ch_password: String,
}

impl Db {
    pub fn new(client: clickhouse::Client) -> Self {
        Self {
            client,
            url: String::new(),
            database: String::new(),
            ch_user: String::new(),
            ch_password: String::new(),
        }
    }

    pub fn new_with_meta(
        client: clickhouse::Client,
        url: String,
        database: String,
        ch_user: String,
        ch_password: String,
    ) -> Self {
        Self {
            client,
            url,
            database,
            ch_user,
            ch_password,
        }
    }

    pub fn client(&self) -> &clickhouse::Client {
        &self.client
    }

    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn database(&self) -> &str {
        &self.database
    }
    pub fn ch_user(&self) -> &str {
        &self.ch_user
    }
    pub fn ch_password(&self) -> &str {
        &self.ch_password
    }

    /// Lightweight connectivity check.
    pub async fn is_healthy(&self) -> bool {
        self.client
            .query("SELECT 1")
            .fetch_one::<u8>()
            .await
            .is_ok()
    }

    /// Execute a ClickHouse insert with retry (up to 3 attempts, exponential backoff).
    pub async fn retry_insert<F, Fut>(&self, description: &str, f: F) -> Result<()>
    where
        F: Fn(clickhouse::Client) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        let mut last_err = None;
        for attempt in 0..3u32 {
            match f(self.client.clone()).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::warn!(
                        "ClickHouse {} failed (attempt {}/3): {:#}",
                        description,
                        attempt + 1,
                        e
                    );
                    last_err = Some(e);
                    if attempt < 2 {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            200 * 2u64.pow(attempt),
                        ))
                        .await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("retry_insert exhausted")))
    }
}

pub fn db_url_from_env() -> Option<String> {
    std::env::var("PERCEPTA_CH_URL")
        .ok()
        .or_else(|| std::env::var("PERCEPTA_CLICKHOUSE_URL").ok())
        .or_else(|| std::env::var("PERCEPTA_DB_URL").ok())
        .or_else(|| std::env::var("PERCEPTA_DATABASE_URL").ok())
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .and_then(|s| {
            let t = s.trim().to_string();
            if t.is_empty() {
                None
            } else {
                Some(t)
            }
        })
}

pub fn db_urls_from_env() -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();

    for key in [
        "PERCEPTA_CH_URLS",
        "PERCEPTA_CLICKHOUSE_URLS",
        "PERCEPTA_DB_URLS",
    ] {
        if let Ok(raw) = std::env::var(key) {
            for item in raw.split(',') {
                let t = item.trim();
                if !t.is_empty() {
                    urls.push(t.to_string());
                }
            }
        }
    }

    if let Some(single) = db_url_from_env() {
        if !urls.iter().any(|u| u == &single) {
            urls.push(single);
        }
    }

    urls
}

pub fn clickhouse_db_name() -> String {
    let name = std::env::var("PERCEPTA_CH_DB")
        .ok()
        .or_else(|| std::env::var("PERCEPTA_DB_NAME").ok())
        .unwrap_or_else(|| "percepta".to_string());
    // Validate: only alphanumeric + underscore to prevent DDL injection
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        tracing::error!("ClickHouse database name must be alphanumeric/underscore, got: {name} — falling back to 'percepta'");
        return "percepta".to_string();
    }
    name
}

fn clickhouse_user() -> String {
    std::env::var("PERCEPTA_CH_USER").unwrap_or_else(|_| "default".to_string())
}

fn clickhouse_password() -> String {
    // If explicitly set via env var, use it as-is (including empty string).
    if std::env::var_os("PERCEPTA_CH_PASSWORD").is_some() {
        return std::env::var("PERCEPTA_CH_PASSWORD").unwrap_or_default();
    }
    // Auto-generate on first startup (DigitalOcean-style).
    // Key is persisted to a file so it survives restarts.
    let key_path = std::env::var("PERCEPTA_CH_KEY_FILE").unwrap_or_else(|_| {
        let base = crate::base_dir();
        base.parent()
            .unwrap_or(&base)
            .join("data")
            .join("percepta")
            .join(".ch_key")
            .to_string_lossy()
            .to_string()
    });
    let key_path = std::path::Path::new(&key_path);
    if let Ok(existing) = std::fs::read_to_string(key_path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }
    // Generate a 64-byte (128 hex chars) cryptographically random key.
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let key_bytes: Vec<u8> = (0..64).map(|_| rng.gen::<u8>()).collect();
    let key_hex: String = key_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    // Persist the key with restricted permissions.
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(key_path, &key_hex) {
        tracing::error!(
            "Failed to persist ClickHouse key to {}: {e}",
            key_path.display()
        );
    } else {
        // Restrict file permissions to owner-only on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
        }
        tracing::info!("Generated ClickHouse access key → {}", key_path.display());
        tracing::info!("Key (first 16 chars): {}...", &key_hex[..16]);
    }
    key_hex
}

pub fn default_local_db_url() -> String {
    "http://localhost:8123".to_string()
}

pub async fn connect_clickhouse(
    db_url: &str,
    database: &str,
) -> Result<(clickhouse::Client, String, String)> {
    let url = db_url.trim();
    if url.is_empty() {
        anyhow::bail!("ClickHouse URL is empty");
    }

    let user = clickhouse_user();
    let password = clickhouse_password();
    let is_local = url.contains("localhost") || url.contains("127.0.0.1");

    // On localhost, always run bootstrap to self-heal grants that may have
    // failed in a prior run (e.g. GRANT ALL failing on CH 26.3).
    if is_local {
        tracing::info!("🗄️ Ensuring ClickHouse user/grants are correct…");
        match bootstrap_ch_user(url, database, &user, &password).await {
            Ok((bootstrapped, effective_user)) => {
                return Ok((bootstrapped, effective_user, password));
            }
            Err(e) => {
                tracing::warn!("🗄️ Bootstrap attempt: {e:#}");
                // Fall through to try direct connect anyway.
            }
        }
    }

    let client = clickhouse::Client::default()
        .with_url(url)
        .with_user(&user)
        .with_password(&password)
        .with_database(database);

    // Validate connectivity with a lightweight query.
    match client.query("SELECT 1").fetch_one::<u8>().await {
        Ok(_) => Ok((client, user, password)),
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("UNKNOWN_DATABASE") {
                if !database.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    anyhow::bail!("Invalid database name '{}': only ASCII alphanumeric and underscores allowed", database);
                }
                let admin = clickhouse::Client::default()
                    .with_url(url)
                    .with_user(&user)
                    .with_password(&password)
                    .with_database("default");
                admin
                    .query(&format!("CREATE DATABASE IF NOT EXISTS {database}"))
                    .execute()
                    .await
                    .context("create ClickHouse database")?;
                return Ok((client, user, password));
            }
            anyhow::bail!("Failed to connect to ClickHouse as '{user}': {e:#}");
        }
    }
}

pub async fn connect_clickhouse_any(
    db_urls: &[String],
    database: &str,
) -> Result<(clickhouse::Client, String, String, String)> {
    let mut errors: Vec<String> = Vec::new();

    for raw in db_urls {
        let url = raw.trim();
        if url.is_empty() {
            continue;
        }

        match connect_clickhouse(url, database).await {
            Ok((client, effective_user, effective_password)) => {
                return Ok((client, url.to_string(), effective_user, effective_password));
            }
            Err(e) => errors.push(format!("{} => {}", url, e)),
        }
    }

    anyhow::bail!(
        "No ClickHouse endpoint reachable. Tried {} endpoint(s): {}",
        db_urls.len(),
        errors.join(" | ")
    )
}

/// Bootstrap a ClickHouse user by connecting passwordless as 'default'
/// and creating/updating the desired user with the given password.
async fn bootstrap_ch_user(
    url: &str,
    database: &str,
    user: &str,
    password: &str,
) -> Result<(clickhouse::Client, String)> {
    // Sanitize: only allow alphanumeric + underscore for user name.
    if !user.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!("Invalid ClickHouse user name: {user}");
    }

    // If explicitly configured to use `default`, prefer using it directly.
    // Some local/dev configs use XML-managed users without writable access
    // storages, where CREATE USER is expected to fail.
    if user == "default" {
        let mut candidate_passwords = vec![password.to_string()];
        if !password.is_empty() {
            candidate_passwords.push(String::new());
        }

        for pw in candidate_passwords {
            let client = clickhouse::Client::default()
                .with_url(url)
                .with_user("default")
                .with_password(&pw)
                .with_database(database);

            if client.query("SELECT 1").fetch_one::<u8>().await.is_ok() {
                tracing::info!("🗄️ Using ClickHouse default user directly (local/dev mode)");
                return Ok((client, "default".to_string()));
            }
        }

        anyhow::bail!(
            "Configured ClickHouse user is 'default', but authentication failed with provided credentials"
        );
    }

    // Connect as 'default' (try empty password, then configured password).
    let mut root = clickhouse::Client::default()
        .with_url(url)
        .with_user("default")
        .with_password("");
    if root.query("SELECT 1").fetch_one::<u8>().await.is_err() {
        if !password.is_empty() {
            root = clickhouse::Client::default()
                .with_url(url)
                .with_user("default")
                .with_password(password);
            root.query("SELECT 1")
                .fetch_one::<u8>()
                .await
                .context("Cannot reach ClickHouse using configured default password")?;
        } else {
            anyhow::bail!("Cannot reach ClickHouse even as passwordless default");
        }
    }

    let target = user;

    tracing::info!("🗄️ Bootstrapping ClickHouse user '{target}'…");

    // CREATE or update the user.
    // ClickHouse escapes single quotes by doubling them ('').
    let escaped_pw = password.replace('\'', "''");
    let create_sql = format!(
        "CREATE USER IF NOT EXISTS {target} IDENTIFIED BY '{pw}' SETTINGS PROFILE 'default'",
        target = target,
        pw = escaped_pw,
    );
    if let Err(e) = root.query(&create_sql).execute().await {
        tracing::error!("CREATE USER {target} failed: {e:#}");
        anyhow::bail!("Failed to CREATE USER {target}: {e:#}");
    }

    // Update password if user already existed with a different one.
    let alter_sql = format!(
        "ALTER USER {target} IDENTIFIED BY '{pw}'",
        target = target,
        pw = escaped_pw,
    );
    let _ = root.query(&alter_sql).execute().await;

    // GRANT CURRENT GRANTS — compatible with CH 26.3+ (GRANT ALL fails on
    // SHOW NAMED COLLECTIONS SECRETS which the default user doesn't hold).
    let grant_sql = format!("GRANT CURRENT GRANTS ON *.* TO {target} WITH GRANT OPTION");
    if let Err(e) = root.query(&grant_sql).execute().await {
        tracing::warn!("GRANT CURRENT GRANTS failed: {e:#}, trying specific grants…");
        // Fallback: grant the essentials individually.
        for g in [
            format!("GRANT SELECT, INSERT, ALTER, CREATE, DROP, TRUNCATE, SHOW ON *.* TO {target}"),
            format!("GRANT dictGet, addressToLine, addressToLineWithInlines, addressToSymbol, demangle ON *.* TO {target}"),
        ] {
            let _ = root.query(&g).execute().await;
        }
    }

    tracing::info!("🗄️ User '{target}' ready with configured password");

    let client = clickhouse::Client::default()
        .with_url(url)
        .with_user(target)
        .with_password(password)
        .with_database(database);
    client
        .query("SELECT 1")
        .fetch_one::<u8>()
        .await
        .context("Cannot connect as bootstrapped user")?;
    Ok((client, target.to_string()))
}

/// Initialize ClickHouse schema for all server components.
/// This is idempotent and safe to call on startup.
pub async fn init_clickhouse_schema(client: &clickhouse::Client, database: &str) -> Result<()> {
    // Prevent SQL injection: database name must be a safe identifier
    if !database.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!("Invalid database name '{}': only ASCII alphanumeric and underscores allowed", database);
    }
    let admin = client.clone().with_database("default");
    admin
        .query(&format!("CREATE DATABASE IF NOT EXISTS {database}"))
        .execute()
        .await
        .context("create ClickHouse database")?;

    // CRITICAL: Schema version tracking to prevent incompatible upgrades
    // Stores the schema version that created the database.
    // Future versions check this on startup to detect incompatible schemas.
    const SCHEMA_VERSION: &str = "1"; // Increment when making breaking schema changes
    
    admin
        .query(&format!(
            "CREATE TABLE IF NOT EXISTS {database}._schema_version (\
                version String,\
                created_at DateTime DEFAULT now()\
            ) ENGINE = ReplacingMergeTree()\
            ORDER BY version"
        ))
        .execute()
        .await
        .context("create schema version tracking table")?;
    
    // Check if schema version already exists
    let result: Vec<String> = admin
        .query(&format!("SELECT version FROM {database}._schema_version ORDER BY created_at DESC LIMIT 1"))
        .fetch_all()
        .await
        .unwrap_or_default();
    
    if !result.is_empty() {
        let stored_version = &result[0];
        if stored_version != SCHEMA_VERSION {
            return Err(anyhow::anyhow!(
                "CRITICAL DATABASE INCOMPATIBILITY: \
                Schema version mismatch. This server expects version {} \
                but the database was created with version {}. \
                Please backup the database and perform a migration. \
                See: https://docs.percepta-siem.io/migrations",
                SCHEMA_VERSION, stored_version
            ));
        }
        tracing::info!("✓ Schema version matches: {}", SCHEMA_VERSION);
    } else {
        // First time initialization - record the schema version
        admin
            .query(&format!(
                "INSERT INTO {database}._schema_version (version) VALUES ('{}')",
                SCHEMA_VERSION
            ))
            .execute()
            .await
            .context("record schema version")?;
        tracing::info!("✓ Initialized schema version: {}", SCHEMA_VERSION);
    }

    // Shared app_config table for persisted settings (credentials, playbooks, etc.).
    client
        .query(
            "CREATE TABLE IF NOT EXISTS app_config (\
                k String,\
                v String,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY k",
        )
        .execute()
        .await
        .context("create app_config table")?;

    // Events store (hash dedupe + time range search)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS events (\
                hash String,\
                timestamp Int64,\
                version UInt64,\
                content String\
            ) ENGINE = ReplacingMergeTree(version)\
            ORDER BY (timestamp, hash)",
        )
        .execute()
        .await
        .context("create events table")?;

    // Forward-compatible migration for existing deployments.
    // Existing tables created before `version` still operate; this adds the column lazily.
    client
        .query("ALTER TABLE events ADD COLUMN IF NOT EXISTS version UInt64 DEFAULT toUInt64(timestamp)")
        .execute()
        .await
        .context("migrate events table version column")?;

    // Best-effort skip indexes for faster selective reads on common predicates.
    // Keep startup resilient if ClickHouse version/config does not support an index type.
    for (name, ddl) in [
        (
            "events.idx_hash_bf",
            "ALTER TABLE events ADD INDEX IF NOT EXISTS idx_hash_bf hash TYPE bloom_filter(0.01) GRANULARITY 64",
        ),
        (
            "events.idx_content_ngram",
            "ALTER TABLE events ADD INDEX IF NOT EXISTS idx_content_ngram content TYPE ngrambf_v1(3, 256, 2, 0) GRANULARITY 64",
        ),
    ] {
        if let Err(e) = client.query(ddl).execute().await {
            tracing::warn!("Skipping optional ClickHouse index {name}: {:#}", e);
        }
    }

    // Alert suppressions
    client
        .query(
            "CREATE TABLE IF NOT EXISTS alert_suppressions (\
                k String,\
                until Int64,\
                reason String,\
                created_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY k",
        )
        .execute()
        .await
        .context("create alert_suppressions table")?;

    // IDS suppressions (signature/sid-based)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS ids_suppressions (\
                k String,\
                until Int64,\
                reason String,\
                created_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY k",
        )
        .execute()
        .await
        .context("create ids_suppressions table")?;

    // Device registry
    client
        .query(
            "CREATE TABLE IF NOT EXISTS device_registry (\
                mac String,\
                name String,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY mac",
        )
        .execute()
        .await
        .context("create device_registry table")?;

    // Agent identity binding
    client
        .query(
            "CREATE TABLE IF NOT EXISTS agent_identity (\
                agent_id String,\
                primary_mac String,\
                first_user String,\
                created_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY agent_id",
        )
        .execute()
        .await
        .context("create agent_identity table")?;

    // Renewal requests
    client
        .query(
            "CREATE TABLE IF NOT EXISTS renewal_requests (\
                id String,\
                agent_id String,\
                primary_mac String,\
                first_user String,\
                csr_pem String,\
                created_at Int64,\
                status String,\
                decision_by String,\
                decision_at Int64,\
                pickup_token String,\
                picked_up_at Int64,\
                issued_cert_pem String,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create renewal_requests table")?;

    // Reactive audit (append-only)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS reactive_audit (\
                id String,\
                ts_unix Int64,\
                actor String,\
                role String,\
                action String,\
                target_type String,\
                target_value String,\
                ttl_seconds Int64,\
                reason String,\
                context_alert_id String,\
                ok UInt8\
            ) ENGINE = MergeTree()\
            ORDER BY (ts_unix, id)",
        )
        .execute()
        .await
        .context("create reactive_audit table")?;

    // Reactive block state (replica-safe via append+replace semantics)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS reactive_blocks (\
                target_type String,\
                value String,\
                until Int64,\
                created_at Int64,\
                created_by String,\
                reason String,\
                deleted UInt8,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY (target_type, value)",
        )
        .execute()
        .await
        .context("create reactive_blocks table")?;

    // Alert persistence (dual-write: in-memory HashMap + ClickHouse)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS alerts (\
                id String,\
                dedup_key String,\
                content String,\
                first_seen Int64,\
                last_seen Int64,\
                status String,\
                severity String,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY (id)",
        )
        .execute()
        .await
        .context("create alerts table")?;

    // Analyst notes (per-event/alert notes persisted server-side)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS analyst_notes (\
                entity_id String,\
                entity_type String,\
                note String,\
                author String,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY (entity_type, entity_id)",
        )
        .execute()
        .await
        .context("create analyst_notes table")?;

    // ── New persistence tables (GAP fixes) ────────────────────────────────

    // IOC / Threat Intelligence persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS iocs (\
                id String,\
                value String,\
                ioc_type String,\
                source String,\
                severity String,\
                description String,\
                false_positive UInt8 DEFAULT 0,\
                tags String DEFAULT '',\
                hit_count UInt64 DEFAULT 0,\
                created_at Int64,\
                expires_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY (ioc_type, value)",
        )
        .execute()
        .await
        .context("create iocs table")?;

    // Migrate legacy iocs table: add columns that may be missing
    for stmt in &[
        "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS id String DEFAULT ''",
        "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS false_positive UInt8 DEFAULT 0",
        "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS tags String DEFAULT ''",
        "ALTER TABLE iocs ADD COLUMN IF NOT EXISTS hit_count UInt64 DEFAULT 0",
    ] {
        let _ = client.query(stmt).execute().await;
    }

    client
        .query(
            "CREATE TABLE IF NOT EXISTS rbac_users (\
                username String,\
                password_hash String,\
                display_name String,\
                role_id String,\
                enabled UInt8,\
                created_at String,\
                last_login String,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY username",
        )
        .execute()
        .await
        .context("create rbac_users table")?;

    // RBAC roles persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS rbac_roles (\
                id String,\
                name String,\
                description String,\
                permissions Array(String),\
                is_builtin UInt8,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create rbac_roles table")?;

    // Cases persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS cases (\
                id String,\
                title String,\
                status String,\
                severity String,\
                assignee String,\
                description String,\
                alert_ids String,\
                comments String,\
                created_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create cases table")?;

    // Saved searches persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS saved_searches (\
                id String,\
                name String,\
                query String,\
                filters String,\
                created_at String,\
                deleted UInt8,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create saved_searches table")?;

    // Vulnerabilities persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS vulnerabilities (\
                cve_id String,\
                severity String,\
                hostname String,\
                description String,\
                status String,\
                references String,\
                exploited_in_wild UInt8,\
                discovered_at Int64,\
                updated_at String,\
                version Int64\
            ) ENGINE = ReplacingMergeTree(version)\
            ORDER BY cve_id",
        )
        .execute()
        .await
        .context("create vulnerabilities table")?;

    // DLP patterns persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS dlp_patterns (\
                id String,\
                name String,\
                pattern_type String,\
                pattern String,\
                severity String,\
                enabled UInt8,\
                created_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create dlp_patterns table")?;

    // API keys persistence (stores hashed keys only)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS api_keys (\
                id String,\
                name String,\
                key_hash String,\
                prefix String,\
                role_id String,\
                enabled UInt8,\
                created_at Int64,\
                expires_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create api_keys table")?;

    // Webhook subscriptions persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS webhooks (\
                id String,\
                name String,\
                url String,\
                events String,\
                enabled UInt8,\
                secret String,\
                headers String,\
                created_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create webhooks table")?;

    // Sessions persistence (survive server restarts)
    client
        .query(
            "CREATE TABLE IF NOT EXISTS sessions (\
                token String,\
                username String,\
                role String,\
                expires_at Int64,\
                last_active Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY token",
        )
        .execute()
        .await
        .context("create sessions table")?;

    // Playbook run history — CONSOLIDATED SCHEMA
    // Note: playbooks.rs also defines this table. This definition is kept for reference
    // but playbooks::Playbook::init_schema() is responsible for table creation.
    // DO NOT create duplicate tables. The playbooks.rs schema is authoritative.

    // Escalations persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS escalations (\
                id String,\
                created_at Int64,\
                created_by String,\
                title String,\
                event_hash String,\
                description String,\
                status String,\
                decision_by String,\
                decision_at Int64,\
                decision_note String,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create escalations table")?;

    // Reports persistence
    client
        .query(
            "CREATE TABLE IF NOT EXISTS reports (\
                id String,\
                report_type String,\
                period String,\
                content String,\
                generated_at Int64,\
                updated_at Int64\
            ) ENGINE = ReplacingMergeTree(updated_at)\
            ORDER BY id",
        )
        .execute()
        .await
        .context("create reports table")?;

    // Honeypot config persistence (single-row via app_config)
    // Uses existing app_config table created by notifications module

    // ── Event table partitioning & TTL (GAP 22) ──────────────────────────
    // Add monthly partitioning and 90-day TTL.
    // These are ALTER TABLE statements — they are idempotent and safe.
    let ttl_days: u64 = std::env::var("PERCEPTA_EVENT_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90);
    let ttl_ddl = format!(
        "ALTER TABLE events MODIFY TTL toDateTime(timestamp) + INTERVAL {} DAY",
        ttl_days
    );
    if let Err(e) = client.query(&ttl_ddl).execute().await {
        tracing::warn!(
            "Optional: event TTL not set (may already exist or CH version issue): {:#}",
            e
        );
    }

    Ok(())
}

// ── ClickHouse Lifecycle Management ────────────────────────────────────────
//
// Auto-start ClickHouse when the SIEM server boots, auto-stop when it exits.
// Skipped when PERCEPTA_CH_MANAGED=0 or when connecting to a remote endpoint.

/// Try to ensure ClickHouse is running before we connect.
/// Returns `true` if we started it ourselves (and should stop it later).
pub async fn ensure_clickhouse_running() -> bool {
    // Opt-out: PERCEPTA_CH_MANAGED=0 disables lifecycle management.
    if std::env::var("PERCEPTA_CH_MANAGED").as_deref() == Ok("0") {
        tracing::info!("🗄️ ClickHouse lifecycle management disabled (PERCEPTA_CH_MANAGED=0)");
        return false;
    }

    // Only manage local instances.
    let urls = db_urls_from_env();
    let is_local = urls.is_empty()
        || urls
            .iter()
            .all(|u| u.contains("localhost") || u.contains("127.0.0.1") || u.contains("0.0.0.0"));
    if !is_local {
        tracing::info!("🗄️ Remote ClickHouse endpoint detected — skipping lifecycle management");
        return false;
    }

    // Quick ping: is it already running?
    if is_ch_reachable().await {
        tracing::info!("🗄️ ClickHouse already running");
        return false;
    }

    tracing::info!("🗄️ ClickHouse not running — attempting to start…");

    let mut started_mode = None;
    if try_start_embedded().await {
        started_mode = Some(CH_MODE_EMBEDDED);
    } else if std::env::var("PERCEPTA_CH_DOCKER_FALLBACK").as_deref() == Ok("1")
        && try_start_docker_compose().await
    {
        started_mode = Some(CH_MODE_DOCKER);
    } else if std::env::var("PERCEPTA_CH_SYSTEMD_FALLBACK").as_deref() == Ok("1")
        && try_start_systemctl().await
    {
        started_mode = Some(CH_MODE_SYSTEMD);
    }

    if started_mode.is_none() {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        if try_start_embedded().await {
            started_mode = Some(CH_MODE_EMBEDDED);
        }
    }

    // Wait up to 30 seconds for it to become healthy.
    for i in 0..60 {
        if is_ch_reachable().await {
            tracing::info!("🗄️ ClickHouse ready (took ~{}ms)", i * 500);
            if let Some(mode) = started_mode {
                CH_MANAGED_MODE.store(mode, Ordering::SeqCst);
                return true;
            }
            return false;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    if started_mode.is_some() {
        tracing::warn!("🗄️ ClickHouse process launched but did not become reachable within 30s");
    } else {
        tracing::warn!(
            "🗄️ Could not start ClickHouse — set PERCEPTA_CH_EMBEDDED_BIN or enable PERCEPTA_CH_DOCKER_FALLBACK / PERCEPTA_CH_SYSTEMD_FALLBACK"
        );
    }
    false
}

/// Stop ClickHouse if we started it. Called on SIEM server shutdown.
pub async fn stop_clickhouse_if_managed() {
    let mode = CH_MANAGED_MODE.load(Ordering::SeqCst);
    if mode == CH_MODE_NONE {
        return;
    }
    tracing::info!("🗄️ Stopping managed ClickHouse instance…");

    match mode {
        CH_MODE_EMBEDDED => {
            let _ = tokio::process::Command::new("pkill")
                .args(["-TERM", "clickhouse-server"])
                .output()
                .await;
            tracing::info!("🗄️ Sent SIGTERM to clickhouse-server");
        }
        CH_MODE_SYSTEMD => {
            let result = tokio::process::Command::new("systemctl")
                .args(["stop", "clickhouse-server"])
                .output()
                .await;
            if matches!(result, Ok(out) if out.status.success()) {
                tracing::info!("🗄️ ClickHouse stopped via systemctl");
            }
        }
        CH_MODE_DOCKER => {
            tracing::info!("🗄️ Managed ClickHouse was started via docker; leaving it running");
        }
        _ => {}
    }

    CH_MANAGED_MODE.store(CH_MODE_NONE, Ordering::SeqCst);
}

fn clickhouse_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PERCEPTA_CH_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(d) = std::env::var("PERCEPTA_BASE_DIR") {
        let p = PathBuf::from(&d);
        if p.is_dir() {
            return p.join("clickhouse");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(format!("{}/.local/share/percepta-siem/clickhouse", home))
}

fn resolve_clickhouse_binary(data_dir: &Path) -> Option<PathBuf> {
    if let Ok(bin) = std::env::var("PERCEPTA_CH_EMBEDDED_BIN") {
        let p = PathBuf::from(bin);
        if p.is_file() {
            return Some(p);
        }
    }

    let candidate = data_dir.join("clickhouse-server");
    if candidate.is_file() {
        return Some(candidate);
    }

    let cwd_candidate = std::env::current_dir().ok().map(|p| p.join("clickhouse-server"));
    if let Some(p) = cwd_candidate {
        if p.is_file() {
            return Some(p);
        }
    }

    Some(PathBuf::from("clickhouse-server"))
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn ensure_clickhouse_users_config(data_dir: &Path) -> Option<PathBuf> {
    let users_path = data_dir.join("users.xml");
    if users_path.is_file() {
        return Some(users_path);
    }

        let password = clickhouse_password();
        let escaped_pw = xml_escape(&password);
        let users_contents = format!(
                "<clickhouse>\n  <profiles>\n    <default>\n      <log_queries>0</log_queries>\n    </default>\n  </profiles>\n  <users>\n    <default>\n      <password>{pw}</password>\n      <networks>\n        <ip>127.0.0.1</ip>\n      </networks>\n      <profile>default</profile>\n      <quota>default</quota>\n    </default>\n  </users>\n  <quotas>\n    <default>\n      <interval>\n        <duration>3600</duration>\n        <queries>0</queries>\n        <errors>0</errors>\n        <result_rows>0</result_rows>\n        <read_rows>0</read_rows>\n        <execution_time>0</execution_time>\n      </interval>\n    </default>\n  </quotas>\n</clickhouse>\n",
                pw = escaped_pw
        );

    if let Err(e) = fs::write(&users_path, users_contents) {
        tracing::warn!("Failed to write ClickHouse users.xml: {e}");
        return None;
    }
    Some(users_path)
}

fn ensure_clickhouse_config(data_dir: &Path) -> Option<PathBuf> {
    if let Ok(cfg) = std::env::var("PERCEPTA_CH_CONFIG") {
        let p = PathBuf::from(cfg);
        if p.is_file() {
            return Some(p);
        }
        tracing::warn!("PERCEPTA_CH_CONFIG set but not found: {}", p.display());
        return None;
    }

    let config_path = data_dir.join("config.xml");
    if config_path.is_file() {
        let _ = ensure_clickhouse_users_config(data_dir);
        return Some(config_path);
    }

    let users_path = ensure_clickhouse_users_config(data_dir)?;
    let data_path = data_dir.join("data");
    let tmp_path = data_dir.join("tmp");
    let user_files_path = data_dir.join("user_files");
    let schema_path = data_dir.join("format_schemas");
    let logs_path = data_dir.join("logs");

    for dir in [&data_path, &tmp_path, &user_files_path, &schema_path, &logs_path] {
        if let Err(e) = fs::create_dir_all(dir) {
            tracing::warn!("Failed to create ClickHouse dir {}: {e}", dir.display());
            return None;
        }
    }

    let config_contents = format!(
        "<clickhouse>\n  <logger>\n    <level>warning</level>\n    <log>{log}</log>\n    <errorlog>{error}</errorlog>\n    <size>100M</size>\n    <count>3</count>\n  </logger>\n  <http_port>8123</http_port>\n  <tcp_port>9000</tcp_port>\n  <interserver_http_port>9009</interserver_http_port>\n  <listen_host>127.0.0.1</listen_host>\n  <path>{data}</path>\n  <tmp_path>{tmp}</tmp_path>\n  <user_files_path>{user_files}</user_files_path>\n  <format_schema_path>{schemas}</format_schema_path>\n  <users_config>{users}</users_config>\n  <default_profile>default</default_profile>\n  <default_database>default</default_database>\n  <mlock_executable>false</mlock_executable>\n  <user_directories>\n    <users_xml>\n      <path>{users}</path>\n    </users_xml>\n  </user_directories>\n</clickhouse>\n",
        log = logs_path.join("clickhouse-server.log").to_string_lossy(),
        error = logs_path.join("clickhouse-server.err.log").to_string_lossy(),
        data = data_path.to_string_lossy(),
        tmp = tmp_path.to_string_lossy(),
        user_files = user_files_path.to_string_lossy(),
        schemas = schema_path.to_string_lossy(),
        users = users_path.to_string_lossy(),
    );

    if let Err(e) = fs::write(&config_path, config_contents) {
        tracing::warn!("Failed to write ClickHouse config.xml: {e}");
        return None;
    }

    Some(config_path)
}

fn claim_clickhouse_start_lock(data_dir: &Path) -> bool {
    let lock_path = data_dir.join("clickhouse.start.lock");
    match OpenOptions::new().create_new(true).write(true).open(&lock_path) {
        Ok(mut f) => {
            let _ = writeln!(f, "pid={}", std::process::id());
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            tracing::info!("🗄️ ClickHouse start already in progress (lock exists)");
            false
        }
        Err(e) => {
            tracing::debug!("Failed to create ClickHouse start lock: {e}");
            false
        }
    }
}

fn release_clickhouse_start_lock(data_dir: &Path) {
    let lock_path = data_dir.join("clickhouse.start.lock");
    let _ = fs::remove_file(lock_path);
}

async fn try_start_embedded() -> bool {
    let data_dir = clickhouse_data_dir();
    if let Err(e) = fs::create_dir_all(&data_dir) {
        tracing::warn!("Failed to create ClickHouse data dir {}: {e}", data_dir.display());
        return false;
    }

    if !claim_clickhouse_start_lock(&data_dir) {
        return false;
    }

    let result = (|| {
        let config_path = ensure_clickhouse_config(&data_dir)?;
        let bin_path = resolve_clickhouse_binary(&data_dir)?;
        Some((config_path, bin_path))
    })();

    let (config_path, bin_path) = match result {
        Some(v) => v,
        None => {
            release_clickhouse_start_lock(&data_dir);
            return false;
        }
    };

    let output = tokio::process::Command::new(&bin_path)
        .args([
            "--config-file",
            config_path.to_string_lossy().as_ref(),
            "--daemon",
        ])
        .output()
        .await;

    release_clickhouse_start_lock(&data_dir);

    match output {
        Ok(out) if out.status.success() => {
            tracing::info!("🗄️ clickhouse-server (embedded) → OK");
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            tracing::debug!("clickhouse-server (embedded) failed: {}", stderr.trim());
            false
        }
        Err(e) => {
            tracing::debug!("clickhouse-server (embedded) not available: {e}");
            false
        }
    }
}

async fn is_ch_reachable() -> bool {
    let url = db_url_from_env().unwrap_or_else(default_local_db_url);
    let ping_url = format!("{}/ping", url.trim_end_matches('/'));
    match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    {
        Ok(c) => c
            .get(&ping_url)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false),
        Err(_) => false,
    }
}

fn find_docker_compose_path() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    for _ in 0..5 {
        let candidate = current.join("docker-compose.yml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

async fn try_start_docker_compose() -> bool {
    let compose_path = match find_docker_compose_path() {
        Some(path) => path,
        None => {
            tracing::debug!("docker-compose.yml not found in current or parent directories");
            return false;
        }
    };

    match tokio::process::Command::new("docker")
        .args([
            "compose",
            "-f",
            compose_path.to_string_lossy().as_ref(),
            "up",
            "-d",
            "clickhouse",
        ])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            tracing::info!("🗄️ docker compose up -d clickhouse → OK");
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            tracing::debug!("docker compose up failed: {}", stderr.trim());
            false
        }
        Err(e) => {
            tracing::debug!("docker compose not available: {e}");
            false
        }
    }
}

async fn try_start_systemctl() -> bool {
    match tokio::process::Command::new("systemctl")
        .args(["start", "clickhouse-server"])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            tracing::info!("🗄️ systemctl start clickhouse-server → OK");
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            tracing::debug!("systemctl start failed: {}", stderr.trim());
            false
        }
        Err(e) => {
            tracing::debug!("systemctl not available: {e}");
            false
        }
    }
}
