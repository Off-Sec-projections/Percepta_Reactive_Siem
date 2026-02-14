//! Role-Based Access Control (RBAC) with granular permissions.
//!
//! Replaces the simple 2-role enum with a fine-grained permission model.
//! Built-in roles: Viewer, Analyst, Senior Analyst, SOC Manager, Administrator.
//! Custom roles can be created via the API.

use crate::db::Db;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ── Permissions ──────────────────────────────────────────────────────────

/// Granular permissions for access control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ReadAlerts,
    WriteAlerts,
    ManageRules,
    ManageCases,
    AdminSettings,
    ViewCompliance,
    ManagePlaybooks,
    DbAdmin,
    ManageAgents,
    ViewDashboard,
    ViewReports,
    GenerateReports,
    ManageUsers,
    ManageRoles,
    ViewAuditLog,
    ManageIdsRules,
    ReactiveActions,
    ManageHoneypot,
    ViewIntel,
    ManageIntel,
    ManageAssets,
    ViewDlp,
    ManageWebhooks,
    ApiKeyManagement,
}

impl Permission {
    pub fn all() -> Vec<Permission> {
        vec![
            Permission::ReadAlerts,
            Permission::WriteAlerts,
            Permission::ManageRules,
            Permission::ManageCases,
            Permission::AdminSettings,
            Permission::ViewCompliance,
            Permission::ManagePlaybooks,
            Permission::DbAdmin,
            Permission::ManageAgents,
            Permission::ViewDashboard,
            Permission::ViewReports,
            Permission::GenerateReports,
            Permission::ManageUsers,
            Permission::ManageRoles,
            Permission::ViewAuditLog,
            Permission::ManageIdsRules,
            Permission::ReactiveActions,
            Permission::ManageHoneypot,
            Permission::ViewIntel,
            Permission::ManageIntel,
            Permission::ManageAssets,
            Permission::ViewDlp,
            Permission::ManageWebhooks,
            Permission::ApiKeyManagement,
        ]
    }
}

// ── Role ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacRole {
    pub id: String,
    pub name: String,
    pub description: String,
    pub permissions: HashSet<Permission>,
    pub is_builtin: bool,
}

// ── User ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacUser {
    pub username: String,
    pub password_hash: String,
    pub display_name: String,
    pub role_id: String,
    pub enabled: bool,
    pub created_at: String,
    pub last_login: Option<String>,
}

// ── RBAC Store ───────────────────────────────────────────────────────────

pub type RbacStoreHandle = Arc<RwLock<RbacStore>>;

pub struct RbacStore {
    pub roles: HashMap<String, RbacRole>,
    pub users: HashMap<String, RbacUser>,
}

impl RbacStore {
    pub fn new() -> Self {
        let mut store = Self {
            roles: HashMap::new(),
            users: HashMap::new(),
        };
        store.seed_builtin_roles();
        store.seed_default_users();
        store
    }

    fn seed_builtin_roles(&mut self) {
        let viewer = RbacRole {
            id: "viewer".into(),
            name: "Viewer".into(),
            description: "Read-only access to dashboards and alerts".into(),
            permissions: [
                Permission::ReadAlerts,
                Permission::ViewDashboard,
                Permission::ViewCompliance,
                Permission::ViewReports,
                Permission::ViewIntel,
            ]
            .into_iter()
            .collect(),
            is_builtin: true,
        };

        let analyst = RbacRole {
            id: "analyst".into(),
            name: "Analyst".into(),
            description: "Can investigate alerts, manage cases, and view compliance".into(),
            permissions: [
                Permission::ReadAlerts,
                Permission::WriteAlerts,
                Permission::ManageCases,
                Permission::ViewDashboard,
                Permission::ViewCompliance,
                Permission::ViewReports,
                Permission::ViewAuditLog,
                Permission::ViewIntel,
                Permission::ViewDlp,
            ]
            .into_iter()
            .collect(),
            is_builtin: true,
        };

        let senior_analyst = RbacRole {
            id: "senior_analyst".into(),
            name: "Senior Analyst".into(),
            description: "Full analyst access plus rule tuning, playbooks, and reactive actions"
                .into(),
            permissions: [
                Permission::ReadAlerts,
                Permission::WriteAlerts,
                Permission::ManageRules,
                Permission::ManageCases,
                Permission::ViewDashboard,
                Permission::ViewCompliance,
                Permission::ViewReports,
                Permission::GenerateReports,
                Permission::ViewAuditLog,
                Permission::ManageIdsRules,
                Permission::ReactiveActions,
                Permission::ViewIntel,
                Permission::ManageIntel,
                Permission::ViewDlp,
                Permission::ManagePlaybooks,
            ]
            .into_iter()
            .collect(),
            is_builtin: true,
        };

        let soc_manager = RbacRole {
            id: "soc_manager".into(),
            name: "SOC Manager".into(),
            description:
                "Manage SOC operations: users, compliance, reports, and all investigations".into(),
            permissions: {
                let mut p: HashSet<Permission> = Permission::all().into_iter().collect();
                p.remove(&Permission::DbAdmin);
                p
            },
            is_builtin: true,
        };

        let administrator = RbacRole {
            id: "administrator".into(),
            name: "Administrator".into(),
            description: "Full system access including database administration".into(),
            permissions: Permission::all().into_iter().collect(),
            is_builtin: true,
        };

        self.roles.insert("viewer".into(), viewer);
        self.roles.insert("analyst".into(), analyst);
        self.roles.insert("senior_analyst".into(), senior_analyst);
        self.roles.insert("soc_manager".into(), soc_manager);
        self.roles.insert("administrator".into(), administrator);
    }

    fn seed_default_users(&mut self) {
        // Seed admin/analyst users with passwords from env vars.
        // If env vars are not set, generate random passwords (matching AuthConfig behavior).
        let admin_pass = std::env::var("PERCEPTA_ADMIN_PASS").unwrap_or_else(|_| {
            use rand::Rng;
            rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(24)
                .map(char::from)
                .collect()
        });
        let analyst_pass = std::env::var("PERCEPTA_ANALYST_PASS").unwrap_or_else(|_| {
            use rand::Rng;
            rand::thread_rng()
                .sample_iter(&rand::distributions::Alphanumeric)
                .take(24)
                .map(char::from)
                .collect()
        });

        let admin_user = std::env::var("PERCEPTA_ADMIN_USER").unwrap_or_else(|_| "admin".into());
        let analyst_user =
            std::env::var("PERCEPTA_ANALYST_USER").unwrap_or_else(|_| "analyst".into());

        self.users.insert(
            admin_user.clone(),
            RbacUser {
                username: admin_user,
                password_hash: hash_password(&admin_pass),
                display_name: "Administrator".into(),
                role_id: "administrator".into(),
                enabled: true,
                created_at: chrono::Utc::now().to_rfc3339(),
                last_login: None,
            },
        );

        self.users.insert(
            analyst_user.clone(),
            RbacUser {
                username: analyst_user,
                password_hash: hash_password(&analyst_pass),
                display_name: "Security Analyst".into(),
                role_id: "analyst".into(),
                enabled: true,
                created_at: chrono::Utc::now().to_rfc3339(),
                last_login: None,
            },
        );
    }

    pub fn verify_password(&self, username: &str, password: &str) -> bool {
        if let Some(user) = self.users.get(username) {
            user.enabled && verify_password_hash(password, &user.password_hash)
        } else {
            false
        }
    }

    /// If the stored hash is a legacy DefaultHasher hex hash, upgrade it
    /// to Argon2id in-place. Call this after a successful login while
    /// holding a write lock.
    pub fn upgrade_legacy_hash(&mut self, username: &str, password: &str) {
        if let Some(user) = self.users.get_mut(username) {
            if !user.password_hash.starts_with("$argon2") {
                user.password_hash = hash_password(password);
                tracing::info!("Upgraded legacy password hash to Argon2id for user '{username}'");
            }
        }
    }

    #[allow(dead_code)]
    pub fn get_user_permissions(&self, username: &str) -> HashSet<Permission> {
        if let Some(user) = self.users.get(username) {
            if let Some(role) = self.roles.get(&user.role_id) {
                return role.permissions.clone();
            }
        }
        HashSet::new()
    }

    #[allow(dead_code)]
    pub fn user_has_permission(&self, username: &str, perm: Permission) -> bool {
        self.get_user_permissions(username).contains(&perm)
    }

    pub fn get_user_role(&self, username: &str) -> Option<&RbacRole> {
        self.users
            .get(username)
            .and_then(|u| self.roles.get(&u.role_id))
    }

    // ── Role CRUD ────────────────────────────────────────────

    pub fn create_role(&mut self, role: RbacRole) -> Result<(), String> {
        if self.roles.contains_key(&role.id) {
            return Err("Role already exists".into());
        }
        info!("RBAC: Created role '{}'", role.name);
        self.roles.insert(role.id.clone(), role);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn update_role(
        &mut self,
        id: &str,
        name: Option<String>,
        description: Option<String>,
        permissions: Option<HashSet<Permission>>,
    ) -> Result<(), String> {
        let role = self.roles.get_mut(id).ok_or("Role not found")?;
        if role.is_builtin {
            return Err("Cannot modify built-in roles".into());
        }
        if let Some(n) = name {
            role.name = n;
        }
        if let Some(d) = description {
            role.description = d;
        }
        if let Some(p) = permissions {
            role.permissions = p;
        }
        Ok(())
    }

    pub fn delete_role(&mut self, id: &str) -> Result<(), String> {
        let role = self.roles.get(id).ok_or("Role not found")?;
        if role.is_builtin {
            return Err("Cannot delete built-in roles".into());
        }
        // Check no users reference this role
        if self.users.values().any(|u| u.role_id == id) {
            return Err("Role is assigned to users; reassign them first".into());
        }
        self.roles.remove(id);
        Ok(())
    }

    // ── User CRUD ────────────────────────────────────────────

    pub fn create_user(
        &mut self,
        username: String,
        password: &str,
        display_name: String,
        role_id: String,
    ) -> Result<(), String> {
        if self.users.contains_key(&username) {
            return Err("User already exists".into());
        }
        if !self.roles.contains_key(&role_id) {
            return Err("Invalid role_id".into());
        }
        self.users.insert(
            username.clone(),
            RbacUser {
                username,
                password_hash: hash_password(password),
                display_name,
                role_id,
                enabled: true,
                created_at: chrono::Utc::now().to_rfc3339(),
                last_login: None,
            },
        );
        Ok(())
    }

    pub fn update_user_role(&mut self, username: &str, role_id: &str) -> Result<(), String> {
        if !self.roles.contains_key(role_id) {
            return Err("Invalid role_id".into());
        }
        let user = self.users.get_mut(username).ok_or("User not found")?;
        user.role_id = role_id.into();
        Ok(())
    }

    pub fn disable_user(&mut self, username: &str) -> Result<(), String> {
        let user = self.users.get_mut(username).ok_or("User not found")?;
        user.enabled = false;
        info!("RBAC: Disabled user '{}'", username);
        Ok(())
    }

    pub fn enable_user(&mut self, username: &str) -> Result<(), String> {
        let user = self.users.get_mut(username).ok_or("User not found")?;
        user.enabled = true;
        Ok(())
    }

    pub fn change_password(&mut self, username: &str, new_password: &str) -> Result<(), String> {
        let user = self.users.get_mut(username).ok_or("User not found")?;
        user.password_hash = hash_password(new_password);
        Ok(())
    }

    pub fn record_login(&mut self, username: &str) {
        if let Some(user) = self.users.get_mut(username) {
            user.last_login = Some(chrono::Utc::now().to_rfc3339());
        }
    }
}

/// Hash a password using Argon2id (OWASP recommended).
/// Returns a PHC-format string containing algorithm, salt, and hash.
fn hash_password(password: &str) -> String {
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Argon2, PasswordHasher,
    };
    let salt = SaltString::generate(&mut OsRng);
    // Use Argon2id with default (safe) parameters.
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hash_password should not fail")
        .to_string()
}

/// Verify a password against a stored hash.
/// Supports both new Argon2id (PHC "$argon2id$…") hashes and legacy
/// DefaultHasher hex hashes (16-char hex) for migration compatibility.
fn verify_password_hash(password: &str, stored_hash: &str) -> bool {
    if stored_hash.starts_with("$argon2") {
        // Modern Argon2id hash
        use argon2::{Argon2, PasswordHash, PasswordVerifier};
        match PasswordHash::new(stored_hash) {
            Ok(parsed) => Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok(),
            Err(_) => false,
        }
    } else {
        // Legacy DefaultHasher hex hash — compare for migration only.
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        "percepta_salt_v1".hash(&mut hasher);
        password.hash(&mut hasher);
        let legacy = format!("{:016x}", hasher.finish());
        legacy == stored_hash
    }
}

pub fn init_rbac_store() -> RbacStoreHandle {
    Arc::new(RwLock::new(RbacStore::new()))
}

// ── ClickHouse Persistence ───────────────────────────────────────────────

/// Persist an RBAC role to ClickHouse.
pub async fn persist_rbac_role(db: &Db, role: &RbacRole) {
    #[derive(clickhouse::Row, serde::Serialize, Clone)]
    struct Row {
        id: String,
        name: String,
        description: String,
        permissions: Vec<String>,
        is_builtin: u8,
        updated_at: i64,
    }
    let row = Row {
        id: role.id.clone(),
        name: role.name.clone(),
        description: role.description.clone(),
        permissions: role
            .permissions
            .iter()
            .map(|p| format!("{p:?}"))
            .collect(),
        is_builtin: if role.is_builtin { 1 } else { 0 },
        updated_at: chrono::Utc::now().timestamp(),
    };
    if let Err(e) = db
        .retry_insert("persist_rbac_role", |cl| {
            let r = row.clone();
            async move {
                let mut ins = cl
                    .insert("rbac_roles")
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.write(&r).await.map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
                Ok(())
            }
        })
        .await
    {
        warn!("Failed to persist RBAC role '{}': {:#}", role.id, e);
    }
}

/// Load RBAC roles from ClickHouse and merge into the store.
pub async fn load_rbac_roles_from_ch(db: &Db, store: &RbacStoreHandle) -> bool {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        id: String,
        name: String,
        description: String,
        permissions: Vec<String>,
        is_builtin: u8,
    }

    let rows = match db
        .client()
        .query(
            "SELECT id, \
                argMax(name, updated_at) AS name, \
                argMax(description, updated_at) AS description, \
                argMax(permissions, updated_at) AS permissions, \
                argMax(is_builtin, updated_at) AS is_builtin \
                FROM rbac_roles GROUP BY id",
        )
        .fetch_all::<Row>()
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!("Failed to load RBAC roles from ClickHouse: {:#}", e);
            return false;
        }
    };

    if rows.is_empty() {
        return false;
    }

    let mut s = store.write().await;
    for r in &rows {
        let permissions: HashSet<Permission> = r
            .permissions
            .iter()
            .filter_map(|p| serde_json::from_str(&format!("\"{}\"", p)).ok())
            .collect();

        let role = RbacRole {
            id: r.id.clone(),
            name: r.name.clone(),
            description: r.description.clone(),
            permissions,
            is_builtin: r.is_builtin != 0,
        };
        s.roles.insert(role.id.clone(), role);
    }
    info!("Loaded {} RBAC roles from ClickHouse", rows.len());
    true
}

/// Persist a single RBAC user to ClickHouse (upsert via ReplacingMergeTree).
pub async fn persist_rbac_user(db: &Db, user: &RbacUser) {
    #[derive(clickhouse::Row, serde::Serialize)]
    struct Row {
        username: String,
        password_hash: String,
        display_name: String,
        role_id: String,
        enabled: u8,
        created_at: String,
        last_login: String,
        updated_at: i64,
    }
    let row = Row {
        username: user.username.clone(),
        password_hash: user.password_hash.clone(),
        display_name: user.display_name.clone(),
        role_id: user.role_id.clone(),
        enabled: if user.enabled { 1 } else { 0 },
        created_at: user.created_at.clone(),
        last_login: user.last_login.clone().unwrap_or_default(),
        updated_at: chrono::Utc::now().timestamp(),
    };
    if let Err(e) = db
        .retry_insert("persist_rbac_user", |cl| {
            let r = Row {
                username: row.username.clone(),
                password_hash: row.password_hash.clone(),
                display_name: row.display_name.clone(),
                role_id: row.role_id.clone(),
                enabled: row.enabled,
                created_at: row.created_at.clone(),
                last_login: row.last_login.clone(),
                updated_at: row.updated_at,
            };
            async move {
                let mut ins = cl
                    .insert("rbac_users")
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.write(&r).await.map_err(|e| anyhow::anyhow!("{}", e))?;
                ins.end().await.map_err(|e| anyhow::anyhow!("{}", e))?;
                Ok(())
            }
        })
        .await
    {
        warn!("Failed to persist RBAC user '{}': {:#}", user.username, e);
    }
}

/// Load RBAC users from ClickHouse and merge into the store.
/// DB users override in-memory defaults (password may have been changed via API).
/// Returns `true` if any users were loaded from the database, indicating the system is not on its first run.
pub async fn load_rbac_users_from_ch(db: &Db, store: &RbacStoreHandle) -> bool {
    #[derive(clickhouse::Row, serde::Deserialize)]
    struct Row {
        username: String,
        password_hash: String,
        display_name: String,
        role_id: String,
        enabled: u8,
        created_at: String,
        last_login: String,
    }
    let rows = match db
        .client()
        .query(
            "SELECT username, \
                argMax(password_hash, updated_at) AS password_hash, \
                argMax(display_name, updated_at) AS display_name, \
                argMax(role_id, updated_at) AS role_id, \
                argMax(enabled, updated_at) AS enabled, \
                argMax(created_at, updated_at) AS created_at, \
                argMax(last_login, updated_at) AS last_login \
                FROM rbac_users GROUP BY username",
        )
        .fetch_all::<Row>()
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            warn!("Failed to load RBAC users from ClickHouse: {:#}", e);
            return false;
        }
    };
    if rows.is_empty() {
        return false;
    }
    let mut s = store.write().await;
    for r in &rows {
        let user = RbacUser {
            username: r.username.clone(),
            password_hash: r.password_hash.clone(),
            display_name: r.display_name.clone(),
            role_id: r.role_id.clone(),
            enabled: r.enabled != 0,
            created_at: r.created_at.clone(),
            last_login: if r.last_login.is_empty() {
                None
            } else {
                Some(r.last_login.clone())
            },
        };
        s.users.insert(user.username.clone(), user);
    }
    info!("Loaded {} RBAC users from ClickHouse", rows.len());
    true
}

// ── API Handlers ─────────────────────────────────────────────────────────

use crate::enroll::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

pub async fn api_list_roles(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.rbac_store.read().await;
    let roles: Vec<&RbacRole> = store.roles.values().collect();
    Json(serde_json::json!({ "roles": roles }))
}

pub async fn api_create_role(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let permissions: HashSet<Permission> = body
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    if id.is_empty() || name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "id and name required"})),
        )
            .into_response();
    }

    let role = RbacRole {
        id,
        name,
        description,
        permissions,
        is_builtin: false,
    };
    let mut store = state.rbac_store.write().await;
    match store.create_role(role.clone()) {
        Ok(()) => {
            drop(store);
            persist_rbac_role(&state.db, &role).await;
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"status": "created"})),
            )
                .into_response()
        }
        Err(e) => (StatusCode::CONFLICT, Json(serde_json::json!({"error": e}))).into_response(),
    }
}

pub async fn api_delete_role(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("");
    let mut store = state.rbac_store.write().await;
    match store.delete_role(id) {
        Ok(()) => {
            drop(store);
            let _ = state
                .db
                .client()
                .query("ALTER TABLE rbac_roles DELETE WHERE id = ?")
                .bind(id)
                .execute()
                .await;
            Json(serde_json::json!({"status": "deleted"})).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
            .into_response(),
    }
}

pub async fn api_list_users(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.rbac_store.read().await;
    let users: Vec<serde_json::Value> = store
        .users
        .values()
        .map(|u| {
            serde_json::json!({
                "username": u.username,
                "display_name": u.display_name,
                "role_id": u.role_id,
                "enabled": u.enabled,
                "created_at": u.created_at,
                "last_login": u.last_login,
            })
        })
        .collect();
    Json(serde_json::json!({ "users": users }))
}

pub async fn api_create_user(
    State(state): State<AppState>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::AuthedUser>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let display_name = body
        .get("display_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let role_id = body
        .get("role_id")
        .and_then(|v| v.as_str())
        .unwrap_or("analyst")
        .to_string();

    if username.is_empty() || password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "username and password required"})),
        )
            .into_response();
    }

    // Privilege escalation guard: caller cannot create a user with a higher-ranked role
    {
        let store = state.rbac_store.read().await;
        let caller_rank = caller_role_rank(&store, &caller.username);
        if role_rank(&role_id) > caller_rank {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Cannot assign a role with higher privileges than your own"
                })),
            )
                .into_response();
        }
    }

    let mut store = state.rbac_store.write().await;
    match store.create_user(username.clone(), password, display_name, role_id) {
        Ok(()) => {
            let user = store.users.get(&username).cloned();
            drop(store);
            if let Some(u) = user {
                persist_rbac_user(&state.db, &u).await;
            }
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"status": "created"})),
            )
                .into_response()
        }
        Err(e) => {
            // Keep 409 for true uniqueness conflicts, but report validation errors as 400.
            let code = if e == "Invalid role_id" {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::CONFLICT
            };
            (code, Json(serde_json::json!({"error": e}))).into_response()
        }
    }
}

pub async fn api_update_user(
    State(state): State<AppState>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::AuthedUser>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Privilege escalation guards
    {
        let store = state.rbac_store.read().await;
        let caller_rank = caller_role_rank(&store, &caller.username);
        let target_role_id = store
            .users
            .get(&username)
            .map(|u| u.role_id.clone())
            .unwrap_or_default();

        // Cannot modify a user who has a higher-ranked role than yourself
        if role_rank(&target_role_id) > caller_rank {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Cannot modify a user with higher privileges than your own"
                })),
            )
                .into_response();
        }
        // Cannot assign a role higher than your own
        if let Some(new_role) = body.get("role_id").and_then(|v| v.as_str()) {
            if role_rank(new_role) > caller_rank {
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": "Cannot assign a role with higher privileges than your own"
                    })),
                )
                    .into_response();
            }
        }
    }

    let mut store = state.rbac_store.write().await;

    if let Some(role_id) = body.get("role_id").and_then(|v| v.as_str()) {
        if let Err(e) = store.update_user_role(&username, role_id) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e})),
            )
                .into_response();
        }
    }
    if let Some(enabled) = body.get("enabled").and_then(|v| v.as_bool()) {
        if enabled {
            let _ = store.enable_user(&username);
        } else {
            let _ = store.disable_user(&username);
        }
    }
    if let Some(password) = body.get("password").and_then(|v| v.as_str()) {
        let _ = store.change_password(&username, password);
    }
    let user = store.users.get(&username).cloned();
    drop(store);
    // Persist updated user to ClickHouse
    if let Some(u) = &user {
        persist_rbac_user(&state.db, u).await;
    }
    // If password was changed, revoke sessions
    if body.get("password").is_some() {
        let revoked = crate::reactive::revoke_sessions_for_user(&state.sessions, &username).await;
        if revoked > 0 {
            tracing::info!(
                "Password changed for '{}': revoked {} active sessions",
                username,
                revoked
            );
        }
    }

    Json(serde_json::json!({"status": "updated"})).into_response()
}

pub async fn api_my_permissions(
    State(state): State<AppState>,
    axum::extract::Extension(user): axum::extract::Extension<crate::auth::AuthedUser>,
) -> impl IntoResponse {
    let store = state.rbac_store.read().await;
    let permissions = store.get_user_permissions(&user.username);
    let role = store.get_user_role(&user.username).cloned();
    Json(serde_json::json!({
        "username": user.username,
        "role": role,
        "permissions": permissions,
    }))
}

/// List all available permissions (for role creation UI).
pub async fn api_list_permissions() -> impl IntoResponse {
    let all: Vec<Permission> = Permission::all();
    Json(serde_json::json!(all))
}

// ── Self-service password change (any authenticated user) ────────────

pub async fn api_change_own_password(
    State(state): State<AppState>,
    axum::extract::Extension(caller): axum::extract::Extension<crate::auth::AuthedUser>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let current = body
        .get("current_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let new_pw = body
        .get("new_password")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if current.is_empty() || new_pw.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "current_password and new_password required"})),
        )
            .into_response();
    }
    if new_pw.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Password must be at least 8 characters"})),
        )
            .into_response();
    }

    // Verify current password first
    let mut store = state.rbac_store.write().await;
    if !store.verify_password(&caller.username, current) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Current password is incorrect"})),
        )
            .into_response();
    }
    let _ = store.change_password(&caller.username, new_pw);
    let user = store.users.get(&caller.username).cloned();
    drop(store);

    if let Some(u) = user {
        persist_rbac_user(&state.db, &u).await;
    }
    // Revoke all OTHER sessions (not the current one — handled by cookie)
    let revoked =
        crate::reactive::revoke_sessions_for_user(&state.sessions, &caller.username).await;
    if revoked > 0 {
        tracing::info!(
            "Self-service password change for '{}': revoked {} sessions",
            caller.username,
            revoked
        );
    }
    Json(serde_json::json!({"status": "password_changed"})).into_response()
}

// ── Role Rank (for privilege escalation prevention) ──────────────────

fn role_rank(role_id: &str) -> u8 {
    match role_id {
        "viewer" => 1,
        "analyst" => 2,
        "senior_analyst" => 3,
        "soc_manager" => 4,
        "administrator" => 5,
        _ => 0, // custom roles are lowest rank
    }
}

/// Return effective role rank for a username, granting max rank to the
/// synthetic API-key user so external integrations can manage all roles.
fn caller_role_rank(store: &RbacStore, username: &str) -> u8 {
    if username == "__api_key__" {
        return 5; // administrator-level
    }
    store
        .users
        .get(username)
        .map(|u| role_rank(&u.role_id))
        .unwrap_or(0)
}
