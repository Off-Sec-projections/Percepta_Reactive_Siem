use anyhow::{bail, Context, Result};
use openssl::hash::{hash, MessageDigest};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::system_info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub agent_id: String,
    pub primary_mac: String,
    pub first_user: String,
    pub created_at_unix: i64,
}

fn identity_path(cert_dir: &Path) -> PathBuf {
    cert_dir.join("identity.json")
}

fn derive_agent_id(hostname: &str, mac: &str, first_user: &str) -> Result<String> {
    let input = format!("{}|{}", mac.trim().to_lowercase(), first_user.trim());
    let digest = hash(MessageDigest::sha256(), input.as_bytes())?;
    let hex = hex::encode(digest);
    // Keep it readable and stable; avoid exposing full MAC in the ID.
    let short = &hex[..12.min(hex.len())];
    let host = hostname.trim();
    if host.is_empty() {
        Ok(format!("agent-{}", short))
    } else {
        Ok(format!("{}-{}", host, short))
    }
}

pub async fn load_or_create(cert_dir: &Path) -> Result<DeviceIdentity> {
    let path = identity_path(cert_dir);
    if path.exists() {
        let bytes = tokio::fs::read(&path)
            .await
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let ident: DeviceIdentity =
            serde_json::from_slice(&bytes).context("Failed to parse identity.json")?;
        if ident.agent_id.trim().is_empty() {
            bail!("identity.json has empty agent_id");
        }
        if ident.primary_mac.trim().is_empty() || ident.primary_mac.trim() == "unknown" {
            bail!("identity.json has empty/unknown primary_mac");
        }
        if ident.first_user.trim().is_empty() {
            bail!("identity.json has empty first_user");
        }
        return Ok(ident);
    }

    let hostname = hostname::get()
        .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
        .to_string_lossy()
        .to_string();

    let primary_mac = system_info::get_primary_mac().unwrap_or_else(|| "unknown".to_string());
    if primary_mac == "unknown" || primary_mac.trim().is_empty() {
        bail!("Cannot determine primary MAC address; cannot create a permanent identity");
    }

    let first_user = system_info::get_current_username();
    if first_user.trim().is_empty() || first_user == "unknown" {
        bail!("Cannot determine initial username; cannot create a permanent identity");
    }

    let agent_id = derive_agent_id(&hostname, &primary_mac, &first_user)
        .context("Failed to derive stable agent_id")?;

    let ident = DeviceIdentity {
        agent_id,
        primary_mac,
        first_user,
        created_at_unix: chrono::Utc::now().timestamp(),
    };

    let json = serde_json::to_vec_pretty(&ident).context("Failed to serialize identity.json")?;
    tokio::fs::write(&path, json)
        .await
        .with_context(|| format!("Failed to write {}", path.display()))?;

    Ok(ident)
}
