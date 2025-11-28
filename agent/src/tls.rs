//! TLS Certificate Management Module
//! Manages agent certificates, private keys, and enrollment with the Percepta SIEM server.

use anyhow::{bail, Context, Result};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{extension::SubjectAlternativeName, X509NameBuilder, X509ReqBuilder, X509},
};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

const RSA_KEY_SIZE: u32 = 4096;

// -----------------------------------------------------------------------------
// OTK Enrollment
// -----------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// Device information sent during enrollment
#[derive(Debug, Serialize)]
struct DeviceInfo {
    hostname: String,
    os: String,
    ip: String,
}

/// Payload to claim an enrollment token
#[derive(Debug, Serialize)]
struct EnrollmentClaim {
    otk: String,
    csr: String,
    device_info: DeviceInfo,
    identity: IdentityInfo,
}

/// Permanent device identity fields used for server-side binding
#[derive(Debug, Serialize)]
struct IdentityInfo {
    primary_mac: String,
    first_user: String,
}

/// Response from a successful enrollment claim
#[derive(Debug, Deserialize)]
struct EnrollmentResponse {
    agent_cert: String,
    ca_cert: String,
}

/// Get the local IP address of the agent
fn get_local_ip() -> String {
    local_ip_address::local_ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

async fn build_http_client(server_url: &str, cert_dir: &Path) -> Result<reqwest::Client> {
    // If using HTTPS, require a CA certificate; if missing, attempt bootstrap by downloading CA over HTTP (TOFU).
    if server_url.starts_with("https://") {
        let ca_cert_path = cert_dir.join("ca_cert.pem");
        let ca_pem = if let Ok(pem) = fs::read(&ca_cert_path).await {
            pem
        } else {
            // Attempt TOFU bootstrap: fetch CA over HTTP from portal
            // Parse host[:port] from the HTTPS server_url
            let host_port = server_url
                .strip_prefix("https://")
                .unwrap_or(server_url)
                .split('/')
                .next()
                .unwrap_or("");
            let ca_url_http = format!("http://{}/api/ca_cert", host_port);
            info!(
                "CA not found at {}. Bootstrapping by downloading CA from {}",
                ca_cert_path.display(),
                ca_url_http
            );
            let ca_resp = reqwest::Client::new()
                .get(&ca_url_http)
                .send()
                .await
                .context("Failed to download CA certificate over HTTP for bootstrap")?;
            if !ca_resp.status().is_success() {
                bail!(
                    "Failed to bootstrap CA. GET {} returned {}",
                    ca_url_http,
                    ca_resp.status()
                );
            }
            let ca_text = ca_resp
                .text()
                .await
                .context("Failed to read CA response body")?;
            // Save CA and pin fingerprint (TOFU)
            save_file_secure(&ca_cert_path, ca_text.as_bytes()).await?;
            let ca_x509 = X509::from_pem(ca_text.as_bytes())?;
            let fp = hex::encode(ca_x509.digest(MessageDigest::sha256())?);
            let fp_path = cert_dir.join("ca_fingerprint.txt");
            if !fp_path.exists() {
                fs::write(&fp_path, &fp).await?;
            }
            ca_text.into_bytes()
        };
        let ca_cert = reqwest::Certificate::from_pem(&ca_pem)?;
        Ok(reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .build()
            .context("Failed to build secure reqwest client")?)
    } else {
        // HTTP - no TLS validation necessary for initial enrollment/renewal request.
        Ok(reqwest::Client::new())
    }
}

/// Enroll the agent using a One-Time Token (OTK)
pub async fn enroll_with_otk(
    server_url: &str,
    otk: &str,
    agent_id: &str,
    cert_dir: &Path,
) -> Result<()> {
    info!("Starting enrollment with OTK...");

    // 1. Generate new private key
    let private_key = generate_private_key()
        .await
        .context("Failed to generate private key")?;
    let key_path = cert_dir.join("agent_key.pem");
    save_private_key(&key_path, &private_key)
        .await
        .context("Failed to save private key")?;

    // 2. Create CSR
    let csr_pem = generate_csr(&private_key, agent_id)
        .await
        .context("Failed to generate CSR")?;

    // 3. Collect device info
    let device_info = DeviceInfo {
        hostname: hostname::get()
            .unwrap_or_else(|_| "unknown".into())
            .to_string_lossy()
            .to_string(),
        os: std::env::consts::OS.to_string(),
        ip: get_local_ip(),
    };

    // 3b. Permanent identity binding fields
    let ident = crate::identity::load_or_create(cert_dir)
        .await
        .context("Failed to load/create identity for enrollment")?;
    let identity = IdentityInfo {
        primary_mac: ident.primary_mac,
        first_user: ident.first_user,
    };

    // 4. Send HTTPS POST to /api/enroll/claim
    let claim = EnrollmentClaim {
        otk: otk.to_string(),
        csr: csr_pem,
        device_info,
        identity,
    };

    // 4. Build HTTP client
    let client = build_http_client(server_url, cert_dir).await?;

    let claim_url = format!("{}/api/enroll/claim", server_url);
    info!("Sending enrollment claim to {}", claim_url);

    let response = client
        .post(&claim_url)
        .json(&claim)
        .send()
        .await
        .context("Failed to send enrollment claim")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "No error body".to_string());
        bail!(
            "Enrollment claim failed with status {}: {}",
            status,
            error_body
        );
    }

    let enroll_response: EnrollmentResponse = response
        .json()
        .await
        .context("Failed to parse enrollment response")?;

    // -- BEGIN TOFU --
    // On first enrollment, save the fingerprint of the CA cert.
    // On subsequent enrollments, this helps to detect if the CA has changed, which could indicate a MITM attack.
    let ca_fingerprint_path = cert_dir.join("ca_fingerprint.txt");
    let new_ca_cert = X509::from_pem(enroll_response.ca_cert.as_bytes())?;
    let new_fingerprint = hex::encode(new_ca_cert.digest(MessageDigest::sha256())?);

    if ca_fingerprint_path.exists() {
        let existing_fingerprint = fs::read_to_string(&ca_fingerprint_path).await?;
        if existing_fingerprint.trim() != new_fingerprint {
            bail!("CRITICAL SECURITY: The server's Certificate Authority has changed. This could indicate a Man-in-the-Middle attack. Enrollment aborted. Please verify the server's identity and delete ca_fingerprint.txt to proceed.");
        }
    } else {
        info!("Pinning new CA fingerprint for Trust On First Use (TOFU).");
        fs::write(&ca_fingerprint_path, &new_fingerprint).await?;
    }
    // -- END TOFU --

    // 5. Save certificates
    let cert_path = cert_dir.join("agent_cert.pem");
    let ca_path = cert_dir.join("ca_cert.pem");
    save_file_secure(&cert_path, enroll_response.agent_cert.as_bytes())
        .await
        .context("Failed to save agent certificate")?;
    save_file_secure(&ca_path, enroll_response.ca_cert.as_bytes())
        .await
        .context("Failed to save CA certificate")?;

    info!("Enrollment successful! Certificates saved.");
    Ok(())
}

// -----------------------------------------------------------------------------
// Renewal request + pickup (admin-approved)
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct RenewalIdentity {
    primary_mac: String,
    first_user: String,
}

#[derive(Debug, Serialize)]
struct RenewalRequest {
    csr: String,
    identity: RenewalIdentity,
}

#[derive(Debug, Deserialize)]
struct RenewalRequestResponse {
    ok: bool,
    request_id: String,
    pickup_token: String,
}

#[derive(Debug, Deserialize)]
struct RenewalPickupResponse {
    ok: bool,
    status: String,
    agent_cert: Option<String>,
    ca_cert: Option<String>,
}

/// Request a certificate renewal (requires later admin approval).
/// Writes a staged private key to `agent_key_renewal.pem` and returns a pickup token.
pub async fn request_certificate_renewal(
    server_url: &str,
    agent_id: &str,
    cert_dir: &Path,
) -> Result<String> {
    let ident = crate::identity::load_or_create(cert_dir).await?;

    // Generate a new private key for the renewed certificate and keep it staged until pickup.
    let private_key = generate_private_key().await?;
    let staged_key_path = cert_dir.join("agent_key_renewal.pem");
    save_private_key(&staged_key_path, &private_key).await?;

    let csr_pem = generate_csr(&private_key, agent_id).await?;

    let client = build_http_client(server_url, cert_dir).await?;
    let url = format!("{}/api/renew/request", server_url);

    let payload = RenewalRequest {
        csr: csr_pem,
        identity: RenewalIdentity {
            primary_mac: ident.primary_mac,
            first_user: ident.first_user,
        },
    };

    let resp = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .context("Failed to send renewal request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|_| "<no body>".to_string());
        bail!("Renewal request failed (status {}): {}", status, body);
    }

    let parsed: RenewalRequestResponse = resp
        .json()
        .await
        .context("Failed to parse renewal request response")?;
    if !parsed.ok {
        bail!("Renewal request returned ok=false");
    }

    info!(
        "Renewal request created: request_id={}, pickup_token_len={}",
        parsed.request_id,
        parsed.pickup_token.len()
    );

    Ok(parsed.pickup_token)
}

/// Try to pick up an approved renewal. Returns Ok(true) if installed, Ok(false) if pending.
pub async fn pickup_certificate_renewal(
    server_url: &str,
    cert_dir: &Path,
    pickup_token: &str,
) -> Result<bool> {
    let client = build_http_client(server_url, cert_dir).await?;
    let url = format!("{}/api/renew/pickup", server_url);

    let resp = client
        .get(&url)
        .query(&[("token", pickup_token)])
        .send()
        .await
        .context("Failed to send renewal pickup")?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        bail!("Invalid pickup token");
    }

    // 202 means pending
    if resp.status() == reqwest::StatusCode::ACCEPTED {
        return Ok(false);
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_else(|_| "<no body>".to_string());
        bail!("Renewal pickup failed (status {}): {}", status, body);
    }

    let parsed: RenewalPickupResponse = resp
        .json()
        .await
        .context("Failed to parse renewal pickup response")?;

    if !parsed.ok {
        bail!("Renewal pickup returned ok=false");
    }

    if parsed.status != "approved" {
        return Ok(false);
    }

    let agent_cert = parsed
        .agent_cert
        .ok_or_else(|| anyhow::anyhow!("Missing agent_cert in approved pickup"))?;
    let ca_cert = parsed
        .ca_cert
        .ok_or_else(|| anyhow::anyhow!("Missing ca_cert in approved pickup"))?;

    // Enforce TOFU CA pinning
    let ca_fingerprint_path = cert_dir.join("ca_fingerprint.txt");
    let new_ca_x509 = X509::from_pem(ca_cert.as_bytes())?;
    let new_fp = hex::encode(new_ca_x509.digest(MessageDigest::sha256())?);
    if ca_fingerprint_path.exists() {
        let existing_fp = fs::read_to_string(&ca_fingerprint_path).await?;
        if existing_fp.trim() != new_fp {
            bail!("CRITICAL SECURITY: The server's Certificate Authority has changed. Renewal aborted.");
        }
    } else {
        // First-time pin if absent
        fs::write(&ca_fingerprint_path, &new_fp).await?;
    }

    // Write new certs
    let cert_path = cert_dir.join("agent_cert.pem");
    let ca_path = cert_dir.join("ca_cert.pem");
    save_file_secure(&cert_path, agent_cert.as_bytes()).await?;
    save_file_secure(&ca_path, ca_cert.as_bytes()).await?;

    // Activate staged private key
    let staged_key_path = cert_dir.join("agent_key_renewal.pem");
    let key_path = cert_dir.join("agent_key.pem");
    if staged_key_path.exists() {
        // Best-effort replacement for Windows (rename won't overwrite)
        let _ = fs::remove_file(&key_path).await;
        fs::rename(&staged_key_path, &key_path)
            .await
            .context("Failed to activate renewal private key")?;
    }

    info!("Renewal installed successfully");
    Ok(true)
}

/// Generate RSA 4096-bit private key
async fn generate_private_key() -> Result<PKey<Private>> {
    debug!("Generating RSA {} private key", RSA_KEY_SIZE);

    let private_key = tokio::task::spawn_blocking(move || {
        let rsa = Rsa::generate(RSA_KEY_SIZE).context("Failed to generate RSA key pair")?;

        PKey::from_rsa(rsa).context("Failed to create private key from RSA")
    })
    .await??;

    debug!("Private key generated successfully");
    Ok(private_key)
}

/// Save private key to file with secure permissions
async fn save_private_key(key_path: &Path, private_key: &PKey<Private>) -> Result<()> {
    let key_pem = private_key
        .private_key_to_pem_pkcs8()
        .context("Failed to encode private key to PEM")?;

    save_file_secure(key_path, &key_pem)
        .await
        .context("Failed to save private key file")?;

    info!("Private key saved to: {}", key_path.display());
    Ok(())
}

/// Generate Certificate Signing Request
pub async fn generate_csr(private_key: &PKey<Private>, agent_id: &str) -> Result<String> {
    debug!("Generating CSR for agent: {}", agent_id);

    let private_key = private_key.clone();
    let agent_id = agent_id.to_string();

    let csr_pem = tokio::task::spawn_blocking(move || {
        let mut req_builder = X509ReqBuilder::new().context("Failed to create CSR builder")?;

        let mut name_builder = X509NameBuilder::new().context("Failed to create name builder")?;
        name_builder
            .append_entry_by_text("CN", &agent_id)
            .context("Failed to set CN in CSR")?;
        let subject_name = name_builder.build();

        req_builder
            .set_subject_name(&subject_name)
            .context("Failed to set subject name")?;

        req_builder
            .set_pubkey(&private_key)
            .context("Failed to set public key in CSR")?;

        let mut san_extension = SubjectAlternativeName::new();
        san_extension.dns(&agent_id);

        if let Ok(hostname) = hostname::get() {
            if let Ok(hostname_str) = hostname.into_string() {
                san_extension.dns(&hostname_str);
            }
        }

        let san_ext = san_extension
            .build(&req_builder.x509v3_context(None))
            .context("Failed to build SAN extension")?;

        let mut extensions =
            openssl::stack::Stack::new().context("Failed to create extension stack")?;
        extensions
            .push(san_ext)
            .context("Failed to add SAN extension")?;

        req_builder
            .add_extensions(&extensions)
            .context("Failed to add extensions to CSR")?;

        req_builder
            .sign(&private_key, MessageDigest::sha256())
            .context("Failed to sign CSR")?;

        let csr = req_builder.build();

        let csr_pem = csr.to_pem().context("Failed to encode CSR to PEM")?;

        String::from_utf8(csr_pem).context("Failed to convert CSR PEM to string")
    })
    .await??;

    debug!("CSR generated successfully");
    Ok(csr_pem)
}

/// Save file with secure permissions (0o600)
async fn save_file_secure(path: &Path, content: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .context("Failed to create parent directory")?;
    }

    fs::write(path, content)
        .await
        .context("Failed to write file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)
            .await
            .context("Failed to get file metadata")?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)
            .await
            .context("Failed to set file permissions")?;
    }

    debug!("Saved secure file: {}", path.display());
    Ok(())
}
