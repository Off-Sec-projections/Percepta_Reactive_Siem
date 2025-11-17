use std::path::PathBuf;

#[cfg(target_os = "linux")]
use anyhow::{anyhow, Context, Result};
#[cfg(target_os = "linux")]
use openssl::sha::sha256;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use tokio::fs;
#[cfg(target_os = "linux")]
use tokio::process::Command;
#[cfg(target_os = "linux")]
use tokio::time::sleep;
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};

#[cfg(target_os = "linux")]
const DEFAULT_LOG_DIR: &str = "/var/log/suricata";

#[cfg(target_os = "linux")]
const DEFAULT_CONFIG_PATH: &str = "/etc/suricata/suricata.yaml";

#[cfg(target_os = "linux")]
const DEFAULT_RULE_SYNC_SECS: u64 = 600;

#[cfg(target_os = "linux")]
pub async fn start_suricata_manager(cert_dir: PathBuf) {
    tokio::spawn(async move {
        let result = match SuricataManager::new(cert_dir).await {
            Ok(mut m) => m.run_loop().await,
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            if debug_enabled() {
                warn!("suricata manager stopped: {:#}", e);
            }
        }
    });
}

#[cfg(target_os = "linux")]
pub fn detect_eve_json_path() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("PERCEPTA_SURICATA_EVE") {
        let s = v.trim();
        if !s.is_empty() {
            return Some(PathBuf::from(s));
        }
    }

    if let Ok(dir) = std::env::var("PERCEPTA_SURICATA_LOG_DIR") {
        let s = dir.trim();
        if !s.is_empty() {
            let p = PathBuf::from(s).join("eve.json");
            return Some(p);
        }
    }

    let candidates = ["/var/log/suricata/eve.json", "/var/log/eve.json"];
    for c in candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return Some(p);
        }
    }

    Some(PathBuf::from("/var/log/suricata/eve.json"))
}

/// Platform stub for non-Linux builds; does nothing.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub async fn start_suricata_manager(_cert_dir: PathBuf) {}

#[cfg(not(target_os = "linux"))]
pub fn detect_eve_json_path() -> Option<PathBuf> {
    None
}

#[cfg(target_os = "linux")]
struct SuricataManager {
    log_dir: PathBuf,
    rules_path: PathBuf,
    config_path: PathBuf,
    iface: String,
    rules_url: Option<String>,
    last_rules_hash: Option<String>,
    last_rules_fetch: Instant,
    rules_interval: Duration,
}

#[cfg(target_os = "linux")]
impl SuricataManager {
    async fn new(cert_dir: PathBuf) -> Result<Self> {
        let log_dir = std::env::var("PERCEPTA_SURICATA_LOG_DIR")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_DIR));

        let rules_path = std::env::var("PERCEPTA_SURICATA_RULES_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| cert_dir.join("ids").join("suricata.rules"));

        let config_path = std::env::var("PERCEPTA_SURICATA_CONFIG_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

        let iface = detect_iface().await.unwrap_or_else(|| "eth0".to_string());

        let rules_url = std::env::var("PERCEPTA_SURICATA_RULES_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(default_rules_url_from_agent_config);

        let rules_interval = std::env::var("PERCEPTA_SURICATA_RULE_SYNC_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|s| Duration::from_secs(s.clamp(120, 7200)))
            .unwrap_or_else(|| Duration::from_secs(DEFAULT_RULE_SYNC_SECS));

        Ok(Self {
            log_dir,
            rules_path,
            config_path,
            iface,
            rules_url,
            last_rules_hash: None,
            last_rules_fetch: Instant::now() - Duration::from_secs(3600),
            rules_interval,
        })
    }

    async fn run_loop(&mut self) -> Result<()> {
        if debug_enabled() {
            info!("✅ Suricata manager enabled (Linux agent)");
        }

        loop {
            if let Err(e) = self.ensure_suricata_installed().await {
                if debug_enabled() {
                    warn!("suricata install check failed: {:#}", e);
                }
                break Ok(());
            }

            if let Err(e) = self.sync_rules_if_needed().await {
                if debug_enabled() {
                    warn!("suricata rules sync failed: {:#}", e);
                }
            }

            if let Err(e) = self.ensure_suricata_running().await {
                if debug_enabled() {
                    warn!("suricata run check failed: {:#}", e);
                }
            }

            sleep(Duration::from_secs(120)).await;
        }
    }

    async fn ensure_suricata_installed(&self) -> Result<()> {
        if command_exists("suricata") {
            return Ok(());
        }

        if !is_root() {
            return Err(anyhow!("suricata install requires root privileges"));
        }

        if debug_enabled() {
            info!("[ids] Suricata not found; attempting install");
        }

        if command_exists("apt-get") {
            run_cmd("apt-get", &["update"]).await?;
            run_cmd("apt-get", &["install", "-y", "suricata"]).await?;
        } else if command_exists("dnf") {
            run_cmd("dnf", &["install", "-y", "suricata"]).await?;
        } else if command_exists("yum") {
            run_cmd("yum", &["install", "-y", "suricata"]).await?;
        } else if command_exists("pacman") {
            run_cmd("pacman", &["-Sy", "--noconfirm", "suricata"]).await?;
        } else if command_exists("zypper") {
            run_cmd("zypper", &["install", "-y", "suricata"]).await?;
        } else {
            return Err(anyhow!("no supported package manager found"));
        }

        Ok(())
    }

    async fn ensure_suricata_running(&self) -> Result<()> {
        if is_suricata_running().await {
            return Ok(());
        }

        let log_dir = self.log_dir.clone();
        let rules_path = self.rules_path.clone();
        let config_path = self.config_path.clone();
        let iface = self.iface.clone();

        fs::create_dir_all(&log_dir).await?;
        if let Some(parent) = rules_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        if !rules_path.exists() {
            fs::write(&rules_path, "# Percepta managed rules\n").await?;
        }

        let eve_types = std::env::var("PERCEPTA_SURICATA_EVE_TYPES")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "alert,dns,http,tls,flow".to_string());

        let eve_types = if eve_types.contains('[') {
            eve_types
        } else {
            let parts: Vec<String> = eve_types
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty() {
                "[alert]".to_string()
            } else {
                format!("[{}]", parts.join(","))
            }
        };

        let mut cmd = Command::new("suricata");
        cmd.arg("-c")
            .arg(&config_path)
            .arg("-i")
            .arg(&iface)
            .arg("-l")
            .arg(&log_dir)
            .arg("-S")
            .arg(&rules_path)
            .arg("--set")
            .arg("outputs.eve-log.enabled=yes")
            .arg("--set")
            .arg("outputs.eve-log.filename=eve.json")
            .arg("--set")
            .arg(format!("outputs.eve-log.types={}", eve_types))
            .arg("--set")
            .arg(format!("default-log-dir={}", log_dir.display()))
            .arg("-D");

        if debug_enabled() {
            info!(
                "[ids] Starting Suricata (iface={}, log_dir={})",
                iface,
                log_dir.display()
            );
        }
        let _ = cmd.spawn().context("failed to spawn suricata")?;

        Ok(())
    }

    async fn sync_rules_if_needed(&mut self) -> Result<()> {
        let url = match &self.rules_url {
            Some(u) => u.clone(),
            None => return Ok(()),
        };

        if self.last_rules_fetch.elapsed() < self.rules_interval {
            return Ok(());
        }
        self.last_rules_fetch = Instant::now();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .context("build http client")?;

        let resp = client
            .get(&url)
            .send()
            .await
            .context("rules fetch failed")?;
        if !resp.status().is_success() {
            return Err(anyhow!("rules fetch failed with status {}", resp.status()));
        }
        let body = resp.text().await.unwrap_or_default();
        if body.trim().is_empty() {
            return Err(anyhow!("rules fetch returned empty body"));
        }

        let hash = hex::encode(sha256(body.as_bytes()));
        if self.last_rules_hash.as_deref() == Some(&hash) {
            if debug_enabled() {
                debug!("[ids] Suricata rules unchanged");
            }
            return Ok(());
        }

        if let Some(parent) = self.rules_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&self.rules_path, body).await?;
        self.last_rules_hash = Some(hash);
        if debug_enabled() {
            info!(
                "[ids] Updated Suricata rules at {}",
                self.rules_path.display()
            );
        }

        // Signal Suricata to reload rules without restarting the daemon.
        if let Err(e) = reload_suricata().await {
            warn!("[ids] Failed to reload Suricata after rules update: {:#}", e);
        }

        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn command_exists(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
async fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(cmd).args(args).status().await?;
    if !status.success() {
        return Err(anyhow!("command failed: {} {:?}", cmd, args));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn detect_iface() -> Option<String> {
    if let Ok(v) = std::env::var("PERCEPTA_SURICATA_IFACE") {
        let s = v.trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }

    if command_exists("ip") {
        if let Ok(out) = Command::new("ip")
            .args(["route", "get", "1.1.1.1"])
            .output()
            .await
        {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                if let Some(dev) = parse_iface_from_ip_route(&txt) {
                    return Some(dev);
                }
            }
        }

        if let Ok(out) = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await
        {
            if out.status.success() {
                let txt = String::from_utf8_lossy(&out.stdout);
                if let Some(dev) = txt.split_whitespace().skip_while(|t| *t != "dev").nth(1) {
                    return Some(dev.to_string());
                }
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn parse_iface_from_ip_route(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    for i in 0..parts.len() {
        if parts[i] == "dev" {
            return parts.get(i + 1).map(|s| s.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
async fn reload_suricata() -> Result<()> {
    // Prefer suricatasc socket command for a clean live-reload.
    if command_exists("suricatasc") {
        let out = Command::new("suricatasc")
            .args(["-c", "reload-rules"])
            .output()
            .await;
        if let Ok(o) = out {
            if o.status.success() {
                if debug_enabled() {
                    info!("[ids] Suricata rules reloaded via suricatasc");
                }
                return Ok(());
            }
        }
    }

    // Fallback: send SIGUSR2 (Suricata's live rule reload signal) to the daemon PID.
    if command_exists("pgrep") {
        if let Ok(out) = Command::new("pgrep")
            .args(["-x", "suricata"])
            .output()
            .await
        {
            if out.status.success() {
                let pid_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if let Some(first_pid) = pid_str.lines().next().and_then(|l| l.trim().parse::<u32>().ok()) {
                    let status = Command::new("kill")
                        .args(["-USR2", &first_pid.to_string()])
                        .status()
                        .await;
                    if let Ok(s) = status {
                        if s.success() {
                            if debug_enabled() {
                                info!("[ids] Suricata rules reloaded via SIGUSR2 (pid={})", first_pid);
                            }
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    Err(anyhow!("no reload method succeeded (suricatasc or SIGUSR2)"))
}

#[cfg(target_os = "linux")]
async fn is_suricata_running() -> bool {
    if command_exists("pgrep") {
        if let Ok(out) = Command::new("pgrep")
            .args(["-x", "suricata"])
            .output()
            .await
        {
            return out.status.success();
        }
    }
    if command_exists("pidof") {
        if let Ok(out) = Command::new("pidof").arg("suricata").output().await {
            return out.status.success();
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn debug_enabled() -> bool {
    std::env::var("PERCEPTA_DEBUG")
        .ok()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .map(|v| v != 0)
        .unwrap_or_else(|| {
            crate::config_store::load_config()
                .map(|c| c.debug)
                .unwrap_or(false)
        })
}

#[cfg(target_os = "linux")]
fn default_rules_url_from_agent_config() -> Option<String> {
    let server = std::env::var("PERCEPTA_SERVER")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(crate::config_store::load_server_addr_robust)?;

    let s = server.trim();
    if s.is_empty() {
        return None;
    }

    let host = if let Some(rest) = s
        .strip_prefix("http://")
        .or_else(|| s.strip_prefix("https://"))
    {
        rest.split('/')
            .next()
            .unwrap_or(rest)
            .split(':')
            .next()
            .unwrap_or(rest)
    } else {
        s.split(':').next().unwrap_or(s)
    };

    if host.is_empty() {
        return None;
    }

    Some(format!("http://{}:8080/api/ids/suricata/rules/raw", host))
}
