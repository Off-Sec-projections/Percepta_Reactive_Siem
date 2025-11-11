use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentUiConfig {
    pub server: String,
    pub debug: bool,
}

pub fn default_config_path() -> PathBuf {
    if let Ok(dir) = std::env::var("PERCEPTA_CONFIG_DIR") {
        return PathBuf::from(dir).join("config.json");
    }

    if cfg!(windows) {
        return PathBuf::from(r"C:\ProgramData\percepta_agent").join("config.json");
    }

    // Prefer /etc for system installs (common for services), otherwise use user config.
    if std::env::var("SUDO_USER").is_ok() {
        return PathBuf::from("/etc/percepta-agent").join("config.json");
    }

    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("percepta-agent/config.json");
    }

    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config/percepta-agent/config.json");
    }

    PathBuf::from("./config.json")
}

pub fn load_config() -> Option<AgentUiConfig> {
    let path = default_config_path();
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<AgentUiConfig>(&raw).ok()
}

pub fn save_config(cfg: &AgentUiConfig) -> Result<()> {
    let path = default_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory: {}", parent.display()))?;
    }
    let s = serde_json::to_string_pretty(cfg).context("Failed to serialize config")?;
    std::fs::write(&path, s).with_context(|| format!("Failed to write config: {}", path.display()))?;
    Ok(())
}

pub fn load_server_addr() -> Option<String> {
    if let Some(cfg) = load_config() {
        let s = cfg.server.trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }

    // Fallback for "run the EXE only" deployments: accept a server-config.txt placed
    // next to the executable, containing a line like: grpc_server=HOST:50051
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("server-config.txt");
            if let Ok(raw) = std::fs::read_to_string(&p) {
                for line in raw.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if let Some(v) = line.strip_prefix("grpc_server=") {
                        let s = v.trim().to_string();
                        if !s.is_empty() {
                            return Some(s);
                        }
                    }
                }
            }
        }
    }

    None
}

pub fn set_server_addr(server: &str) -> Result<()> {
    let mut cfg = load_config().unwrap_or_default();
    cfg.server = server.trim().to_string();
    save_config(&cfg)
}

pub fn normalize_grpc_server_from_enroll_arg(server_arg: &str) -> Option<String> {
    let s = server_arg.trim();
    if s.is_empty() {
        return None;
    }

    // If caller provided an HTTP enrollment URL, convert to host:50051.
    if let Some(rest) = s.strip_prefix("http://").or_else(|| s.strip_prefix("https://")) {
        let hostport = rest.split('/').next().unwrap_or(rest);
        let host = hostport.split(':').next().unwrap_or(hostport);
        if host.is_empty() {
            return None;
        }
        return Some(format!("{}:50051", host));
    }

    // If it's already host:port, keep as-is.
    if s.contains(':') {
        return Some(s.to_string());
    }

    // Bare host.
    Some(format!("{}:50051", s))
}
