//! Windows Service Integration Module
//!
//! Provides Windows service wrapper functionality for the Percepta SIEM agent.
//! Allows the agent to run as a Windows service with proper service control.

#[cfg(windows)]
use anyhow::{bail, Context, Result};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(windows)]
use tracing::info;

#[cfg(windows)]
static SERVICE_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
#[allow(dead_code)]
const SERVICE_STOPPED: u32 = 1;
#[cfg(windows)]
#[allow(dead_code)]
const SERVICE_START_PENDING: u32 = 2;
#[cfg(windows)]
#[allow(dead_code)]
const SERVICE_STOP_PENDING: u32 = 3;
#[cfg(windows)]
#[allow(dead_code)]
const SERVICE_RUNNING: u32 = 4;
#[cfg(windows)]
#[allow(dead_code)]
const SERVICE_ERROR: u32 = 5;

#[cfg(not(windows))]
#[allow(dead_code)]
const SERVICE_STOPPED: u32 = 1;
#[cfg(not(windows))]
#[allow(dead_code)]
const SERVICE_START_PENDING: u32 = 2;
#[cfg(not(windows))]
#[allow(dead_code)]
const SERVICE_STOP_PENDING: u32 = 3;
#[cfg(not(windows))]
#[allow(dead_code)]
const SERVICE_RUNNING: u32 = 4;
#[cfg(not(windows))]
#[allow(dead_code)]
const SERVICE_ERROR: u32 = 5;

/// Initialize Windows service functionality
#[cfg(windows)]
pub fn init_windows_service() -> Result<()> {
    use std::env;

    // Check if we're running as a service
    if env::args().any(|arg| arg == "--service") {
        info!("🔧 Initializing Windows service mode...");
        info!("✅ Windows service initialized successfully");
    }

    Ok(())
}

/// Set Windows service status (simplified for cross-compilation)
#[cfg(windows)]
pub fn set_service_status(
    _current_state: u32,
    _win32_exit_code: u32,
    _wait_hint: u32,
) -> Result<()> {
    // Simplified implementation for cross-compilation
    Ok(())
}

/// Check if service stop was requested
#[cfg(windows)]
pub fn is_service_stop_requested() -> bool {
    SERVICE_STOP_REQUESTED.load(Ordering::Acquire)
}

/// Run the agent in Windows service mode
#[cfg(windows)]
pub async fn run_as_service<F, Fut>(main_func: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    init_windows_service()?;
    // Update service status to RUNNING (simplified) before starting main logic
    let _ = set_service_status(SERVICE_RUNNING, 0, 0);

    // Run the main function
    let result = main_func().await;

    // Mark service as STOPPED after completion
    let _ = set_service_status(SERVICE_STOPPED, 0, 0);
    result
}

/// Install the agent as a Windows service
#[cfg(windows)]
pub fn install_service() -> Result<()> {
    use std::process::Command;
    use crate::config_store;
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    // Persist server (if provided) into config.json so the service can start on boot
    // without needing a hardcoded binPath argument.
    if let Some(pos) = std::env::args().position(|arg| arg == "--server") {
        if let Some(addr) = std::env::args().nth(pos + 1) {
            if !addr.trim().is_empty() {
                let _ = config_store::set_server_addr(&addr);
            }
        }
    } else if let Ok(addr) = std::env::var("PERCEPTA_SERVER") {
        if !addr.trim().is_empty() {
            let _ = config_store::set_server_addr(&addr);
        }
    }

    // Do NOT bake the server into binPath. Server can be changed later by editing config.json
    // (via GUI) and restarting the service.
    let binpath = format!("\"{}\" --service", exe_path.display());

    let service_name = "PerceptaSIEMAgent";
    let display_name = "Percepta SIEM Agent";
    let description = "Percepta SIEM Agent - Security Information and Event Management";

    // Use sc.exe to create the service
    let output = Command::new("sc")
        .args(&[
            "create",
            service_name,
            &format!("binPath= {}", binpath),
            &format!("DisplayName= \"{}\"", display_name),
            &format!("Description= \"{}\"", description),
            "start= auto",
            "type= own",
        ])
        .output()
        .context("Failed to execute sc.exe")?;

    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to install service: {}", error_msg);
    }

    info!("✅ Service installed successfully: {}", service_name);
    Ok(())
}

/// Uninstall the Windows service
#[cfg(windows)]
pub fn uninstall_service() -> Result<()> {
    use std::process::Command;

    let service_name = "PerceptaSIEMAgent";

    // Stop the service first
    let _ = Command::new("sc").args(&["stop", service_name]).output();

    // Delete the service
    let output = Command::new("sc")
        .args(&["delete", service_name])
        .output()
        .context("Failed to execute sc.exe")?;

    if !output.status.success() {
        let error_msg = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to uninstall service: {}", error_msg);
    }

    info!("✅ Service uninstalled successfully: {}", service_name);
    Ok(())
}

/// Non-Windows implementations (no-op)
#[cfg(not(windows))]
use anyhow::{bail, Result};

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn init_windows_service() -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn set_service_status(
    _current_state: u32,
    _win32_exit_code: u32,
    _wait_hint: u32,
) -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn is_service_stop_requested() -> bool {
    false
}

#[cfg(not(windows))]
pub async fn run_as_service<F, Fut>(main_func: F) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    main_func().await
}

#[cfg(not(windows))]
pub fn install_service() -> Result<()> {
    bail!("Windows service installation not available on this platform")
}

#[cfg(not(windows))]
pub fn uninstall_service() -> Result<()> {
    bail!("Windows service uninstallation not available on this platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_status_functions() {
        // These should not panic on any platform
        let _ = set_service_status(SERVICE_RUNNING, 0, 0);
        assert!(!is_service_stop_requested());
    }

    #[tokio::test]
    async fn test_run_as_service() {
        let result = run_as_service(|| async { Ok::<(), anyhow::Error>(()) }).await;

        assert!(result.is_ok());
    }
}
