//! Percepta Agent Library
//! Exposes core agent functionality for use by different binary targets

// Re-export protobuf definitions
pub mod percepta {
    tonic::include_proto!("percepta.siem.ingestion.v1");
}

// Re-export core modules
pub mod client;
pub mod collector;
pub mod embedded_assets;
pub mod files;
pub mod config_store;
pub mod identity;
pub mod system_info;
pub mod tls;
pub mod windows_service;

#[cfg(all(target_os = "windows", feature = "windows-service"))]
pub mod tray_app;

#[cfg(all(windows, target_os = "windows"))]
pub mod windows_eventlog;

#[cfg(target_os = "linux")]
pub mod linux_logs;
