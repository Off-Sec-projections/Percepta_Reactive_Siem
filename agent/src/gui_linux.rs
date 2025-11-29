//! Linux-specific GUI platform layer.
//!
//! Provides a StatusNotifier tray bridge, GUI-triggered privileged service
//! management, and the `run()` entry point that launches the shared egui app.

#![cfg(target_os = "linux")]

use eframe::egui;
use ksni::{menu::StandardItem, MenuItem, TrayMethods};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
};
use tracing::{info, warn};
use uuid::Uuid;

use crate::gui_common::{
    build_icon, extract_host, normalize_grpc_addr, PlatformMsg, PerceptaAgentApp,
    LINUX_SERVICE_NAME,
};

const INSTALL_DIR: &str = "/opt/percepta-agent";
const SYSTEM_CONFIG_DIR: &str = "/etc/percepta-agent";
const SYSTEM_DATA_DIR: &str = "/var/lib/percepta-agent";
const SYSTEM_CERT_DIR: &str = "/var/lib/percepta-agent/certs";
const SYSTEM_OUT_DIR: &str = "/var/lib/percepta-agent/outgoing";
const SYSTEM_LOG_DIR: &str = "/var/lib/percepta-agent/logs";
const UNIT_PATH: &str = "/etc/systemd/system/percepta-agent.service";

static TRAY_AVAILABLE: AtomicBool = AtomicBool::new(false);

pub fn tray_available() -> bool {
    TRAY_AVAILABLE.load(Ordering::SeqCst)
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn command_output_text(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("{}{}", stdout, stderr).trim().to_string()
}

fn systemctl_program() -> PathBuf {
    which::which("systemctl").unwrap_or_else(|_| PathBuf::from("systemctl"))
}

fn pkexec_program() -> Option<PathBuf> {
    which::which("pkexec").ok()
}

fn systemctl(args: &[&str]) -> Result<Output, String> {
    Command::new(systemctl_program())
        .args(args)
        .output()
        .map_err(|e| e.to_string())
}

fn run_root_script(script: &str, args: &[String]) -> Result<String, String> {
    let script_path = std::env::temp_dir().join(format!(
        "percepta-agent-root-{}.sh",
        Uuid::new_v4()
    ));
    fs::write(&script_path, script).map_err(|e| e.to_string())?;

    let mut perms = fs::metadata(&script_path)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&script_path, perms).map_err(|e| e.to_string())?;

    let output = if is_root() {
        Command::new("/bin/sh")
            .arg(&script_path)
            .args(args)
            .output()
    } else if let Some(pkexec) = pkexec_program() {
        Command::new(pkexec)
            .arg("/bin/sh")
            .arg(&script_path)
            .args(args)
            .output()
    } else {
        let _ = fs::remove_file(&script_path);
        return Err(
            "Administrator privileges are required, but no GUI polkit helper (pkexec) is available. Use the Linux setup download or install a polkit authentication agent."
                .to_string(),
        );
    }
    .map_err(|e| e.to_string());

    let _ = fs::remove_file(&script_path);

    match output {
        Ok(out) if out.status.success() => {
            let text = command_output_text(&out);
            if text.is_empty() {
                Ok("Command completed successfully".to_string())
            } else {
                Ok(text)
            }
        }
        Ok(out) => {
            let text = command_output_text(&out);
            if text.is_empty() {
                Err("Privileged command failed".to_string())
            } else {
                Err(text)
            }
        }
        Err(err) => Err(err),
    }
}

fn run_systemctl_privileged(action: &str) -> Result<String, String> {
    let script = r#"#!/usr/bin/env sh
set -eu
"$1" "$2" "$3"
"#;

    run_root_script(
        script,
        &[
            systemctl_program().display().to_string(),
            action.to_string(),
            LINUX_SERVICE_NAME.to_string(),
        ],
    )
}

fn bundled_path_if_exists(dir: &Path, file_name: &str) -> String {
    let path = dir.join(file_name);
    if path.exists() {
        path.display().to_string()
    } else {
        String::new()
    }
}

fn install_portal_url(grpc_addr: &str) -> String {
    let host = extract_host(grpc_addr);
    if host.is_empty() {
        String::new()
    } else {
        format!("https://{}", host)
    }
}

fn install_script() -> &'static str {
    r#"#!/usr/bin/env sh
set -eu

SYSTEMCTL_BIN="$1"
SOURCE_BIN="$2"
INSTALL_DIR="$3"
CONFIG_DIR="$4"
DATA_DIR="$5"
CERT_DIR="$6"
OUT_DIR="$7"
LOG_DIR="$8"
UNIT_PATH="$9"
SERVICE_NAME="${10}"
GRPC_SERVER="${11}"
PORTAL_URL="${12}"
SOURCE_CA="${13}"
SOURCE_OTK="${14}"
USER_CERT_DIR="${15}"
USER_CONFIG_PATH="${16}"

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR" "$CERT_DIR" "$OUT_DIR" "$LOG_DIR"
install -m 0755 "$SOURCE_BIN" "$INSTALL_DIR/percepta-agent"

cat > "$INSTALL_DIR/server-config.txt" <<EOF
grpc_server=$GRPC_SERVER
portal_url=$PORTAL_URL
EOF

if [ -n "$SOURCE_CA" ] && [ -f "$SOURCE_CA" ]; then
  install -m 0644 "$SOURCE_CA" "$INSTALL_DIR/ca_cert.pem"
fi
if [ -n "$SOURCE_OTK" ] && [ -f "$SOURCE_OTK" ]; then
  install -m 0600 "$SOURCE_OTK" "$INSTALL_DIR/otk.txt"
fi

if [ -d "$USER_CERT_DIR" ]; then
  for file in agent_cert.pem agent_key.pem ca_cert.pem identity.json agent_id.txt; do
    if [ -f "$USER_CERT_DIR/$file" ]; then
      install -m 0600 "$USER_CERT_DIR/$file" "$CERT_DIR/$file"
    fi
  done
  [ -f "$CERT_DIR/ca_cert.pem" ] && chmod 0644 "$CERT_DIR/ca_cert.pem"
  [ -f "$CERT_DIR/identity.json" ] && chmod 0644 "$CERT_DIR/identity.json"
  [ -f "$CERT_DIR/agent_id.txt" ] && chmod 0644 "$CERT_DIR/agent_id.txt"
fi

if [ -f "$USER_CONFIG_PATH" ]; then
  install -m 0644 "$USER_CONFIG_PATH" "$CONFIG_DIR/config.json"
fi

cat > "$UNIT_PATH" <<EOF
[Unit]
Description=Percepta SIEM Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=PERCEPTA_SERVER=$GRPC_SERVER
Environment=PERCEPTA_CONFIG_DIR=$CONFIG_DIR
Environment=PERCEPTA_CERT_DIR=$CERT_DIR
Environment=PERCEPTA_OUT=$OUT_DIR
ExecStart=$INSTALL_DIR/percepta-agent --service
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

"$SYSTEMCTL_BIN" daemon-reload
"$SYSTEMCTL_BIN" enable "$SERVICE_NAME"
echo "Percepta agent service installed under $INSTALL_DIR"
echo "Use the Start button in the GUI to launch the service now."
"#
}

struct LinuxTray {
    tx: mpsc::Sender<PlatformMsg>,
}

impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        "percepta-agent".into()
    }

    fn icon_name(&self) -> String {
        "security-high".into()
    }

    fn title(&self) -> String {
        "Percepta SIEM Agent".into()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.tx.send(PlatformMsg::ShowWindow);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        vec![
            StandardItem {
                label: "Show Window".into(),
                icon_name: "window-restore".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(PlatformMsg::ShowWindow);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Stop Agent".into(),
                icon_name: "media-playback-stop".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(PlatformMsg::StopAgent);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Restart Agent".into(),
                icon_name: "view-refresh".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(PlatformMsg::RestartAgent);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Settings".into(),
                icon_name: "preferences-system".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(PlatformMsg::OpenSettings);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: "Exit Agent".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|this: &mut Self| {
                    let _ = this.tx.send(PlatformMsg::Exit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }

    fn watcher_online(&self) {
        TRAY_AVAILABLE.store(true, Ordering::SeqCst);
        info!("Linux tray watcher online");
    }

    fn watcher_offline(&self, reason: ksni::OfflineReason) -> bool {
        TRAY_AVAILABLE.store(false, Ordering::SeqCst);
        warn!(?reason, "Linux tray watcher offline; tray minimize disabled");
        true
    }
}

fn start_tray_thread(platform_tx: mpsc::Sender<PlatformMsg>) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                warn!(error = %err, "Failed to start Linux tray runtime");
                return;
            }
        };

        runtime.block_on(async move {
            let tray = LinuxTray { tx: platform_tx };
            match tray.spawn().await {
                Ok(_handle) => {
                    TRAY_AVAILABLE.store(true, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }
                Err(err) => {
                    TRAY_AVAILABLE.store(false, Ordering::SeqCst);
                    warn!(error = %err, "Failed to create Linux tray bridge");
                }
            }
        });
    });
}

pub fn service_query() -> Option<bool> {
    let out = systemctl(&["is-active", LINUX_SERVICE_NAME]).ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    Some(stdout == "active" || stdout == "activating")
}

pub fn service_start() -> Result<String, String> {
    run_systemctl_privileged("start")
}

pub fn service_stop() -> Result<String, String> {
    run_systemctl_privileged("stop")
}

pub fn service_restart() -> Result<String, String> {
    run_systemctl_privileged("restart")
}

pub fn service_install(server: &str) -> Result<String, String> {
    let grpc_server = normalize_grpc_addr(server);
    if grpc_server.is_empty() {
        return Err("A valid server address is required before installing the Linux service".into());
    }

    let core_path = crate::gui_common::resolve_core_binary_path()
        .ok_or_else(|| "Agent executable not found".to_string())?;
    let source_dir = core_path
        .parent()
        .ok_or_else(|| "Agent executable directory not found".to_string())?;

    run_root_script(
        install_script(),
        &[
            systemctl_program().display().to_string(),
            core_path.display().to_string(),
            INSTALL_DIR.to_string(),
            SYSTEM_CONFIG_DIR.to_string(),
            SYSTEM_DATA_DIR.to_string(),
            SYSTEM_CERT_DIR.to_string(),
            SYSTEM_OUT_DIR.to_string(),
            SYSTEM_LOG_DIR.to_string(),
            UNIT_PATH.to_string(),
            LINUX_SERVICE_NAME.to_string(),
            grpc_server.clone(),
            install_portal_url(&grpc_server),
            bundled_path_if_exists(source_dir, "ca_cert.pem"),
            bundled_path_if_exists(source_dir, "otk.txt"),
            crate::default_cert_dir_path().display().to_string(),
            crate::config_store::default_config_path().display().to_string(),
        ],
    )
}

pub fn service_uninstall() -> Result<String, String> {
    let script = r#"#!/usr/bin/env sh
set -eu
SYSTEMCTL_BIN="$1"
UNIT_PATH="$2"
SERVICE_NAME="$3"
"$SYSTEMCTL_BIN" stop "$SERVICE_NAME" >/dev/null 2>&1 || true
"$SYSTEMCTL_BIN" disable "$SERVICE_NAME" >/dev/null 2>&1 || true
rm -f "$UNIT_PATH"
"$SYSTEMCTL_BIN" daemon-reload
echo "Percepta agent service uninstalled"
"#;

    run_root_script(
        script,
        &[
            systemctl_program().display().to_string(),
            UNIT_PATH.to_string(),
            LINUX_SERVICE_NAME.to_string(),
        ],
    )
}

pub fn service_set_autostart(enabled: bool) -> Result<String, String> {
    let action = if enabled { "enable" } else { "disable" };
    run_systemctl_privileged(action)
}

/// Probe whether the Wayland client library is loadable.  If the session is
/// Wayland but `libwayland-client.so` is absent, winit 0.29 crashes instead of
/// falling back to X11.  We detect this early and redirect to X11.
fn ensure_display_backend() {
    let is_wayland = std::env::var("WAYLAND_DISPLAY").is_ok()
        || std::env::var("XDG_SESSION_TYPE")
            .map(|v| v.eq_ignore_ascii_case("wayland"))
            .unwrap_or(false);

    if !is_wayland {
        return;
    }

    // Try to dlopen the Wayland client library.  If it's missing, force X11.
    let lib_available = unsafe {
        let name = b"libwayland-client.so.0\0";
        let handle = libc::dlopen(name.as_ptr() as *const _, libc::RTLD_LAZY);
        if handle.is_null() {
            false
        } else {
            libc::dlclose(handle);
            true
        }
    };

    if !lib_available {
        warn!(
            "Wayland session detected but libwayland-client.so not found — falling back to X11"
        );
        // Clearing WAYLAND_DISPLAY makes winit pick the X11 backend.
        std::env::remove_var("WAYLAND_DISPLAY");
    }
}

pub fn run() -> anyhow::Result<()> {
    ensure_display_backend();

    let (platform_tx, platform_rx) = mpsc::channel::<PlatformMsg>();
    start_tray_thread(platform_tx);

    let app = PerceptaAgentApp::new(platform_rx);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 640.0])
            .with_min_inner_size([720.0, 500.0])
            .with_icon(std::sync::Arc::new(build_icon()))
            .with_title("Percepta SIEM Agent"),
        vsync: true,
        hardware_acceleration: eframe::HardwareAcceleration::Preferred,
        follow_system_theme: false,
        ..Default::default()
    };

    eframe::run_native(
        "Percepta SIEM Agent",
        native_options,
        Box::new(move |_cc| Box::new(app)),
    )
    .map_err(|e| anyhow::anyhow!("eframe error: {}", e))
}