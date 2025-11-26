#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::{anyhow, Context, Result};
use base64::Engine as _;
use eframe::egui;
use percepta_agent::gui_common::{
    build_icon, ACCENT, BG_CARD, BG_PRIMARY, BORDER_CARD, BTN_BG, GREEN, ORANGE, RED,
    TEXT_MUTED, TEXT_PRIMARY, TEXT_SECONDARY,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    process::Command,
    sync::{mpsc, Arc},
    time::Instant,
};
use zip::ZipArchive;

const INSTALLER_MAGIC: &[u8] = b"PERCEPTA_INSTALLER_V1\0";

#[cfg(windows)]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallerManifest {
    platform: String,
    display_name: String,
    agent_binary_name: String,
    service_name: String,
}

impl InstallerManifest {
    fn default_for_current_platform() -> Self {
        #[cfg(windows)]
        {
            return Self {
                platform: "windows".to_string(),
                display_name: "Percepta SIEM Agent".to_string(),
                agent_binary_name: "percepta-agent.exe".to_string(),
                service_name: "PerceptaSIEMAgent".to_string(),
            };
        }
        #[cfg(target_os = "linux")]
        {
            Self {
                platform: "linux".to_string(),
                display_name: "Percepta SIEM Agent".to_string(),
                agent_binary_name: "percepta-agent".to_string(),
                service_name: "percepta-agent".to_string(),
            }
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Self {
                platform: std::env::consts::OS.to_string(),
                display_name: "Percepta SIEM Agent".to_string(),
                agent_binary_name: "percepta-agent".to_string(),
                service_name: "percepta-agent".to_string(),
            }
        }
    }
}

#[derive(Clone, Debug)]
struct PayloadBundle {
    manifest: InstallerManifest,
    files: HashMap<String, Vec<u8>>,
}

impl PayloadBundle {
    #[cfg(windows)]
    fn agent_bytes(&self) -> Result<&[u8]> {
        self.files
            .get(&self.manifest.agent_binary_name)
            .map(|bytes| bytes.as_slice())
            .ok_or_else(|| anyhow!("Embedded agent binary '{}' is missing", self.manifest.agent_binary_name))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InstallRequest {
    install_dir: String,
    install_service: bool,
    launch_after_install: bool,
}

#[derive(Clone, Debug)]
struct InstallOutcome {
    install_dir: PathBuf,
    launched: bool,
    service_enabled: bool,
    message: String,
}

struct InstallerApp {
    bundle: Result<Arc<PayloadBundle>, String>,
    install_dir: String,
    install_service: bool,
    launch_after_install: bool,
    status: String,
    install_rx: Option<mpsc::Receiver<Result<InstallOutcome, String>>>,
    in_progress: bool,
    finished: bool,
    close_requested: bool,
    auto_request: Option<InstallRequest>,
    auto_started: bool,
    installed_dir: Option<PathBuf>,
    last_status_at: Instant,
}

impl InstallerApp {
    fn new() -> Self {
        let bundle = read_payload_bundle_from_current_exe().map(Arc::new).map_err(|e| e.to_string());
        let auto_request = parse_install_request_arg();
        let install_service = auto_request
            .as_ref()
            .map(|req| req.install_service)
            .unwrap_or(true);
        let install_dir = auto_request
            .as_ref()
            .map(|req| req.install_dir.clone())
            .unwrap_or_else(|| default_install_dir(install_service).display().to_string());

        Self {
            bundle,
            install_dir,
            install_service,
            launch_after_install: auto_request
                .as_ref()
                .map(|req| req.launch_after_install)
                .unwrap_or(true),
            status: "Ready to install".to_string(),
            install_rx: None,
            in_progress: false,
            finished: false,
            close_requested: false,
            auto_request,
            auto_started: false,
            installed_dir: None,
            last_status_at: Instant::now(),
        }
    }

    fn current_request(&self) -> InstallRequest {
        InstallRequest {
            install_dir: self.install_dir.trim().to_string(),
            install_service: self.install_service,
            launch_after_install: self.launch_after_install,
        }
    }

    fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
        self.last_status_at = Instant::now();
    }

    fn start_install(&mut self) {
        if self.in_progress {
            return;
        }

        let bundle = match &self.bundle {
            Ok(bundle) => bundle.clone(),
            Err(err) => {
                self.set_status(err.clone());
                return;
            }
        };

        let request = self.current_request();
        if request.install_dir.trim().is_empty() {
            self.set_status("Choose an installation directory first");
            return;
        }

        #[cfg(windows)]
        if windows_requires_elevation(&request) && !is_windows_elevated() {
            match relaunch_windows_elevated(&request) {
                Ok(true) => {
                    self.set_status("Administrator approval requested. Continue in the elevated installer window.");
                    self.close_requested = true;
                }
                Ok(false) => self.set_status("Administrator approval was cancelled."),
                Err(err) => self.set_status(format!("Failed to request elevation: {err}")),
            }
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.install_rx = Some(rx);
        self.in_progress = true;
        self.finished = false;
        self.set_status("Installing Percepta Agent...");

        std::thread::spawn(move || {
            let result = perform_install(bundle, request);
            let _ = tx.send(result);
        });
    }

    fn poll_install_result(&mut self) {
        if let Some(rx) = &self.install_rx {
            if let Ok(result) = rx.try_recv() {
                self.in_progress = false;
                self.install_rx = None;
                match result {
                    Ok(outcome) => {
                        self.finished = true;
                        self.installed_dir = Some(outcome.install_dir.clone());
                        let suffix = match (outcome.service_enabled, outcome.launched) {
                            (true, true) => " Service is enabled and the GUI was launched.",
                            (true, false) => " Service is enabled.",
                            (false, true) => " GUI was launched.",
                            (false, false) => "",
                        };
                        self.set_status(format!("{}{}", outcome.message, suffix));
                    }
                    Err(err) => {
                        self.finished = false;
                        self.set_status(format!("Installation failed: {err}"));
                    }
                }
            }
        }
    }
}

impl eframe::App for InstallerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.close_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        if self.auto_request.is_some() && !self.auto_started {
            self.auto_started = true;
            self.start_install();
        }

        self.poll_install_result();

        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BG_PRIMARY;
        visuals.window_fill = BG_CARD;
        visuals.widgets.noninteractive.bg_fill = BG_CARD;
        visuals.widgets.inactive.bg_fill = BTN_BG;
        visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(0x1A, 0x28, 0x48);
        visuals.override_text_color = Some(TEXT_PRIMARY);
        visuals.selection.bg_fill = egui::Color32::from_rgba_unmultiplied(0, 212, 255, 30);
        ctx.set_visuals(visuals);

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(BG_PRIMARY).inner_margin(egui::Margin::same(20.0)))
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    ui.heading(egui::RichText::new("Percepta Agent Installer").size(28.0).color(TEXT_PRIMARY));
                    ui.label(
                        egui::RichText::new("GUI-only installation. No PowerShell or terminal required.")
                            .size(14.0)
                            .color(TEXT_SECONDARY),
                    );
                });

                ui.add_space(18.0);

                egui::Frame::none()
                    .fill(BG_CARD)
                    .rounding(14.0)
                    .stroke(egui::Stroke::new(1.0, BORDER_CARD))
                    .inner_margin(egui::Margin::same(18.0))
                    .show(ui, |ui| {
                        match &self.bundle {
                            Ok(bundle) => {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "Installer payload: {} for {}",
                                        bundle.manifest.display_name,
                                        bundle.manifest.platform.to_uppercase()
                                    ))
                                    .size(14.0)
                                    .strong()
                                    .color(ACCENT),
                                );
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("Installation Directory").size(13.0).color(TEXT_SECONDARY));
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.install_dir)
                                        .desired_width(f32::INFINITY)
                                        .margin(egui::vec2(10.0, 8.0)),
                                );
                                ui.add_space(8.0);

                                ui.checkbox(&mut self.install_service, "Install background service");
                                ui.checkbox(&mut self.launch_after_install, "Launch the GUI after installation");

                                #[cfg(target_os = "linux")]
                                if self.install_service {
                                    ui.label(
                                        egui::RichText::new("Service install will request system authorization through the desktop polkit prompt.")
                                            .size(12.0)
                                            .color(ORANGE),
                                    );
                                }

                                #[cfg(windows)]
                                if self.install_service {
                                    ui.label(
                                        egui::RichText::new("Service install will request UAC administrator approval.")
                                            .size(12.0)
                                            .color(ORANGE),
                                    );
                                }

                                ui.add_space(12.0);
                                let install_btn = egui::Button::new(
                                    egui::RichText::new(if self.in_progress { "Installing..." } else { "Install Percepta Agent" })
                                        .size(14.0)
                                        .strong(),
                                )
                                .fill(egui::Color32::from_rgba_unmultiplied(0, 212, 255, 48))
                                .stroke(egui::Stroke::new(1.0, ACCENT))
                                .rounding(10.0);

                                if ui.add_enabled(!self.in_progress, install_btn).clicked() {
                                    self.start_install();
                                }

                                if self.finished {
                                    ui.add_space(10.0);
                                    if let Some(dir) = &self.installed_dir {
                                        ui.label(
                                            egui::RichText::new(format!("Installed to {}", dir.display()))
                                                .size(12.0)
                                                .color(GREEN),
                                        );
                                    }
                                }
                            }
                            Err(err) => {
                                ui.label(egui::RichText::new("Installer payload missing").size(16.0).strong().color(RED));
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new(err).size(13.0).color(TEXT_SECONDARY));
                                ui.add_space(6.0);
                                ui.label(
                                    egui::RichText::new(
                                        "This binary is the installer shell only. Download it from the Percepta portal so it contains the embedded agent payload.",
                                    )
                                    .size(12.0)
                                    .color(TEXT_MUTED),
                                );
                            }
                        }
                    });

                ui.add_space(14.0);
                let status_color = if self.status.starts_with("Installation failed") {
                    RED
                } else if self.finished {
                    GREEN
                } else if self.in_progress {
                    ORANGE
                } else {
                    TEXT_SECONDARY
                };
                ui.label(egui::RichText::new(&self.status).size(13.0).color(status_color));
            });

        ctx.request_repaint_after(std::time::Duration::from_millis(120));
    }
}

fn default_install_dir(install_service: bool) -> PathBuf {
    #[cfg(windows)]
    {
        if install_service {
            std::env::var_os("ProgramFiles")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
                .join("Percepta SIEM Agent")
        } else {
            std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
                .join("Percepta SIEM Agent")
        }
    }
    #[cfg(target_os = "linux")]
    {
        if install_service {
            PathBuf::from("/opt/percepta-agent")
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".local/share/percepta-agent")
        } else {
            PathBuf::from("./percepta-agent")
        }
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = install_service;
        PathBuf::from("./percepta-agent")
    }
}

fn read_payload_bundle_from_current_exe() -> Result<PayloadBundle> {
    let exe = std::env::current_exe().context("Failed to locate installer binary")?;
    let bytes = std::fs::read(&exe).with_context(|| format!("Failed to read {}", exe.display()))?;
    let footer_size = INSTALLER_MAGIC.len() + 8;
    if bytes.len() < footer_size {
        return Err(anyhow!("No embedded installer payload found"));
    }

    let footer_start = bytes.len() - footer_size;
    let magic = &bytes[footer_start..footer_start + INSTALLER_MAGIC.len()];
    if magic != INSTALLER_MAGIC {
        return Err(anyhow!("No embedded installer payload found"));
    }

    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&bytes[footer_start + INSTALLER_MAGIC.len()..]);
    let payload_len = u64::from_le_bytes(len_bytes) as usize;
    if payload_len == 0 || payload_len > footer_start {
        return Err(anyhow!("Installer payload footer is invalid"));
    }

    let payload_start = footer_start - payload_len;
    let payload = bytes[payload_start..footer_start].to_vec();
    let mut zip = ZipArchive::new(Cursor::new(payload)).context("Failed to read embedded installer archive")?;
    let mut files = HashMap::new();
    let mut manifest = InstallerManifest::default_for_current_platform();

    for index in 0..zip.len() {
        let mut file = zip.by_index(index).context("Failed to read embedded installer entry")?;
        let name = file.name().to_string();
        let mut entry_bytes = Vec::new();
        file.read_to_end(&mut entry_bytes)
            .with_context(|| format!("Failed to extract installer entry {name}"))?;
        if name == "manifest.json" {
            manifest = serde_json::from_slice(&entry_bytes).context("Invalid installer manifest")?;
        } else {
            files.insert(name, entry_bytes);
        }
    }

    Ok(PayloadBundle { manifest, files })
}

fn parse_install_request_arg() -> Option<InstallRequest> {
    let prefix = "--installer-apply=";
    let encoded = std::env::args().find_map(|arg| arg.strip_prefix(prefix).map(str::to_string))?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn perform_install(bundle: Arc<PayloadBundle>, request: InstallRequest) -> Result<InstallOutcome, String> {
    #[cfg(windows)]
    {
        perform_windows_install(&bundle, &request)
    }
    #[cfg(target_os = "linux")]
    {
        perform_linux_install(&bundle, &request)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = bundle;
        let _ = request;
        Err("Installer is not implemented for this platform".to_string())
    }
}

fn write_bundle_file(path: &Path, bytes: &[u8], _executable: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("Failed to write {}", path.display()))?;
    #[cfg(target_os = "linux")]
    if _executable {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .with_context(|| format!("Failed to read {}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("Failed to chmod {}", path.display()))?;
    }
    Ok(())
}

fn launch_agent(agent_path: &Path) -> Result<()> {
    let mut cmd = Command::new(agent_path);
    if let Some(dir) = agent_path.parent() {
        cmd.current_dir(dir);
    }
    cmd.spawn()
        .with_context(|| format!("Failed to launch {}", agent_path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn windows_requires_elevation(request: &InstallRequest) -> bool {
    request.install_service || PathBuf::from(&request.install_dir).starts_with(default_install_dir(true))
}

#[cfg(windows)]
fn is_windows_elevated() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

#[cfg(windows)]
fn relaunch_windows_elevated(request: &InstallRequest) -> Result<bool> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    let exe = std::env::current_exe().context("Failed to locate installer executable")?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(request).context("Failed to encode installer request")?);
    let args = format!("--installer-apply={encoded}");

    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let args_w: Vec<u16> = OsStr::new(&args).encode_wide().chain(Some(0)).collect();
    let verb_w: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();

    let result = unsafe {
        winapi::um::shellapi::ShellExecuteW(
            std::ptr::null_mut(),
            verb_w.as_ptr(),
            exe_w.as_ptr(),
            args_w.as_ptr(),
            std::ptr::null(),
            winapi::um::winuser::SW_SHOWNORMAL,
        )
    };

    Ok((result as usize) > 32)
}

#[cfg(windows)]
fn perform_windows_install(bundle: &PayloadBundle, request: &InstallRequest) -> Result<InstallOutcome, String> {
    let install_dir = PathBuf::from(&request.install_dir);
    std::fs::create_dir_all(&install_dir).map_err(|e| e.to_string())?;

    for (name, bytes) in &bundle.files {
        if name == "manifest.json" {
            continue;
        }
        if name == &bundle.manifest.agent_binary_name {
            continue;
        }
        let dest = install_dir.join(name);
        write_bundle_file(&dest, bytes, false).map_err(|e| e.to_string())?;
    }

    let agent_path = install_dir.join(&bundle.manifest.agent_binary_name);
    let agent_bytes = bundle.agent_bytes().map_err(|e| e.to_string())?;
    write_bundle_file(&agent_path, agent_bytes, false).map_err(|e| e.to_string())?;

    if request.install_service {
        let run_sc = |args: &[&str], step: &str| -> Result<std::process::Output, String> {
            let output = Command::new("sc.exe")
                .args(args)
                .output()
                .map_err(|e| format!("{step}: {e}"))?;
            if output.status.success() {
                Ok(output)
            } else {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let details = match (stdout.is_empty(), stderr.is_empty()) {
                    (true, true) => String::new(),
                    (false, true) => stdout,
                    (true, false) => stderr,
                    (false, false) => format!("{stdout}\n{stderr}"),
                };
                if details.is_empty() {
                    Err(step.to_string())
                } else {
                    Err(format!("{step}: {details}"))
                }
            }
        };
        let bin_path = format!("\"{}\" --service", agent_path.display());
        let query = Command::new("sc.exe")
            .args(["query", &bundle.manifest.service_name])
            .output()
            .map_err(|e| e.to_string())?;
        let exists = query.status.success() || String::from_utf8_lossy(&query.stdout).contains("SERVICE_NAME");
        if exists {
            let _ = Command::new("sc.exe")
                .args(["stop", &bundle.manifest.service_name])
                .output();
            run_sc(
                &["config", &bundle.manifest.service_name, "binPath=", &bin_path, "start=", "auto"],
                "Failed to update Windows service configuration",
            )?;
        } else {
            run_sc(
                &[
                    "create",
                    &bundle.manifest.service_name,
                    "binPath=",
                    &bin_path,
                    "start=",
                    "auto",
                    "DisplayName=",
                    &bundle.manifest.display_name,
                ],
                "Failed to create Windows service",
            )?;
        }
        run_sc(
            &["start", &bundle.manifest.service_name],
            "Failed to start Windows service",
        )?;
        std::thread::sleep(std::time::Duration::from_millis(500));
        let verify = run_sc(
            &["query", &bundle.manifest.service_name],
            "Failed to verify Windows service state",
        )?;
        let verify_stdout = String::from_utf8_lossy(&verify.stdout);
        if !verify_stdout.contains("RUNNING") && !verify_stdout.contains("START_PENDING") {
            return Err(format!(
                "Windows service did not reach a running state after install: {}",
                verify_stdout.trim()
            ));
        }
    }

    let launched = if request.launch_after_install {
        launch_agent(&agent_path).map_err(|e| e.to_string())?;
        true
    } else {
        false
    };

    Ok(InstallOutcome {
        install_dir,
        launched,
        service_enabled: request.install_service,
        message: if launched {
            "Percepta Agent installed successfully and the GUI was launched.".to_string()
        } else {
            "Percepta Agent installed successfully.".to_string()
        },
    })
}

#[cfg(target_os = "linux")]
fn linux_needs_privilege(request: &InstallRequest) -> bool {
    request.install_service
        || request.install_dir.starts_with("/opt/")
        || request.install_dir.starts_with("/usr/")
        || request.install_dir == "/opt/percepta-agent"
}

#[cfg(target_os = "linux")]
fn is_linux_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn pkexec_program() -> Option<PathBuf> {
    which::which("pkexec").ok()
}

#[cfg(target_os = "linux")]
fn run_linux_root_script(script: &str, args: &[String]) -> Result<String, String> {
    use std::os::unix::fs::PermissionsExt;

    let script_path = std::env::temp_dir().join(format!("percepta-installer-{}.sh", uuid::Uuid::new_v4()));
    std::fs::write(&script_path, script).map_err(|e| e.to_string())?;
    let mut perms = std::fs::metadata(&script_path)
        .map_err(|e| e.to_string())?
        .permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&script_path, perms).map_err(|e| e.to_string())?;

    let output = if is_linux_root() {
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
        let _ = std::fs::remove_file(&script_path);
        return Err("System installation needs a desktop polkit helper. pkexec was not found.".to_string());
    }
    .map_err(|e| e.to_string())?;

    let _ = std::fs::remove_file(&script_path);

    if output.status.success() {
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .trim()
        .to_string())
    } else {
        Err(format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .trim()
        .to_string())
    }
}

#[cfg(target_os = "linux")]
fn write_linux_desktop_entry(app_dir: &Path, system_wide: bool) -> Result<()> {
    let desktop_dir = if system_wide {
        PathBuf::from("/usr/local/share/applications")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share/applications")
    } else {
        PathBuf::from("./.local/share/applications")
    };
    std::fs::create_dir_all(&desktop_dir)
        .with_context(|| format!("Failed to create {}", desktop_dir.display()))?;

    let desktop_file = desktop_dir.join("percepta-agent.desktop");
    let content = format!(
        "[Desktop Entry]\nType=Application\nName=Percepta SIEM Agent\nExec={0}/percepta-agent\nPath={0}\nTerminal=false\nCategories=Utility;Security;\nStartupWMClass=Percepta SIEM Agent\n",
        app_dir.display()
    );
    std::fs::write(&desktop_file, content)
        .with_context(|| format!("Failed to write {}", desktop_file.display()))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn build_linux_staging_dir(bundle: &PayloadBundle) -> Result<PathBuf, String> {
    let staging = std::env::temp_dir().join(format!("percepta-installer-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&staging).map_err(|e| e.to_string())?;
    for (name, bytes) in &bundle.files {
        if name == "manifest.json" {
            continue;
        }
        let dest = staging.join(name);
        write_bundle_file(&dest, bytes, name == &bundle.manifest.agent_binary_name).map_err(|e| e.to_string())?;
    }
    Ok(staging)
}

#[cfg(target_os = "linux")]
fn perform_linux_install(bundle: &PayloadBundle, request: &InstallRequest) -> Result<InstallOutcome, String> {
    let install_dir = PathBuf::from(&request.install_dir);
    let needs_privilege = linux_needs_privilege(request);
    let staging = build_linux_staging_dir(bundle)?;
    let agent_path = install_dir.join(&bundle.manifest.agent_binary_name);

    let result = if needs_privilege {
        let script = r#"#!/usr/bin/env sh
set -eu
STAGING="$1"
INSTALL_DIR="$2"
SERVICE_NAME="$3"
AGENT_NAME="$4"
START_SERVICE="$5"
mkdir -p "$INSTALL_DIR" /etc/percepta-agent /var/lib/percepta-agent/certs /var/lib/percepta-agent/outgoing /var/lib/percepta-agent/logs /usr/local/share/applications
install -m 0755 "$STAGING/$AGENT_NAME" "$INSTALL_DIR/$AGENT_NAME"
for name in server-config.txt ca_cert.pem otk.txt; do
  if [ -f "$STAGING/$name" ]; then
    install -m 0644 "$STAGING/$name" "$INSTALL_DIR/$name"
  fi
done
cat > /etc/systemd/system/$SERVICE_NAME.service <<EOF
[Unit]
Description=Percepta SIEM Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=PERCEPTA_CONFIG_DIR=/etc/percepta-agent
Environment=PERCEPTA_CERT_DIR=/var/lib/percepta-agent/certs
Environment=PERCEPTA_OUT=/var/lib/percepta-agent/outgoing
ExecStart=$INSTALL_DIR/$AGENT_NAME --service
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
cat > /usr/local/share/applications/percepta-agent.desktop <<EOF
[Desktop Entry]
Type=Application
Name=Percepta SIEM Agent
Exec=$INSTALL_DIR/$AGENT_NAME
Path=$INSTALL_DIR
Terminal=false
Categories=Utility;Security;
StartupWMClass=Percepta SIEM Agent
EOF
systemctl daemon-reload
if [ "$START_SERVICE" = "1" ]; then
  systemctl enable --now "$SERVICE_NAME"
else
  systemctl enable "$SERVICE_NAME"
fi
"#;
        run_linux_root_script(
            script,
            &[
                staging.display().to_string(),
                install_dir.display().to_string(),
                bundle.manifest.service_name.clone(),
                bundle.manifest.agent_binary_name.clone(),
                if request.install_service { "1" } else { "0" }.to_string(),
            ],
        )
    } else {
        std::fs::create_dir_all(&install_dir).map_err(|e| e.to_string())?;
        for (name, bytes) in &bundle.files {
            if name == "manifest.json" {
                continue;
            }
            let dest = install_dir.join(name);
            write_bundle_file(&dest, bytes, name == &bundle.manifest.agent_binary_name).map_err(|e| e.to_string())?;
        }
        write_linux_desktop_entry(&install_dir, false).map_err(|e| e.to_string())?;
        Ok(String::new())
    };

    let _ = std::fs::remove_dir_all(&staging);
    result?;

    let launched = if request.launch_after_install {
        launch_agent(&agent_path).map_err(|e| e.to_string())?;
        true
    } else {
        false
    };

    Ok(InstallOutcome {
        install_dir,
        launched,
        service_enabled: request.install_service,
        message: if launched {
            "Percepta Agent installed successfully and the GUI was launched.".to_string()
        } else {
            "Percepta Agent installed successfully.".to_string()
        },
    })
}

fn main() -> Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 520.0])
            .with_min_inner_size([620.0, 420.0])
            .with_icon(std::sync::Arc::new(build_icon()))
            .with_title("Percepta Agent Installer"),
        ..Default::default()
    };

    eframe::run_native(
        "Percepta Agent Installer",
        native_options,
        Box::new(|_cc| Box::new(InstallerApp::new())),
    )
    .map_err(|e| anyhow!("Installer GUI error: {e}"))?;

    Ok(())
}