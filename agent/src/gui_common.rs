//! Cross-platform GUI core for Percepta SIEM Agent.
//!
//! Contains the full egui App, color palette, tab rendering, enrollment logic,
//! and all UI helper widgets. Platform-specific details (tray icon, service
//! management) are delegated to `gui_windows` and `gui_linux` modules.

use eframe::egui;
use std::{
    net::TcpStream,
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    time::{Duration, Instant},
};
use crate::config_store;
use crate::embedded_assets;
use crate::identity;
use crate::identity::DeviceIdentity;
use crate::system_info;
use crate::tls;

// ─── Color palette (dark theme) ──────────────────────────────────────────────

pub const BG_PRIMARY: egui::Color32 = egui::Color32::from_rgb(0x09, 0x0C, 0x16);
pub const BG_CARD: egui::Color32 = egui::Color32::from_rgb(0x0A, 0x0E, 0x1C);
pub const BG_TITLEBAR: egui::Color32 = egui::Color32::from_rgb(0x06, 0x09, 0x12);
pub const BORDER_CARD: egui::Color32 = egui::Color32::from_rgb(0x22, 0x34, 0x5C);
pub const BORDER_SUBTLE: egui::Color32 = egui::Color32::from_rgb(0x1E, 0x2C, 0x4E);
pub const ACCENT: egui::Color32 = egui::Color32::from_rgb(0x00, 0xD4, 0xFF);
pub const TEXT_PRIMARY: egui::Color32 = egui::Color32::from_rgb(0xEB, 0xF2, 0xFF);
pub const TEXT_SECONDARY: egui::Color32 = egui::Color32::from_rgb(0x96, 0xA8, 0xCD);
pub const TEXT_MUTED: egui::Color32 = egui::Color32::from_rgb(0x5A, 0x6E, 0x96);
pub const GREEN: egui::Color32 = egui::Color32::from_rgb(0x2E, 0xCC, 0x71);
pub const ORANGE: egui::Color32 = egui::Color32::from_rgb(0xFF, 0xA5, 0x02);
pub const RED: egui::Color32 = egui::Color32::from_rgb(0xFF, 0x47, 0x57);
pub const STAT_BG: egui::Color32 = egui::Color32::from_rgb(0x0C, 0x12, 0x22);
pub const BTN_BG: egui::Color32 = egui::Color32::from_rgb(0x14, 0x1E, 0x38);
pub const INPUT_BG: egui::Color32 = egui::Color32::from_rgb(0x0C, 0x10, 0x20);

// ─── Service name ────────────────────────────────────────────────────────────

pub const SERVICE_NAME: &str = "PerceptaSIEMAgent";
pub const LINUX_SERVICE_NAME: &str = "percepta-agent";

// ─── Tab enum ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
pub enum Tab {
    Dashboard,
    Setup,
    Health,
    Settings,
    Logs,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Dashboard,
        Tab::Setup,
        Tab::Health,
        Tab::Settings,
        Tab::Logs,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Setup => "Setup",
            Tab::Health => "Health",
            Tab::Settings => "Settings",
            Tab::Logs => "Logs",
        }
    }
}

// ─── Platform message (from tray icon or OS) ─────────────────────────────────

pub enum PlatformMsg {
    ShowWindow,
    Exit,
    StopAgent,
    RestartAgent,
    OpenSettings,
}

// ─── Async GUI events ───────────────────────────────────────────────────────

#[derive(Debug)]
pub enum GuiEvent {
    AutoEnrollFinished(Result<u32, String>),
    EnrollOtkFinished(Result<String, String>),
}

// ─── No-window command helper ────────────────────────────────────────────────

pub trait CommandExtNoWindow {
    fn no_window(&mut self) -> &mut Self;
}

impl CommandExtNoWindow for Command {
    fn no_window(&mut self) -> &mut Self {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            self.creation_flags(CREATE_NO_WINDOW);
        }
        self
    }
}

// ─── Path helpers ────────────────────────────────────────────────────────────

pub fn default_linux_data_base() -> Option<PathBuf> {
    if std::env::var("SUDO_USER").is_ok() {
        return Some(PathBuf::from("/var/lib/percepta-agent"));
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        let t = xdg.trim();
        if !t.is_empty() {
            return Some(PathBuf::from(t).join("percepta-agent"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let t = home.trim();
        if !t.is_empty() {
            return Some(PathBuf::from(t).join(".local/share/percepta-agent"));
        }
    }
    None
}

pub fn default_cert_dir() -> PathBuf {
    crate::default_cert_dir_path()
}

pub fn default_outgoing_dir() -> PathBuf {
    if let Ok(v) = std::env::var("PERCEPTA_OUT") {
        let t = v.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    if cfg!(windows) {
        return PathBuf::from(r"C:\ProgramData\percepta_agent\outgoing");
    }
    default_linux_data_base()
        .map(|b| b.join("outgoing"))
        .unwrap_or_else(|| PathBuf::from("./outgoing"))
}

pub fn gui_log_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\percepta_agent\logs")
    } else {
        default_linux_data_base()
            .map(|b| b.join("logs"))
            .unwrap_or_else(|| PathBuf::from("./logs"))
    }
}

// ─── Network helpers ─────────────────────────────────────────────────────────

pub fn extract_host(server: &str) -> String {
    let s = server.trim();
    if s.is_empty() {
        return String::new();
    }
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let hostport = s.split('/').next().unwrap_or(s).trim();
    config_store::split_host_port(hostport).0
}

pub fn normalize_grpc_addr(server: &str) -> String {
    config_store::normalize_grpc_server_from_enroll_arg(server).unwrap_or_default()
}

pub fn tcp_reachable(host: &str, port: u16, timeout: Duration) -> bool {
    use std::net::ToSocketAddrs;
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    let addr = config_store::format_host_port(host, port);
    let addrs = match addr.to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(_) => return false,
    };
    for a in addrs {
        if TcpStream::connect_timeout(&a, timeout).is_ok() {
            return true;
        }
    }
    false
}

/// Fetch operational stats (events_sent, dedup_saved) from the running agent
/// service via its local /healthz HTTP endpoint. Returns None if the agent is
/// not reachable or the response cannot be parsed.
fn fetch_healthz_stats() -> Option<system_info::AgentHealthSnapshot> {
    use std::io::{Read, Write};
    let addr: std::net::SocketAddr = "127.0.0.1:8081".parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(300)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    stream
        .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .ok()?;
    let mut buf = Vec::with_capacity(4096);
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let body = text.splitn(2, "\r\n\r\n").nth(1)?;
    serde_json::from_str(body.trim()).ok()
}

/// Returns true if a host firewall is detected as active on the current platform.
fn check_firewall_active() -> bool {
    if cfg!(target_os = "linux") {
        for svc in &["ufw", "nftables", "firewalld"] {
            if std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", svc])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                return true;
            }
        }
        false
    } else if cfg!(target_os = "windows") {
        std::process::Command::new("sc")
            .args(["query", "MpsSvc"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
            .unwrap_or(false)
    } else {
        false
    }
}

/// Returns true if a password-quality PAM module or policy is configured.
fn check_password_policy() -> bool {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string("/etc/pam.d/common-password")
            .map(|c| c.contains("pam_pwquality") || c.contains("pam_cracklib"))
            .unwrap_or(false)
    } else if cfg!(target_os = "windows") {
        true // Windows always has password policy via Local Security Policy
    } else {
        false
    }
}

/// Returns true if the kernel audit subsystem (auditd) is active on Linux,
/// or always true on Windows where the Event Log is always running.
fn check_audit_logging() -> bool {
    if cfg!(target_os = "linux") {
        std::process::Command::new("systemctl")
            .args(["is-active", "--quiet", "auditd"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else if cfg!(target_os = "windows") {
        true // Windows Event Log (EventLog service) is always active
    } else {
        false
    }
}

fn is_local_or_private_host(host: &str) -> bool {
    let h = host.trim().trim_matches(&['[', ']'][..]);
    if h.eq_ignore_ascii_case("localhost") || h.ends_with(".local") {
        return true;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            std::net::IpAddr::V6(v6) => {
                let seg0 = v6.segments()[0];
                v6.is_loopback() || (seg0 & 0xfe00) == 0xfc00
            }
        };
    }
    false
}

pub fn resolve_core_binary_path() -> Option<PathBuf> {
    let core_names: Vec<&str> = if cfg!(windows) {
        vec!["percepta-agent.exe", "percepta-agent-core.exe"]
    } else {
        vec!["percepta-agent", "percepta-agent-core"]
    };
    if let Ok(cur) = std::env::current_exe() {
        if let Some(dir) = cur.parent() {
            for name in &core_names {
                let p = dir.join(name);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    for name in &core_names {
        if let Ok(p) = which::which(name) {
            return Some(p);
        }
    }
    None
}

fn read_agent_id_for_display(cert_dir: &Path) -> Option<String> {
    let agent_id_txt = cert_dir.join("agent_id.txt");
    if let Ok(s) = std::fs::read_to_string(&agent_id_txt) {
        let v = s.trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }
    let identity_json = cert_dir.join("identity.json");
    if let Ok(bytes) = std::fs::read(&identity_json) {
        if let Ok(ident) = serde_json::from_slice::<DeviceIdentity>(&bytes) {
            let v = ident.agent_id.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

// ─── Platform service abstraction ────────────────────────────────────────────

pub fn platform_service_query() -> Option<bool> {
    #[cfg(windows)]
    {
        crate::gui_windows::service_query()
    }
    #[cfg(target_os = "linux")]
    {
        crate::gui_linux::service_query()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        None
    }
}

pub fn platform_service_start() -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::gui_windows::service_start()
    }
    #[cfg(target_os = "linux")]
    {
        crate::gui_linux::service_start()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("Unsupported platform".to_string())
    }
}

pub fn platform_service_stop() -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::gui_windows::service_stop()
    }
    #[cfg(target_os = "linux")]
    {
        crate::gui_linux::service_stop()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("Unsupported platform".to_string())
    }
}

pub fn platform_service_restart() -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::gui_windows::service_restart()
    }
    #[cfg(target_os = "linux")]
    {
        crate::gui_linux::service_restart()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("Unsupported platform".to_string())
    }
}

pub fn platform_service_install(server: &str) -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::gui_windows::service_install(server)
    }
    #[cfg(target_os = "linux")]
    {
        crate::gui_linux::service_install(server)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = server;
        Err("Unsupported platform".to_string())
    }
}

pub fn platform_service_uninstall() -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::gui_windows::service_uninstall()
    }
    #[cfg(target_os = "linux")]
    {
        crate::gui_linux::service_uninstall()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        Err("Unsupported platform".to_string())
    }
}

pub fn platform_service_set_autostart(enabled: bool) -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::gui_windows::service_set_autostart(enabled)
    }
    #[cfg(target_os = "linux")]
    {
        crate::gui_linux::service_set_autostart(enabled)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = enabled;
        Err("Unsupported platform".to_string())
    }
}

pub fn platform_supports_tray() -> bool {
    #[cfg(windows)]
    {
        crate::gui_windows::tray_available()
    }
    #[cfg(target_os = "linux")]
    {
        crate::gui_linux::tray_available()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        false
    }
}

// ─── Reusable UI helpers ────────────────────────────────────────────────────

pub fn card(ui: &mut egui::Ui, light: bool, add_contents: impl FnOnce(&mut egui::Ui)) {
    let (fill, stroke_default) = if light {
        (egui::Color32::WHITE, egui::Color32::from_rgb(0xD0, 0xD8, 0xE4))
    } else {
        (BG_CARD, BORDER_CARD)
    };
    let frame_resp = egui::Frame::none()
        .fill(fill)
        .rounding(14.0)
        .inner_margin(egui::Margin::symmetric(18.0, 16.0))
        .stroke(egui::Stroke::new(1.0, stroke_default))
        .show(ui, add_contents);
    // Hover accent border (like anti-gravity card:hover)
    if frame_resp.response.hovered() {
        let accent_border = egui::Color32::from_rgba_unmultiplied(0, 212, 255, 51);
        ui.painter().rect_stroke(frame_resp.response.rect, 14.0, egui::Stroke::new(1.0, accent_border));
    }
}

pub fn card_header(ui: &mut egui::Ui, title: &str, badge: &str, badge_color: egui::Color32) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(title).size(15.0).strong().color(TEXT_PRIMARY));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if !badge.is_empty() {
                ui.label(egui::RichText::new(badge).size(11.0).strong().color(badge_color));
            }
        });
    });
    ui.add_space(4.0);
}

pub fn stat_tile(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32, light: bool) {
    let (fill, stroke) = if light {
        (egui::Color32::from_rgb(0xEC, 0xEF, 0xF5), egui::Color32::from_rgb(0xD0, 0xD8, 0xE4))
    } else {
        (STAT_BG, egui::Color32::from_rgb(0x1E, 0x2E, 0x50))
    };
    egui::Frame::none()
        .fill(fill)
        .rounding(10.0)
        .stroke(egui::Stroke::new(1.0, stroke))
        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).size(11.0).color(TEXT_MUTED));
            ui.add_space(2.0);
            ui.label(egui::RichText::new(value).size(18.0).strong().color(color));
        });
}

pub fn pill(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::none()
        .fill(egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 38))
        .rounding(999.0)
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 76),
        ))
        .inner_margin(egui::Margin::symmetric(14.0, 4.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).size(12.0).strong().color(color));
        });
}

pub fn check_row(ui: &mut egui::Ui, pass: bool, label: &str) {
    ui.horizontal(|ui| {
        if pass {
            ui.colored_label(GREEN, "✓");
        } else {
            ui.colored_label(RED, "✗");
        }
        ui.label(egui::RichText::new(label).size(13.0).color(TEXT_PRIMARY));
    });
    ui.add_space(2.0);
}

pub fn toggle_row(ui: &mut egui::Ui, val: &mut bool, label: &str) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let desired = egui::vec2(44.0, 24.0);
        let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::click());
        if response.clicked() {
            *val = !*val;
            changed = true;
        }
        let anim = ui.ctx().animate_bool(response.id, *val);
        let track_color = egui::Color32::from_rgba_unmultiplied(
            0,
            (0x2C as f32 + anim * (0xD4 as f32 - 0x2C as f32)) as u8,
            (0x34 as f32 + anim * (0xFF as f32 - 0x34 as f32)) as u8,
            (0x48 as f32 + anim * (0x80 as f32 - 0x48 as f32)) as u8,
        );
        ui.painter().rect_filled(rect, 12.0, track_color);
        let knob_x = rect.left() + 3.0 + anim * 20.0;
        let knob_center = egui::pos2(knob_x + 9.0, rect.center().y);
        ui.painter()
            .circle_filled(knob_center, 9.0, egui::Color32::from_rgb(0xE6, 0xEE, 0xFF));
        ui.add_space(4.0);
        ui.label(egui::RichText::new(label).size(13.0).color(TEXT_SECONDARY));
    });
    ui.add_space(4.0);
    changed
}

pub fn accent_btn(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let btn = egui::Button::new(egui::RichText::new(text).size(13.0).strong().color(ACCENT))
        .fill(egui::Color32::from_rgba_unmultiplied(0, 212, 255, 38))
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(0, 212, 255, 89),
        ))
        .rounding(10.0);
    ui.add(btn)
}

pub fn small_btn(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let btn = egui::Button::new(egui::RichText::new(text).size(12.0).color(TEXT_PRIMARY))
        .fill(BTN_BG)
        .stroke(egui::Stroke::new(1.0, BORDER_CARD))
        .rounding(10.0);
    ui.add(btn)
}

pub fn separator(ui: &mut egui::Ui) {
    let rect = ui.available_rect_before_wrap();
    let y = rect.top();
    ui.painter().line_segment(
        [egui::pos2(rect.left(), y), egui::pos2(rect.right(), y)],
        egui::Stroke::new(1.0, BORDER_SUBTLE),
    );
    ui.add_space(2.0);
}

// ─── App icon ───────────────────────────────────────────────────────────────

pub fn build_icon() -> egui::IconData {
    const S: usize = 32;
    let mut px = vec![0u8; S * S * 4];
    let cx = (S / 2) as i32;
    let cy = (S / 2) as i32;
    for y in 0..S {
        for x in 0..S {
            let dx = x as i32 - cx;
            let dy = y as i32 - cy;
            let in_shield = dx * dx * 4 + dy * dy * 3 < 400
                || (dx.abs() < 5 && dy > 4 && dy < 13 - dx.abs() / 2);
            if in_shield {
                let i = (y * S + x) * 4;
                px[i] = 0x00;
                px[i + 1] = 0xd4;
                px[i + 2] = 0xff;
                px[i + 3] = 0xff;
            }
        }
    }
    egui::IconData {
        rgba: px,
        width: S as u32,
        height: S as u32,
    }
}

// ─── Main app struct ────────────────────────────────────────────────────────

pub struct PerceptaAgentApp {
    pub platform_rx: mpsc::Receiver<PlatformMsg>,

    active_tab: Tab,
    server_input: String,
    otk_input: String,
    enrollment_in_progress: bool,
    status: String,

    // Discovery
    discovery_sender: mpsc::Sender<Option<String>>,
    discovery_receiver: mpsc::Receiver<Option<String>>,
    discovery_in_progress: bool,

    // Async event channel
    event_sender: mpsc::Sender<GuiEvent>,
    event_receiver: mpsc::Receiver<GuiEvent>,

    // Service/process state
    service_running: Option<bool>,
    core_pid: Option<u32>,
    last_service_refresh: Instant,

    // Stats
    events_sent: u64,
    buffer_queue: u32,
    dedup_saved: u64,
    uptime_start: Instant,
    last_poll: Instant,

    // System info
    cpu_usage: f32,
    mem_mb: u64,
    agent_id: String,
    hostname_str: String,
    platform_str: String,
    cert_expiry: String,
    pid: u32,

    // Settings
    auto_restart: bool,
    auto_reconnect: bool,
    event_dedup: bool,
    debug_logging: bool,
    minimize_to_tray: bool,
    light_theme: bool,
    compact_layout: bool,
    reduce_motion: bool,

    // Self-check
    self_check: Vec<(String, bool)>,
    last_self_check: Instant,
    health_snapshot: Option<system_info::AgentHealthSnapshot>,

    // Logs
    log_lines: Vec<(String, &'static str, String)>,
    logs_text: String,
    last_log_refresh: Instant,
    #[allow(dead_code)]
    show_logs: bool,

    // Toast
    toast: Option<(String, Instant)>,

    // Config
    #[allow(dead_code)]
    config_path: PathBuf,

    // Auto-start check done flag
    auto_restart_checked: bool,

    // Force exit
    force_exit: bool,

    // Track close-to-tray: second X click within 2 s actually quits
    last_close_attempt: Option<Instant>,
}

/// Read the tail of a log file, capped at `max_bytes`.
///
/// If the file is larger than `max_bytes`, the first bytes are skipped so only
/// the most recent content is returned. This prevents OOM crashes on agents with
/// large, unrotated log files.
fn read_log_tail(path: &std::path::Path, max_bytes: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len > max_bytes {
        // Skip to the last `max_bytes` of the file.
        file.seek(SeekFrom::Start(len - max_bytes))?;
        // Advance past any incomplete UTF-8 line boundary.
        let mut skip_buf = [0u8; 256];
        let _ = file.read(&mut skip_buf);
        // Find first newline to start on a clean line.
        if let Some(nl) = skip_buf.iter().position(|&b| b == b'\n') {
            let rewind = skip_buf.len() - nl - 1;
            let cur = file.seek(SeekFrom::Current(0))?;
            file.seek(SeekFrom::Start(cur.saturating_sub(rewind as u64)))?;
        }
    }
    let mut buf = String::new();
    file.read_to_string(&mut buf)?;
    Ok(buf)
}

impl PerceptaAgentApp {
    pub fn new(platform_rx: mpsc::Receiver<PlatformMsg>) -> Self {
        let cert_dir = default_cert_dir();
        let enrolled = cert_dir.join("agent_cert.pem").exists();

        let agent_id = read_agent_id_for_display(&cert_dir).unwrap_or_else(|| "—".into());

        let cert_expiry = if enrolled {
            std::fs::read(cert_dir.join("agent_cert.pem"))
                .ok()
                .and_then(|pem| openssl::x509::X509::from_pem(&pem).ok())
                .map(|cert| cert.not_after().to_string())
                .unwrap_or_else(|| "valid".into())
        } else {
            "—".into()
        };

        let hostname_str = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".into());

        let platform_str = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);

        let server_input = config_store::load_server_addr().unwrap_or_default();

        // Load saved UI config
        let ui_cfg = config_store::load_config().unwrap_or_default();

        let (disc_tx, disc_rx) = mpsc::channel();
        let (evt_tx, evt_rx) = mpsc::channel();

        let mut app = Self {
            platform_rx,
            active_tab: Tab::Dashboard,
            server_input,
            otk_input: String::new(),
            enrollment_in_progress: false,
            status: "Ready".into(),

            discovery_sender: disc_tx,
            discovery_receiver: disc_rx,
            discovery_in_progress: false,

            event_sender: evt_tx,
            event_receiver: evt_rx,

            service_running: None,
            core_pid: None,
            last_service_refresh: Instant::now() - Duration::from_secs(10),

            events_sent: 0,
            buffer_queue: 0,
            dedup_saved: 0,
            uptime_start: Instant::now(),
            last_poll: Instant::now(),

            cpu_usage: 0.0,
            mem_mb: 0,
            agent_id,
            hostname_str,
            platform_str,
            cert_expiry,
            pid: std::process::id(),

            auto_restart: ui_cfg.auto_restart,
            auto_reconnect: true,
            event_dedup: true,
            debug_logging: ui_cfg.debug,
            minimize_to_tray: ui_cfg.minimize_to_tray,
            light_theme: ui_cfg.use_light_theme,
            compact_layout: ui_cfg.ui_compact,
            reduce_motion: ui_cfg.reduce_motion,

            self_check: Vec::new(),
            last_self_check: Instant::now() - Duration::from_secs(10),
            health_snapshot: None,

            log_lines: vec![(
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                "INFO",
                "Agent GUI started".into(),
            )],
            logs_text: String::new(),
            last_log_refresh: Instant::now(),
            show_logs: false,

            toast: None,
            config_path: config_store::default_config_path(),
            auto_restart_checked: false,
            force_exit: false,
            last_close_attempt: None,
        };

        // Auto-read bundled OTK/server config from files next to exe
        if let Ok(cur) = std::env::current_exe() {
            if let Some(dir) = cur.parent() {
                if let Ok(otk_contents) = std::fs::read_to_string(dir.join("otk.txt")) {
                    app.otk_input = otk_contents.trim().to_string();
                }
                if let Ok(cfg_contents) = std::fs::read_to_string(dir.join("server-config.txt")) {
                    for line in cfg_contents.lines() {
                        if let Some(val) = line.strip_prefix("grpc_server=") {
                            app.server_input = val.trim().to_string();
                        }
                    }
                }
                if !app.otk_input.is_empty() && !app.server_input.is_empty() {
                    app.status = "Ready: review server and click Enroll with OTK".into();
                }
            }
        }

        app
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    fn save_config(&self) {
        let cfg = config_store::AgentUiConfig {
            server: self.server_input.clone(),
            debug: self.debug_logging,
            auto_restart: self.auto_restart,
            minimize_to_tray: self.minimize_to_tray,
            ui_compact: self.compact_layout,
            reduce_motion: self.reduce_motion,
            use_light_theme: self.light_theme,
        };
        let _ = config_store::save_config(&cfg);
    }

    fn is_agent_running(&self) -> bool {
        self.service_running.unwrap_or(false) || self.core_pid.is_some()
    }

    fn uptime_str(&self) -> String {
        let secs = self.uptime_start.elapsed().as_secs();
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        let s = secs % 60;
        if h > 0 {
            format!("{h}h {m:02}m {s:02}s")
        } else {
            format!("{m}m {s:02}s")
        }
    }

    // ── Service management ─────────────────────────────────────────────────

    fn refresh_service_state(&mut self) {
        // Reap exited direct-launch processes on Linux
        #[cfg(target_os = "linux")]
        if let Some(pid) = self.core_pid {
            if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                self.core_pid = None;
            }
        }
        if self.last_service_refresh.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.last_service_refresh = Instant::now();
        self.service_running = platform_service_query();
    }

    fn refresh_stats(&mut self) {
        if let Ok(load) = sys_info::loadavg() {
            self.cpu_usage = load.one as f32;
        }
        if let Ok(mem) = sys_info::mem_info() {
            self.mem_mb = (mem.total.saturating_sub(mem.avail)) / 1024;
        }
        if self.is_agent_running() {
            if let Some(snap) = fetch_healthz_stats() {
                self.events_sent = snap.events_sent;
                self.dedup_saved = snap.dedup_saved;
            }
        }
        self.last_poll = Instant::now();
    }

    fn enable_agent(&mut self) {
        self.save_config();
        if self.auto_restart {
            let _ = platform_service_set_autostart(true);
        }
        if !self.is_agent_running() {
            // Try platform service first, fallback to direct process
            if self.auto_restart && self.service_running.is_none() {
                if let Err(e) = platform_service_install(&self.server_input) {
                    self.status = format!("Service install failed: {}", e.trim());
                }
            }
            match platform_service_start() {
                Ok(_) => self.status = "Agent service started".into(),
                Err(_) => self.start_agent_core(),
            }
        } else {
            self.status = "Agent already running".into();
        }
        self.last_service_refresh = Instant::now() - Duration::from_secs(10);
    }

    fn disable_agent(&mut self) {
        self.status = "Stopping agent...".into();
        self.service_running = None;
        let _ = platform_service_stop();
        self.stop_agent_core();
        let _ = platform_service_set_autostart(false);
        self.last_service_refresh = Instant::now() - Duration::from_secs(10);
    }

    fn restart_agent(&mut self) {
        self.status = "Restarting agent...".into();
        match platform_service_restart() {
            Ok(_) => self.status = "Agent service restarted".into(),
            Err(_) => {
                self.stop_agent_core();
                self.start_agent_core();
            }
        }
        self.last_service_refresh = Instant::now() - Duration::from_secs(10);
    }

    fn start_agent_core(&mut self) {
        if self.server_input.is_empty() {
            self.status = "Server address is empty".into();
            return;
        }
        let grpc_addr = normalize_grpc_addr(&self.server_input);
        if grpc_addr.is_empty() {
            self.status = "Invalid server address".into();
            return;
        }
        if let Some(path) = resolve_core_binary_path() {
            let mut cmd = Command::new(path);
            cmd.no_window();
            #[allow(unused_unsafe)]
            unsafe {
                cmd.env("PERCEPTA_SERVER", &grpc_addr);
            }
            if let Ok(child) = cmd.spawn() {
                self.core_pid = Some(child.id());
                self.status = format!("Agent started (PID: {})", child.id());
            } else {
                self.status = "Failed to start agent process".into();
            }
        } else {
            self.status = "Agent executable not found".into();
        }
    }

    fn stop_agent_core(&mut self) {
        if let Some(pid) = self.core_pid.take() {
            #[cfg(target_os = "windows")]
            {
                let _ = Command::new("taskkill")
                    .no_window()
                    .arg("/F")
                    .arg("/PID")
                    .arg(pid.to_string())
                    .output();
            }
            #[cfg(not(target_os = "windows"))]
            {
                unsafe { libc::kill(pid as i32, libc::SIGTERM); }
            }
        }
    }

    // ── Enrollment ─────────────────────────────────────────────────────────

    fn run_auto_enroll_and_start(&mut self) {
        if self.enrollment_in_progress {
            return;
        }
        if self.server_input.is_empty() {
            self.status = "Server address is empty".into();
            return;
        }
        self.enrollment_in_progress = true;
        self.status = "Auto-enrolling and starting agent...".into();

        let server = self.server_input.clone();
        let event_sender = self.event_sender.clone();
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    let _ = event_sender.send(GuiEvent::AutoEnrollFinished(Err(format!("{e}"))));
                    return;
                }
            };
            let res: anyhow::Result<u32> = rt.block_on(async move {
                let host = extract_host(&server);
                if host.trim().is_empty() {
                    return Err(anyhow::anyhow!("Server address is empty"));
                }

                let allow_bootstrap = std::env::var("PERCEPTA_ALLOW_CA_BOOTSTRAP")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if !allow_bootstrap && !is_local_or_private_host(&host) {
                    return Err(anyhow::anyhow!(
                        "Auto-enroll blocked for non-local hosts. Set PERCEPTA_ALLOW_CA_BOOTSTRAP=1."
                    ));
                }

                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .build()?;

                let health = system_info::collect_agent_health_snapshot();
                let register_body = serde_json::json!({
                    "device_info": {
                        "hostname": health.hostname,
                        "os": health.os_name,
                        "ip": health.primary_ip,
                    },
                    "identity": {
                        "primary_mac": health.primary_mac,
                        "first_user": health.current_user,
                    },
                    "enrichment": {
                        "os_version": health.os_version,
                        "cpu_cores": health.cpu_cores,
                        "total_memory_mb": health.total_memory_mb,
                        "agent_version": env!("CARGO_PKG_VERSION"),
                        "platform": health.platform,
                    }
                });

                let register_url_https = format!("https://{}/api/enroll/auto-register", host);
                let register_url_http = format!("http://{}/api/enroll/auto-register", host);

                let register_resp = match client.post(&register_url_https).json(&register_body).send().await {
                    Ok(resp) if resp.status().is_success() => resp,
                    _ => client.post(&register_url_http).json(&register_body).send().await?,
                };

                let (otk, ca_pem, server_agent_id) = if register_resp.status().is_success() {
                    let body: serde_json::Value = register_resp.json().await?;
                    let otk = body.get("otk").and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("Missing 'otk'"))?.to_string();
                    let ca_pem = body.get("ca_cert_pem").and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("Missing 'ca_cert_pem'"))?.to_string();
                    let server_agent_id = body.get("agent_id").and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("Missing 'agent_id'"))?.to_string();
                    (otk, ca_pem, server_agent_id)
                } else {
                    let ca_url_https = format!("https://{}/api/ca_cert", host);
                    let ca_url_http = format!("http://{}/api/ca_cert", host);
                    let ca_pem = match client.get(&ca_url_https).send().await {
                        Ok(resp) if resp.status().is_success() => resp.text().await?,
                        _ => client.get(&ca_url_http).send().await?.text().await?,
                    };
                    let otk = if let Some(embedded) = embedded_assets::embedded_otk() {
                        embedded.to_string()
                    } else {
                        return Err(anyhow::anyhow!("Auto-register not available. Provide OTK manually."));
                    };
                    let local_agent_id = match std::env::var("PERCEPTA_AGENT_ID") {
                        Ok(id) if !id.trim().is_empty() => id,
                        _ => identity::load_or_create(&default_cert_dir()).await?.agent_id,
                    };
                    (otk, ca_pem, local_agent_id)
                };

                let cert_dir = default_cert_dir();
                tokio::fs::create_dir_all(&cert_dir).await?;
                // Log the CA fingerprint so an admin can verify it out-of-band before
                // trusting the TOFU-bootstrapped CA (MITM protection during initial enroll).
                if let Ok(ca_x509) = openssl::x509::X509::from_pem(ca_pem.as_bytes()) {
                    if let Ok(fp_bytes) = ca_x509.digest(openssl::hash::MessageDigest::sha256()) {
                        let fp = hex::encode(fp_bytes.as_ref());
                        tracing::warn!(
                            "⚠️  TOFU CA bootstrap (auto-enroll): SHA-256={} — verify this on your SIEM server.",
                            fp
                        );
                    }
                }
                tokio::fs::write(cert_dir.join("ca_cert.pem"), ca_pem.as_bytes()).await?;

                let agent_id = match std::env::var("PERCEPTA_AGENT_ID") {
                    Ok(id) if !id.trim().is_empty() => id,
                    _ => identity::force_agent_id(&cert_dir, &server_agent_id).await?.agent_id,
                };

                let enroll_url = format!("https://{}", host);
                tls::enroll_with_otk(&enroll_url, &otk, &agent_id, &cert_dir).await?;

                let grpc_addr = normalize_grpc_addr(&server);
                if let Some(grpc) = config_store::normalize_grpc_server_from_enroll_arg(&grpc_addr) {
                    let _ = config_store::set_server_addr(&grpc);
                }

                let core_exe = resolve_core_binary_path()
                    .ok_or_else(|| anyhow::anyhow!("Agent executable not found"))?;
                let mut start_cmd = Command::new(&core_exe);
                start_cmd.no_window();
                #[allow(unused_unsafe)]
                unsafe {
                    start_cmd.env("PERCEPTA_SERVER", &grpc_addr);
                }
                let child = start_cmd.spawn()?;
                Ok(child.id())
            });

            let event = match res {
                Ok(pid) => GuiEvent::AutoEnrollFinished(Ok(pid)),
                Err(e) => GuiEvent::AutoEnrollFinished(Err(format!("{e:#}"))),
            };
            let _ = event_sender.send(event);
        });
    }

    fn run_enroll_with_otk(&mut self) {
        if self.enrollment_in_progress || self.server_input.is_empty() || self.otk_input.is_empty()
        {
            self.status = "Server address and OTK are required".into();
            return;
        }
        self.enrollment_in_progress = true;
        self.status = "Enrolling with OTK...".into();

        let server = self.server_input.clone();
        let otk = self.otk_input.clone();
        let event_sender = self.event_sender.clone();

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(e) => {
                    let _ = event_sender.send(GuiEvent::EnrollOtkFinished(Err(format!("{e}"))));
                    return;
                }
            };
            let result: Result<String, String> = rt.block_on(async {
                let host = extract_host(&server);
                if host.trim().is_empty() {
                    return Err("Server address is empty".into());
                }
                let cert_dir = default_cert_dir();
                tokio::fs::create_dir_all(&cert_dir)
                    .await.map_err(|e| format!("{e}"))?;

                let ca_path = cert_dir.join("ca_cert.pem");
                if !ca_path.exists() {
                    let client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .build().map_err(|e| format!("{e}"))?;
                    let ca_url = format!("https://{}/api/ca_cert", host);
                    let ca_pem = client.get(&ca_url).send().await
                        .map_err(|e| format!("Failed to fetch CA cert: {e}"))?
                        .text().await.map_err(|e| format!("{e}"))?;
                    // Log the CA fingerprint for TOFU verification before writing.
                    if let Ok(ca_x509) = openssl::x509::X509::from_pem(ca_pem.as_bytes()) {
                        if let Ok(fp_bytes) = ca_x509.digest(openssl::hash::MessageDigest::sha256()) {
                            let fp = hex::encode(fp_bytes.as_ref());
                            tracing::warn!(
                                "⚠️  TOFU CA bootstrap (OTK enroll): SHA-256={} — verify on your SIEM server.",
                                fp
                            );
                        }
                    }
                    tokio::fs::write(&ca_path, ca_pem.as_bytes())
                        .await.map_err(|e| format!("{e}"))?;
                }

                let agent_id = match std::env::var("PERCEPTA_AGENT_ID") {
                    Ok(id) if !id.trim().is_empty() => id,
                    _ => identity::load_or_create(&cert_dir).await.map_err(|e| format!("{e}"))?.agent_id,
                };

                let enroll_url = format!("https://{}", host);
                tls::enroll_with_otk(&enroll_url, &otk, &agent_id, &cert_dir)
                    .await.map_err(|e| format!("{e:#}"))?;

                let grpc_addr = normalize_grpc_addr(&server);
                if let Some(grpc) = config_store::normalize_grpc_server_from_enroll_arg(&grpc_addr)
                {
                    let _ = config_store::set_server_addr(&grpc);
                }
                Ok("Enrollment successful".into())
            });
            let _ = event_sender.send(GuiEvent::EnrollOtkFinished(result));
        });
    }

    fn run_request_renewal(&mut self) {
        if self.server_input.is_empty() {
            self.status = "Server address is empty".into();
            return;
        }
        let server_addr = if self.server_input.starts_with("https://") {
            self.server_input.clone()
        } else if self.server_input.starts_with("http://") {
            self.server_input.replacen("http://", "https://", 1)
        } else {
            let host = self.server_input.split(':').next().unwrap_or(&self.server_input);
            format!("https://{}:8080", host)
        };
        self.status = "Renewal requested; waiting for approval...".into();

        std::thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(_) => return,
            };
            let _ = rt.block_on(async move {
                let cert_dir = default_cert_dir();
                let _ = tokio::fs::create_dir_all(&cert_dir).await;
                let agent_id = match std::env::var("PERCEPTA_AGENT_ID") {
                    Ok(id) if !id.trim().is_empty() => id,
                    _ => identity::load_or_create(&cert_dir).await?.agent_id,
                };
                let pickup_token = tls::request_certificate_renewal(&server_addr, &agent_id, &cert_dir).await?;
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10 * 60);
                loop {
                    if tokio::time::Instant::now() > deadline {
                        break;
                    }
                    match tls::pickup_certificate_renewal(&server_addr, &cert_dir, &pickup_token).await {
                        Ok(true) => break,
                        Ok(false) => tokio::time::sleep(std::time::Duration::from_secs(5)).await,
                        Err(_) => break,
                    }
                }
                Ok::<(), anyhow::Error>(())
            });
        });
    }

    fn discover_server_start(&mut self) {
        if self.discovery_in_progress {
            return;
        }
        self.discovery_in_progress = true;
        self.status = "Discovering server...".into();
        let sender = self.discovery_sender.clone();
        std::thread::spawn(move || {
            if let Ok(server) = std::env::var("PERCEPTA_SERVER") {
                let s = server.trim().to_string();
                if !s.is_empty() {
                    let _ = sender.send(Some(s));
                    return;
                }
            }
            let service_type = "_percepta-siem._tcp.local.";
            if let Ok(mdns) = mdns_sd::ServiceDaemon::new() {
                if let Ok(receiver) = mdns.browse(service_type) {
                    let start_time = Instant::now();
                    while start_time.elapsed() < Duration::from_secs(5) {
                        if let Ok(mdns_sd::ServiceEvent::ServiceResolved(info)) =
                            receiver.recv_timeout(Duration::from_secs(1))
                        {
                            if let Some(addr) = info.get_addresses().iter().next() {
                                let server_addr =
                                    config_store::format_host_port(&addr.to_string(), info.get_port());
                                let _ = mdns.stop_browse(service_type);
                                let _ = mdns.shutdown();
                                std::thread::sleep(Duration::from_millis(1200));
                                let _ = sender.send(Some(server_addr));
                                return;
                            }
                        }
                    }
                    let _ = mdns.stop_browse(service_type);
                    let _ = mdns.shutdown();
                }
            }
            // DNS fallback
            use std::net::ToSocketAddrs;
            if let Ok(addrs) = ("percepta-server", 50051u16).to_socket_addrs() {
                let addrs: Vec<_> = addrs.collect();
                if let Some(addr) = addrs.first() {
                    let _ = sender.send(Some(addr.to_string()));
                    return;
                }
            }
            let _ = sender.send(None);
        });
    }

    // ── Self-check ─────────────────────────────────────────────────────────

    fn run_self_check(&mut self) {
        let mut items: Vec<(String, bool)> = Vec::new();
        let server = self.server_input.trim().to_string();
        items.push(("Server address set".into(), !server.is_empty()));

        let grpc_addr = normalize_grpc_addr(&server);
        items.push(("gRPC address valid".into(), !grpc_addr.is_empty()));
        if !grpc_addr.is_empty() && grpc_addr != server {
            self.server_input = grpc_addr.clone();
            self.save_config();
        }

        let cert_dir = default_cert_dir();
        let cert_dir_ok = cert_dir.exists() || std::fs::create_dir_all(&cert_dir).is_ok();
        items.push((format!("Cert dir exists ({})", cert_dir.display()), cert_dir_ok));

        let outgoing_dir = default_outgoing_dir();
        let outgoing_ok = outgoing_dir.exists() || std::fs::create_dir_all(&outgoing_dir).is_ok();
        items.push((format!("Outgoing dir exists ({})", outgoing_dir.display()), outgoing_ok));

        items.push(("Core agent binary found".into(), resolve_core_binary_path().is_some()));

        let cert_enrolled = cert_dir.join("agent_cert.pem").exists();
        let ca_pinned = cert_dir.join("ca_cert.pem").exists();
        items.push((if cert_enrolled { "Agent enrolled (cert present)".into() } else { "Agent NOT enrolled".into() }, cert_enrolled));
        items.push((if ca_pinned { "CA cert pinned (TOFU)".into() } else { "CA cert missing".into() }, ca_pinned));

        let host = extract_host(&server);
        if !host.is_empty() {
            let https_ok = tcp_reachable(&host, 8080, Duration::from_millis(400));
            items.push((format!("HTTPS portal reachable ({}:8080)", host), https_ok));
            let grpc_ok = tcp_reachable(&host, 50051, Duration::from_millis(400));
            items.push((format!("gRPC reachable ({}:50051)", host), grpc_ok));
        }

        self.self_check = items;
        self.health_snapshot = Some(system_info::collect_agent_health_snapshot());
        self.last_self_check = Instant::now();
    }

    fn open_logs(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if let Ok(output) = Command::new("journalctl")
                .no_window()
                .args(["-u", LINUX_SERVICE_NAME, "--no-pager", "-n", "200"])
                .output()
            {
                if output.status.success() {
                    let content = String::from_utf8_lossy(&output.stdout).to_string();
                    if !content.trim().is_empty() {
                        self.logs_text = content;
                        return;
                    }
                }
            }
        }
        let mut candidates = vec![];
        if cfg!(windows) {
            candidates.push(gui_log_dir().join("gui-startup.log"));
            candidates.push(PathBuf::from(r"C:\ProgramData\percepta_agent\outgoing\agent.log"));
            candidates.push(PathBuf::from(r"C:\ProgramData\percepta_agent\outgoing\latest.log"));
        } else {
            let out = default_outgoing_dir();
            candidates.push(out.join("agent.log"));
            candidates.push(out.join("latest.log"));
        }
        for p in candidates {
            if p.exists() {
                if let Ok(content) = read_log_tail(&p, 5 * 1024 * 1024) {
                    self.logs_text = content;
                    return;
                }
            }
        }
        self.logs_text = "No log file found.".into();
    }

    // ── Tab rendering ──────────────────────────────────────────────────────

    fn tab_dashboard(&mut self, ui: &mut egui::Ui) {
        let light = self.light_theme;
        let running = self.is_agent_running();

        ui.columns(2, |cols| {
            // Left: Connection card
            card(&mut cols[0], light, |ui| {
                card_header(ui, "Connection", if running { "Connected" } else { "Disconnected" },
                    if running { GREEN } else { ORANGE });
                ui.add_space(4.0);
                ui.label(egui::RichText::new("Server Address (gRPC)").size(12.0).color(TEXT_SECONDARY));
                ui.add_space(4.0);
                let te = egui::TextEdit::singleline(&mut self.server_input)
                    .hint_text("hostname:50051")
                    .desired_width(ui.available_width())
                    .text_color(TEXT_PRIMARY);
                let re = ui.add(te);
                if re.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    let addr = self.server_input.trim().to_string();
                    if !addr.is_empty() {
                        let _ = config_store::set_server_addr(&addr);
                    }
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if accent_btn(ui, if running { "⏹ Stop" } else { "▶ Start" }).clicked() {
                        if running {
                            self.disable_agent();
                        } else {
                            self.enable_agent();
                        }
                    }
                    if ui.button("↻ Restart").clicked() {
                        self.restart_agent();
                    }
                    if small_btn(ui, "🔍 Discover").clicked() {
                        self.discover_server_start();
                    }
                });
            });

            // Right: Stats card
            card(&mut cols[1], light, |ui| {
                card_header(ui, "Stats", "LIVE", ACCENT);
                ui.add_space(6.0);
                ui.columns(2, |sc| {
                    stat_tile(&mut sc[0], "Uptime", &self.uptime_str(), ACCENT, light);
                    stat_tile(&mut sc[1], "Events Sent", &self.events_sent.to_string(), GREEN, light);
                });
                ui.add_space(6.0);
                ui.columns(2, |sc| {
                    stat_tile(&mut sc[0], "Buffer Queue", &self.buffer_queue.to_string(), TEXT_PRIMARY, light);
                    stat_tile(&mut sc[1], "Dedup Saved", &self.dedup_saved.to_string(), ACCENT, light);
                });
            });
        });

        ui.add_space(10.0);

        // Enrollment info card
        card(ui, light, |ui| {
            card_header(ui, "Enrollment", "IDENTITY", ACCENT);
            ui.add_space(4.0);
            ui.columns(2, |cols| {
                cols[0].label(egui::RichText::new("Agent ID:").size(13.0).color(TEXT_SECONDARY));
                cols[0].label(egui::RichText::new(&self.agent_id).size(13.0).color(TEXT_PRIMARY));
                cols[0].add_space(4.0);
                cols[0].label(egui::RichText::new("Hostname:").size(13.0).color(TEXT_SECONDARY));
                cols[0].label(egui::RichText::new(&self.hostname_str).size(13.0).color(TEXT_PRIMARY));
                cols[0].add_space(4.0);
                cols[0].label(egui::RichText::new("Platform:").size(13.0).color(TEXT_SECONDARY));
                cols[0].label(egui::RichText::new(&self.platform_str).size(13.0).color(TEXT_PRIMARY));

                let cert_dir = default_cert_dir();
                let enrolled = cert_dir.join("agent_cert.pem").exists();
                cols[1].label(egui::RichText::new("Certificate:").size(13.0).color(TEXT_SECONDARY));
                if enrolled {
                    cols[1].colored_label(GREEN, format!("✓ Valid — expires {}", self.cert_expiry));
                } else {
                    cols[1].colored_label(ORANGE, "⚠ Not enrolled");
                }
                cols[1].add_space(4.0);
                cols[1].label(egui::RichText::new("CA Pinned:").size(13.0).color(TEXT_SECONDARY));
                if cert_dir.join("ca_cert.pem").exists() {
                    cols[1].colored_label(GREEN, "Yes (TOFU)");
                } else {
                    cols[1].colored_label(TEXT_MUTED, "No");
                }
            });
        });
    }

    fn tab_setup(&mut self, ui: &mut egui::Ui) {
        let light = self.light_theme;

        card(ui, light, |ui| {
            card_header(ui, "Initial Enrollment", "SETUP", ACCENT);
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Server Address").size(12.0).color(TEXT_SECONDARY));
            ui.add_space(4.0);
            ui.add(egui::TextEdit::singleline(&mut self.server_input)
                .hint_text("server:8080")
                .desired_width(ui.available_width())
                .text_color(TEXT_PRIMARY));
            ui.add_space(8.0);
            ui.label(egui::RichText::new("One-Time Key (OTK)").size(12.0).color(TEXT_SECONDARY));
            ui.add_space(4.0);
            ui.add(egui::TextEdit::singleline(&mut self.otk_input)
                .hint_text("Paste OTK from server dashboard…")
                .desired_width(ui.available_width())
                .text_color(TEXT_PRIMARY));
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let can_enroll = !self.enrollment_in_progress;
                if ui.add_enabled(can_enroll, accent_btn_widget("⬆ Enroll with OTK")).clicked() {
                    self.run_enroll_with_otk();
                    self.toast("Enrollment started");
                }
                if ui.add_enabled(can_enroll, egui::Button::new("🔄 Auto Enroll")
                    .fill(BTN_BG).stroke(egui::Stroke::new(1.0, BORDER_CARD)).rounding(10.0))
                    .clicked()
                {
                    self.run_auto_enroll_and_start();
                    self.toast("Auto-enroll started");
                }
                if small_btn(ui, "🔍 Discover Server").clicked() {
                    self.discover_server_start();
                }
            });
            if self.enrollment_in_progress {
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Enrollment in progress…").color(ORANGE));
            }
        });

        ui.add_space(10.0);

        // Certificate management
        card(ui, light, |ui| {
            card_header(ui, "Certificate Management", "TOOLS", ACCENT);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if small_btn(ui, "🔒 Renew Certificate").clicked() {
                    self.run_request_renewal();
                    self.toast("Renewal requested");
                }
                if small_btn(ui, "📦 Install Service").clicked() {
                    match platform_service_install(&self.server_input) {
                        Ok(_) => self.toast("Service installed"),
                        Err(e) => {
                            self.status = format!("Failed: {}", e.trim());
                            self.toast("Service install failed");
                        }
                    }
                }
                let danger_btn = egui::Button::new(
                    egui::RichText::new("Uninstall Service").size(12.0).color(RED),
                )
                .fill(BTN_BG)
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(255, 71, 87, 64)));
                if ui.add(danger_btn).clicked() {
                    let _ = platform_service_uninstall();
                    self.toast("Service uninstalled");
                }
            });
        });

        ui.add_space(10.0);

        card(ui, light, |ui| {
            card_header(ui, "Self-Check", "DIAGNOSTICS", ACCENT);
            ui.add_space(4.0);
            if self.self_check.is_empty() {
                ui.label("No checks run yet. Click Refresh to run diagnostics.");
            } else {
                for (label, ok) in &self.self_check {
                    check_row(ui, *ok, label);
                }
            }
            ui.add_space(6.0);
            if small_btn(ui, "↻ Refresh").clicked() {
                self.run_self_check();
                self.toast("Self-check complete");
            }
        });
    }

    fn tab_health(&mut self, ui: &mut egui::Ui) {
        let light = self.light_theme;

        card(ui, light, |ui| {
            card_header(ui, "System Health", "REALTIME", ACCENT);
            ui.add_space(4.0);
            ui.columns(4, |cols| {
                stat_tile(&mut cols[0], "CPU Load", &format!("{:.1}", self.cpu_usage), ACCENT, light);
                stat_tile(&mut cols[1], "Memory", &format!("{} MB", self.mem_mb), ACCENT, light);
                stat_tile(&mut cols[2], "Disk Buffer", &format!("{} KB", self.buffer_queue), GREEN, light);
                stat_tile(&mut cols[3], "Connections", if self.is_agent_running() { "1" } else { "0" }, GREEN, light);
            });
        });

        ui.add_space(10.0);

        if let Some(health) = &self.health_snapshot {
            card(ui, light, |ui| {
                card_header(ui, "Agent Info", "DETAILS", ACCENT);
                ui.label(egui::RichText::new(format!("Host: {} | IP: {} | MAC: {}",
                    health.hostname, health.primary_ip, health.primary_mac
                )).size(12.0).color(TEXT_SECONDARY));
                ui.label(egui::RichText::new(format!("CPU: {} cores | Memory: {} MB free / {} MB total",
                    health.cpu_cores, health.free_memory_mb, health.total_memory_mb
                )).size(12.0).color(TEXT_SECONDARY));
            });
            ui.add_space(10.0);
        }

        card(ui, light, |ui| {
            card_header(ui, "Compliance Status", "FRAMEWORKS", ACCENT);
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                for fw in &["NIST CSF 2.0", "CIS V8", "PCI DSS v4", "HIPAA", "ISO 27001", "SOC2", "GDPR", "SOX"] {
                    pill(ui, fw, ACCENT);
                    ui.add_space(2.0);
                }
            });
            ui.add_space(8.0);
            separator(ui);
            ui.add_space(4.0);
            let running = self.is_agent_running();
            let checks = [
                (check_firewall_active(), "Firewall active"),
                (check_password_policy(), "Password policy enforced"),
                (check_audit_logging(), "Audit logging enabled"),
                (std::env::var("PERCEPTA_FIM_PATHS").map(|s| !s.trim().is_empty()).unwrap_or(false), "FIM monitoring active"),
                (running, "Agent service running"),
            ];
            for (pass, label) in checks {
                check_row(ui, pass, label);
            }
        });

        ui.add_space(10.0);

        card(ui, light, |ui| {
            card_header(ui, "Sensors", "COLLECTORS", ACCENT);
            ui.add_space(4.0);
            let sensors = [
                (cfg!(windows), "Windows Event Log — collecting"),
                (cfg!(target_os = "linux"), "Linux syslog — collecting"),
                (Path::new("/var/log/suricata/eve.json").exists()
                    || Path::new(r"C:\ProgramData\Suricata\log\eve.json").exists(),
                 "Suricata IDS — eve.json"),
                (std::env::var("PERCEPTA_FIM_PATHS").map(|s| !s.trim().is_empty()).unwrap_or(false), "FIM — active paths"),
            ];
            for (pass, label) in sensors {
                check_row(ui, pass, label);
            }
        });
    }

    fn tab_settings(&mut self, ui: &mut egui::Ui) {
        let light = self.light_theme;
        let running = self.is_agent_running();

        // Agent Behavior
        card(ui, light, |ui| {
            card_header(ui, "Agent Behavior", "CONFIG", ACCENT);
            ui.add_space(4.0);
            if toggle_row(ui, &mut self.auto_restart, "Auto-restart on crash") {
                self.save_config();
                let _ = platform_service_set_autostart(self.auto_restart);
            }
            toggle_row(ui, &mut self.auto_reconnect, "Auto-reconnect to server");
            toggle_row(ui, &mut self.event_dedup, "Event deduplication (60s window)");
            if toggle_row(ui, &mut self.debug_logging, "Debug logging") {
                self.save_config();
            }
            if toggle_row(ui, &mut self.minimize_to_tray, "Minimize to tray on close") {
                self.save_config();
            }
        });

        ui.add_space(10.0);

        // Appearance
        card(ui, light, |ui| {
            card_header(ui, "Appearance", "THEME", ACCENT);
            ui.add_space(4.0);
            if toggle_row(ui, &mut self.light_theme, "Light theme") {
                self.save_config();
            }
            if toggle_row(ui, &mut self.compact_layout, "Compact layout") {
                self.save_config();
            }
            if toggle_row(ui, &mut self.reduce_motion, "Reduce motion / animations") {
                self.save_config();
            }
        });

        ui.add_space(10.0);

        // Service Management
        card(ui, light, |ui| {
            card_header(ui, "Service Management", "SYSTEM", ACCENT);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("Service Status:").size(13.0).color(TEXT_SECONDARY));
                if running {
                    pill(ui, "Active", GREEN);
                } else {
                    pill(ui, "Stopped", RED);
                }
            });
            ui.add_space(2.0);
            ui.label(egui::RichText::new(format!("PID: {}", self.pid)).size(13.0).color(TEXT_SECONDARY));
            ui.label(egui::RichText::new(format!("Service: {}", if cfg!(windows) { SERVICE_NAME } else { LINUX_SERVICE_NAME }))
                .size(13.0).color(TEXT_SECONDARY));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if accent_btn(ui, if running { "⏹ Stop" } else { "▶ Start" }).clicked() {
                    if running { self.disable_agent(); } else { self.enable_agent(); }
                }
                if ui.button("↻ Restart").clicked() {
                    self.restart_agent();
                }
            });
        });
    }

    fn tab_logs(&mut self, ui: &mut egui::Ui) {
        let light = self.light_theme;

        card(ui, light, |ui| {
            card_header(ui, "Agent Logs", "LIVE", ACCENT);
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if small_btn(ui, "↻ Refresh").clicked() {
                    self.open_logs();
                    self.last_log_refresh = Instant::now();
                    self.toast("Logs refreshed");
                }
                ui.label(egui::RichText::new(format!("Last refresh: {}s ago", self.last_log_refresh.elapsed().as_secs()))
                    .size(11.0).color(TEXT_MUTED));
            });
            ui.add_space(6.0);

            // Structured log entries
            let log_bg = if light {
                egui::Color32::from_rgb(0xF0, 0xF2, 0xF6)
            } else {
                egui::Color32::from_rgb(0x06, 0x09, 0x12)
            };
            egui::Frame::none()
                .fill(log_bg)
                .rounding(10.0)
                .stroke(egui::Stroke::new(1.0, BORDER_SUBTLE))
                .inner_margin(egui::Margin::same(12.0))
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(ui.available_height().max(160.0) * 0.45)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for (ts, lvl, msg) in &self.log_lines {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(ts).size(11.0).color(TEXT_MUTED).monospace());
                                    ui.add_space(4.0);
                                    let color = match *lvl {
                                        "WARN" => ORANGE,
                                        "ERR" | "ERROR" => RED,
                                        _ => ACCENT,
                                    };
                                    ui.label(egui::RichText::new(*lvl).size(11.0).color(color).monospace());
                                    ui.add_space(4.0);
                                    ui.label(egui::RichText::new(msg).size(11.0).color(TEXT_SECONDARY).monospace());
                                });
                            }
                        });
                });

            // File-based logs
            if !self.logs_text.is_empty() {
                ui.add_space(8.0);
                ui.label(egui::RichText::new("File Logs").size(13.0).strong().color(TEXT_PRIMARY));
                egui::ScrollArea::vertical()
                    .max_height(ui.available_height().max(160.0) * 0.45)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.logs_text)
                                .desired_rows(10)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace),
                        );
                    });
            }
        });
    }
}

// Button widget helper (for add_enabled compatibility)
fn accent_btn_widget(text: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(text).size(13.0).strong().color(ACCENT))
        .fill(egui::Color32::from_rgba_unmultiplied(0, 212, 255, 38))
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgba_unmultiplied(0, 212, 255, 89),
        ))
        .rounding(10.0)
}

// ─── eframe::App implementation ─────────────────────────────────────────────

impl eframe::App for PerceptaAgentApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle platform messages (tray icon / status notifier)
        while let Ok(msg) = self.platform_rx.try_recv() {
            match msg {
                PlatformMsg::ShowWindow => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                PlatformMsg::Exit => {
                    self.force_exit = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    return;
                }
                PlatformMsg::StopAgent => {
                    self.disable_agent();
                    self.toast("Agent stopped via tray");
                }
                PlatformMsg::RestartAgent => {
                    self.restart_agent();
                    self.toast("Agent restarted via tray");
                }
                PlatformMsg::OpenSettings => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    self.active_tab = Tab::Settings;
                }
            }
        }

        // Handle window close — minimize instead of quitting
        if ctx.input(|i| i.viewport().close_requested())
            && !self.force_exit
            && self.minimize_to_tray
        {
                // Second X click within 2 s → actually quit
                if let Some(prev) = self.last_close_attempt {
                    if prev.elapsed().as_secs_f32() < 2.0 {
                        // Let the close through
                        self.last_close_attempt = None;
                        // fall through to default close
                    } else {
                        self.last_close_attempt = Some(Instant::now());
                        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                        if platform_supports_tray() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                        } else {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                        }
                        self.toast("Agent still running — double-click ✕ to quit");
                        return;
                    }
                } else {
                    self.last_close_attempt = Some(Instant::now());
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    if platform_supports_tray() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                    } else {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    }
                    self.toast("Agent still running — double-click ✕ to quit");
                    return;
                }
        }
        // Force-exit or tray-disabled or double-close: allow window close

        // Handle discovery results
        if let Ok(result) = self.discovery_receiver.try_recv() {
            self.discovery_in_progress = false;
            match result {
                Some(addr) => {
                    self.server_input = normalize_grpc_addr(&addr);
                    self.status = "Server discovered!".into();
                    self.toast("Server discovered via mDNS");
                }
                None => {
                    self.status = "Discovery failed: No server found.".into();
                    self.toast("Discovery failed");
                }
            }
        }

        // Handle enrollment events
        while let Ok(event) = self.event_receiver.try_recv() {
            match event {
                GuiEvent::AutoEnrollFinished(Ok(pid)) => {
                    self.enrollment_in_progress = false;
                    self.core_pid = Some(pid);
                    self.status = format!("Auto-enrollment successful. Agent started (PID: {pid})");
                    self.toast("Auto-enroll complete");
                }
                GuiEvent::AutoEnrollFinished(Err(err)) => {
                    self.enrollment_in_progress = false;
                    self.status = format!("Auto-enroll failed: {err}");
                    self.toast("Auto-enroll failed");
                }
                GuiEvent::EnrollOtkFinished(Ok(msg)) => {
                    self.enrollment_in_progress = false;
                    self.status = format!("{msg} — starting agent");
                    self.toast("Enrollment successful");
                    if !self.is_agent_running() {
                        self.enable_agent();
                    }
                }
                GuiEvent::EnrollOtkFinished(Err(err)) => {
                    self.enrollment_in_progress = false;
                    self.status = err;
                    self.toast("Enrollment failed");
                }
            }
        }

        // Auto-start on first frame
        if !self.auto_restart_checked {
            if self.auto_restart && !self.is_agent_running() {
                self.enable_agent();
            }
            self.auto_restart_checked = true;
        }

        // Periodic refresh
        self.refresh_service_state();
        if self.last_poll.elapsed() >= Duration::from_secs(4) {
            self.refresh_stats();
            ctx.request_repaint_after(Duration::from_secs(4));
        }

        // ── Visuals ────────────────────────────────────────────────────────────
        let (bg_primary, bg_titlebar, text_primary, text_muted, border_subtle) =
            if self.light_theme {
                (
                    egui::Color32::from_rgb(0xF4, 0xF6, 0xFA),
                    egui::Color32::from_rgb(0xE8, 0xEC, 0xF2),
                    egui::Color32::from_rgb(0x1A, 0x1E, 0x2C),
                    egui::Color32::from_rgb(0x6E, 0x78, 0x90),
                    egui::Color32::from_rgb(0xDA, 0xDF, 0xE8),
                )
            } else {
                (BG_PRIMARY, BG_TITLEBAR, TEXT_PRIMARY, TEXT_MUTED, BORDER_SUBTLE)
            };

        let mut visuals = if self.light_theme { egui::Visuals::light() } else { egui::Visuals::dark() };
        visuals.panel_fill = bg_primary;
        visuals.window_fill = if self.light_theme { egui::Color32::WHITE } else { BG_CARD };
        visuals.widgets.noninteractive.bg_fill = if self.light_theme { egui::Color32::WHITE } else { BG_CARD };
        visuals.widgets.inactive.bg_fill = if self.light_theme {
            egui::Color32::from_rgb(0xE2, 0xE6, 0xEE)
        } else { BTN_BG };
        visuals.widgets.inactive.weak_bg_fill = visuals.widgets.inactive.bg_fill;
        visuals.widgets.hovered.bg_fill = if self.light_theme {
            egui::Color32::from_rgb(0xD4, 0xDA, 0xE8)
        } else {
            egui::Color32::from_rgb(0x1A, 0x28, 0x48)
        };
        visuals.selection.bg_fill = egui::Color32::from_rgba_unmultiplied(0, 212, 255, 30);
        visuals.override_text_color = Some(text_primary);
        ctx.set_visuals(visuals);

        let running = self.is_agent_running();

        // ── Header bar ─────────────────────────────────────────────────────────
        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::none()
                    .fill(bg_titlebar)
                    .inner_margin(egui::Margin::symmetric(16.0, 10.0))
                    .stroke(egui::Stroke::new(1.0, border_subtle)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let (logo_r, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
                    // Gradient-like logo: darker accent at top-left to bright accent at bottom-right
                    ui.painter().rect_filled(logo_r, 6.0, egui::Color32::from_rgb(0x00, 0x90, 0xB0));
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(
                            egui::pos2(logo_r.center().x - 2.0, logo_r.min.y),
                            egui::vec2(logo_r.width() / 2.0 + 2.0, logo_r.height()),
                        ),
                        egui::Rounding { nw: 0.0, ne: 6.0, sw: 0.0, se: 6.0 },
                        ACCENT,
                    );
                    ui.painter().text(
                        logo_r.center(),
                        egui::Align2::CENTER_CENTER,
                        "P",
                        egui::FontId::proportional(11.0),
                        egui::Color32::WHITE,
                    );
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Percepta SIEM Agent").size(13.0).color(TEXT_SECONDARY));
                    ui.label(egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION"))).size(11.0).color(text_muted));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if running {
                            ui.colored_label(GREEN, "● ONLINE");
                        } else {
                            ui.colored_label(ORANGE, "○ OFFLINE");
                        }
                    });
                });
            });

        // ── Status banner ──────────────────────────────────────────────────────
        egui::TopBottomPanel::top("status_banner")
            .frame(egui::Frame::none().fill(bg_primary).inner_margin(egui::Margin {
                left: 20.0, right: 20.0, top: 12.0, bottom: 4.0,
            }))
            .show(ctx, |ui| {
                let (banner_color, dot_color, label, detail) = if running {
                    (
                        egui::Color32::from_rgba_unmultiplied(13, 24, 28, 230),
                        GREEN, "AGENT ONLINE",
                        format!("Connected to {}", if self.server_input.is_empty() { "—" } else { &self.server_input }),
                    )
                } else {
                    (
                        egui::Color32::from_rgba_unmultiplied(24, 20, 14, 230),
                        ORANGE, "AGENT OFFLINE",
                        self.status.clone(),
                    )
                };

                // Pulsing glow for the status dot border
                let pulse = if self.reduce_motion {
                    1.0_f32
                } else {
                    let t = ui.input(|i| i.time) as f32;
                    0.65 + 0.35 * (t * std::f32::consts::PI).sin().abs()
                };
                let glow_alpha = (76.0 * pulse) as u8;

                egui::Frame::none()
                    .fill(banner_color).rounding(14.0)
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(dot_color.r(), dot_color.g(), dot_color.b(), glow_alpha)))
                    .inner_margin(egui::Margin::symmetric(18.0, 12.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let (dot_r, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                            // Draw outer pulsing glow
                            if !self.reduce_motion {
                                let glow_radius = 6.0 + 2.0 * pulse;
                                let glow_col = egui::Color32::from_rgba_unmultiplied(
                                    dot_color.r(), dot_color.g(), dot_color.b(), (60.0 * pulse) as u8,
                                );
                                ui.painter().circle_filled(dot_r.center(), glow_radius, glow_col);
                            }
                            // Draw solid dot with animated opacity
                            let dot_alpha = (255.0 * (0.65 + 0.35 * pulse)) as u8;
                            let animated_dot = egui::Color32::from_rgba_unmultiplied(
                                dot_color.r(), dot_color.g(), dot_color.b(), dot_alpha,
                            );
                            ui.painter().circle_filled(dot_r.center(), 6.0, animated_dot);
                            ui.add_space(4.0);
                            ui.label(egui::RichText::new(label).strong().size(14.0).color(dot_color));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(egui::RichText::new(detail).size(12.0).color(TEXT_SECONDARY));
                            });
                        });
                    });
            });

        // ── Footer bar ─────────────────────────────────────────────────────────
        egui::TopBottomPanel::bottom("footer")
            .frame(
                egui::Frame::none()
                    .fill(bg_titlebar)
                    .inner_margin(egui::Margin::symmetric(18.0, 8.0))
                    .stroke(egui::Stroke::new(1.0, border_subtle)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new(format!(
                        "Percepta Agent v{} • PID {} • {}",
                        env!("CARGO_PKG_VERSION"), self.pid,
                        if cfg!(windows) { SERVICE_NAME } else { LINUX_SERVICE_NAME }
                    )).size(11.0).color(text_muted));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let hint = if platform_supports_tray() {
                            "✕ hides to tray · double-✕ to quit"
                        } else {
                            "Off-sec Projections · Percepta SIEM"
                        };
                        ui.label(egui::RichText::new(hint).size(11.0).color(text_muted));
                    });
                });
            });

        // ── Tab bar ────────────────────────────────────────────────────────────
        let tab_track_bg = if self.light_theme {
            egui::Color32::from_rgb(0xE2, 0xE6, 0xEE)
        } else {
            egui::Color32::from_rgb(0x06, 0x0A, 0x14)
        };
        egui::TopBottomPanel::top("tabs")
            .frame(egui::Frame::none().fill(bg_primary).inner_margin(egui::Margin {
                left: 20.0, right: 20.0, top: 8.0, bottom: 8.0,
            }))
            .show(ctx, |ui| {
                egui::Frame::none()
                    .fill(tab_track_bg).rounding(10.0)
                    .stroke(egui::Stroke::new(1.0, border_subtle))
                    .inner_margin(egui::Margin::symmetric(3.0, 3.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = 2.0;
                            for tab in Tab::ALL {
                                let active = self.active_tab == tab;
                                let text = egui::RichText::new(tab.label())
                                    .size(13.0)
                                    .color(if active { ACCENT } else { text_muted });
                                let btn = egui::Button::new(text)
                                    .fill(if active {
                                        egui::Color32::from_rgba_unmultiplied(0, 212, 255, 38)
                                    } else {
                                        egui::Color32::TRANSPARENT
                                    })
                                    .rounding(8.0).stroke(egui::Stroke::NONE)
                                    .min_size(egui::vec2((ui.available_width() / 5.0).max(60.0), 28.0));
                                if ui.add(btn).clicked() {
                                    self.active_tab = tab;
                                }
                            }
                        });
                    });
            });

        // ── Main content ───────────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(bg_primary).inner_margin(egui::Margin::symmetric(20.0, 12.0)))
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    match self.active_tab {
                        Tab::Dashboard => self.tab_dashboard(ui),
                        Tab::Setup => self.tab_setup(ui),
                        Tab::Health => self.tab_health(ui),
                        Tab::Settings => self.tab_settings(ui),
                        Tab::Logs => self.tab_logs(ui),
                    }
                });
            });

        // ── Toast overlay ──────────────────────────────────────────────────────
        if let Some((msg, at)) = self.toast.clone() {
            if at.elapsed() > Duration::from_secs(3) {
                self.toast = None;
            } else {
                let alpha = (1.0 - (at.elapsed().as_secs_f32() / 3.0)).clamp(0.0, 1.0);
                let bg = egui::Color32::from_rgba_unmultiplied(0, 212, 255, (55.0 * alpha) as u8);
                let stroke = egui::Color32::from_rgba_unmultiplied(0, 212, 255, (120.0 * alpha) as u8);
                let txt = egui::Color32::from_rgba_unmultiplied(230, 238, 255, (255.0 * alpha) as u8);
                egui::Area::new("toast".into())
                    .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-18.0, -18.0))
                    .interactable(false)
                    .show(ctx, |ui| {
                        egui::Frame::none()
                            .fill(bg).stroke(egui::Stroke::new(1.0, stroke))
                            .rounding(12.0)
                            .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(msg).color(txt).strong());
                            });
                    });
            }
        }

        // Throttle repaint: 30fps normal, ~12fps reduced-motion
        if self.reduce_motion {
            ctx.request_repaint_after(Duration::from_millis(80));
        } else {
            ctx.request_repaint_after(Duration::from_millis(33));
        }
    }
}
