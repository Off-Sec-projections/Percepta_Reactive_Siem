//! Windows-specific GUI platform layer.
//!
//! Win32 system-tray icon, sc.exe service management, and UAC elevation.
//! The main `run()` function launches the tray icon thread and the shared egui
//! app from [`gui_common`].

#![cfg(windows)]

use std::{
    ffi::OsStr,
    fs::{self, OpenOptions},
    io::Write,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
        OnceLock,
    },
};

use chrono::Local;
use parking_lot::Mutex;
use tracing::{info, warn};

use crate::gui_common::{
    build_icon, gui_log_dir, CommandExtNoWindow, PlatformMsg, PerceptaAgentApp,
    SERVICE_NAME,
};

// ─── Tray → GUI channel ────────────────────────────────────────────────────

pub enum UiMsg {
    ShowWindow,
    StopAgent,
    RestartAgent,
    OpenSettings,
    Exit,
}

static UI_TX: OnceLock<Mutex<mpsc::Sender<UiMsg>>> = OnceLock::new();
static TRAY_AVAILABLE: AtomicBool = AtomicBool::new(false);
static TASKBAR_CREATED_MSG: OnceLock<u32> = OnceLock::new();

fn notify_gui(msg: UiMsg) {
    if let Some(mtx) = UI_TX.get() {
        let _ = mtx.lock().send(msg);
    }
}

pub fn tray_available() -> bool {
    TRAY_AVAILABLE.load(Ordering::SeqCst)
}

// ─── sc.exe wrapper ─────────────────────────────────────────────────────────

/// Run `sc.exe` with the given args, enforcing a 5-second timeout.
///
/// `sc.exe` can stall when called from a service context, an impersonated
/// account, or a network-share CWD.  Running it in a dedicated thread lets us
/// apply a hard deadline without killing the calling thread.
fn sc_run(args: &[&str]) -> std::io::Result<std::process::Output> {
    use std::sync::mpsc as std_mpsc;

    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let (tx, rx) = std_mpsc::channel::<std::io::Result<std::process::Output>>();
    std::thread::spawn(move || {
        let result = Command::new("sc.exe")
            .no_window()
            .args(owned.iter().map(String::as_str))
            .output();
        let _ = tx.send(result);
    });
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .unwrap_or_else(|_| Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "sc.exe did not respond within 5 seconds",
        )))
}

pub fn service_query() -> Option<bool> {
    let out = sc_run(&["query", SERVICE_NAME]).ok()?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    Some(stdout.contains("RUNNING"))
}

pub fn service_start() -> Result<String, String> {
    let out = sc_run(&["start", SERVICE_NAME]).map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if out.status.success() || stdout.contains("RUNNING") {
        Ok(stdout)
    } else {
        Err(format!(
            "{}{}",
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

pub fn service_stop() -> Result<String, String> {
    let out = sc_run(&["stop", SERVICE_NAME]).map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if out.status.success() || stdout.contains("STOPPED") {
        Ok(stdout)
    } else {
        Err(format!(
            "{}{}",
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

pub fn service_restart() -> Result<String, String> {
    let _ = service_stop();
    std::thread::sleep(std::time::Duration::from_millis(500));
    service_start()
}

pub fn service_install(server: &str) -> Result<String, String> {
    let core_path =
        crate::gui_common::resolve_core_binary_path().ok_or("Agent executable not found")?;
    let bin = core_path.display().to_string();
    let _ = server;
    // GUI-only flow: service mode is internal; server is read from persisted config/env.
    let binpath_val = format!("\"{}\" --service", bin);
    let out = sc_run(&[
        "create",
        SERVICE_NAME,
        "binPath=",
        &binpath_val,
        "start=",
        "auto",
        "DisplayName=",
        "Percepta SIEM Agent",
    ])
    .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if out.status.success() || stdout.contains("SUCCESS") || stdout.contains("exists") {
        Ok(stdout)
    } else {
        Err(format!(
            "{}{}",
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

pub fn service_uninstall() -> Result<String, String> {
    let _ = service_stop();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let out = sc_run(&["delete", SERVICE_NAME]).map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    if out.status.success() {
        Ok(stdout)
    } else {
        Err(format!(
            "{}{}",
            stdout,
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

pub fn service_set_autostart(enabled: bool) -> Result<String, String> {
    let start = if enabled { "auto" } else { "demand" };
    let out = sc_run(&["config", SERVICE_NAME, "start=", start]).map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

// ─── UAC elevation ──────────────────────────────────────────────────────────

pub fn relaunch_elevated() -> bool {
    use std::os::windows::ffi::OsStrExt;
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let w_exe: Vec<u16> = exe_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let verb: Vec<u16> = "runas\0".encode_utf16().collect();
    unsafe {
        let ret = winapi::um::shellapi::ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            w_exe.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            winapi::um::winuser::SW_SHOWNORMAL,
        );
        (ret as usize) > 32
    }
}

pub fn ensure_service_running() {
    match service_query() {
        Some(true) => info!("Service already running"),
        Some(false) => {
            match service_start() {
                Ok(_) => info!("Service started"),
                Err(err) => {
                    let log_path = append_startup_log(&format!(
                        "Windows GUI started without background service: {}",
                        err
                    ));
                    warn!(
                        service_error = %err,
                        log_path = %log_path.display(),
                        "Windows service did not start automatically; continuing with GUI only"
                    );
                }
            }
        }
        None => {
            info!("Service not installed; will install on first Start");
        }
    }
}

// ─── Win32 tray icon ────────────────────────────────────────────────────────

const WM_TRAY: u32 = winapi::um::winuser::WM_APP + 1;
const ID_TRAY: u32 = 1;

fn taskbar_created_message() -> u32 {
    *TASKBAR_CREATED_MSG.get_or_init(|| unsafe {
        winapi::um::winuser::RegisterWindowMessageW(wstr("TaskbarCreated").as_ptr())
    })
}

fn startup_log_path() -> PathBuf {
    let preferred = gui_log_dir().join("gui-startup.log");
    if let Some(parent) = preferred.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if preferred.parent().map(|p| p.exists()).unwrap_or(false) {
        preferred
    } else {
        std::env::temp_dir().join("percepta-agent-gui-startup.log")
    }
}

fn append_startup_log(message: &str) -> PathBuf {
    let path = startup_log_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(
            file,
            "{} {}",
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            message
        );
    }
    path
}

fn show_error_dialog(title: &str, message: &str) {
    let title_wide: Vec<u16> = OsStr::new(title)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let body_wide: Vec<u16> = OsStr::new(message)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        winapi::um::winuser::MessageBoxW(
            std::ptr::null_mut(),
            body_wide.as_ptr(),
            title_wide.as_ptr(),
            winapi::um::winuser::MB_OK | winapi::um::winuser::MB_ICONERROR,
        );
    }
}

pub fn report_startup_failure(message: &str) {
    let log_path = append_startup_log(&format!("GUI startup failure: {}", message));
    let body = format!(
        "Percepta SIEM Agent could not start the Windows GUI.\n\n{}\n\nDetails were written to:\n{}",
        message,
        log_path.display()
    );
    show_error_dialog("Percepta Agent GUI startup failed", &body);
}

fn start_tray_thread() {
    std::thread::spawn(|| {
        unsafe {
            use winapi::um::libloaderapi::GetModuleHandleW;
            use winapi::um::winuser::*;

            let class_name = wstr("PerceptaTray");
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(tray_wnd_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: GetModuleHandleW(std::ptr::null()),
                hIcon: std::ptr::null_mut(),
                hCursor: std::ptr::null_mut(),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
            };
            RegisterClassW(&wc);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                class_name.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if hwnd.is_null() {
                TRAY_AVAILABLE.store(false, Ordering::SeqCst);
                let log_path = append_startup_log(
                    "Windows tray initialization failed: CreateWindowExW returned NULL",
                );
                warn!(
                    log_path = %log_path.display(),
                    "Windows tray unavailable; GUI will continue without tray integration"
                );
                return;
            }
            let _ = taskbar_created_message();
            let _ = add_tray_icon(hwnd);

            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            remove_tray_icon(hwnd);
        }
    });
}

unsafe fn add_tray_icon(hwnd: winapi::shared::windef::HWND) -> bool {
    use winapi::um::shellapi::*;
    if hwnd.is_null() {
        TRAY_AVAILABLE.store(false, Ordering::SeqCst);
        return false;
    }
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = ID_TRAY;
    nid.uFlags = NIF_ICON | NIF_TIP | NIF_MESSAGE;
    nid.uCallbackMessage = WM_TRAY;
    nid.hIcon = winapi::um::winuser::LoadIconW(
        std::ptr::null_mut(),
        winapi::um::winuser::IDI_APPLICATION,
    );
    let tip_wide = wstr("Percepta SIEM Agent");
    for (i, &ch) in tip_wide.iter().enumerate().take(127) {
        nid.szTip[i] = ch;
    }
    let added = Shell_NotifyIconW(NIM_ADD, &mut nid) != 0;
    TRAY_AVAILABLE.store(added, Ordering::SeqCst);
    if !added {
        let log_path = append_startup_log(
            "Windows tray initialization failed: Shell_NotifyIconW(NIM_ADD) returned 0",
        );
        warn!(
            log_path = %log_path.display(),
            "Windows tray icon could not be registered"
        );
    }
    added
}

unsafe fn remove_tray_icon(hwnd: winapi::shared::windef::HWND) {
    use winapi::um::shellapi::*;
    if hwnd.is_null() {
        TRAY_AVAILABLE.store(false, Ordering::SeqCst);
        return;
    }
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = ID_TRAY;
    if Shell_NotifyIconW(NIM_DELETE, &mut nid) == 0 {
        warn!("Windows tray icon removal reported failure");
    }
    TRAY_AVAILABLE.store(false, Ordering::SeqCst);
}

unsafe fn show_tray_menu(hwnd: winapi::shared::windef::HWND) {
    use winapi::um::winuser::*;
    if hwnd.is_null() {
        return;
    }
    let hmenu = CreatePopupMenu();
    AppendMenuW(hmenu, MF_STRING, 1, wstr("Show Window").as_ptr());
    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(hmenu, MF_STRING, 3, wstr("Stop Agent").as_ptr());
    AppendMenuW(hmenu, MF_STRING, 4, wstr("Restart Agent").as_ptr());
    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(hmenu, MF_STRING, 5, wstr("Settings").as_ptr());
    AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
    AppendMenuW(hmenu, MF_STRING, 2, wstr("Exit Agent").as_ptr());
    let mut pt: winapi::shared::windef::POINT = std::mem::zeroed();
    GetCursorPos(&mut pt);
    SetForegroundWindow(hwnd);
    let cmd = TrackPopupMenu(hmenu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, std::ptr::null());
    DestroyMenu(hmenu);
    match cmd as u32 {
        1 => notify_gui(UiMsg::ShowWindow),
        2 => notify_gui(UiMsg::Exit),
        3 => notify_gui(UiMsg::StopAgent),
        4 => notify_gui(UiMsg::RestartAgent),
        5 => notify_gui(UiMsg::OpenSettings),
        _ => {}
    }
}

unsafe extern "system" fn tray_wnd_proc(
    hwnd: winapi::shared::windef::HWND,
    msg: u32,
    wparam: winapi::shared::minwindef::WPARAM,
    lparam: winapi::shared::minwindef::LPARAM,
) -> winapi::shared::minwindef::LRESULT {
    use winapi::um::winuser::*;
    if msg == taskbar_created_message() {
        let _ = add_tray_icon(hwnd);
        return 0;
    }
    if msg == WM_TRAY {
        let event = (lparam & 0xFFFF) as u32;
        match event {
            WM_LBUTTONUP | WM_LBUTTONDBLCLK => {
                notify_gui(UiMsg::ShowWindow);
                return 0;
            }
            WM_RBUTTONUP => {
                show_tray_menu(hwnd);
                return 0;
            }
            _ => {}
        }
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

fn wstr(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

// ─── Run entry point ────────────────────────────────────────────────────────

pub fn run() -> anyhow::Result<()> {
    // Create platform message channel
    let (platform_tx, platform_rx) = mpsc::channel::<PlatformMsg>();

    // Store the sender for the tray icon thread to use
    let (tray_tx, tray_rx) = mpsc::channel::<UiMsg>();
    UI_TX.get_or_init(|| Mutex::new(tray_tx));

    // Forward UiMsg → PlatformMsg in a bridge thread
    let tx = platform_tx;
    std::thread::spawn(move || {
        while let Ok(msg) = tray_rx.recv() {
            let pm = match msg {
                UiMsg::ShowWindow => PlatformMsg::ShowWindow,
                UiMsg::Exit => PlatformMsg::Exit,
                UiMsg::StopAgent => PlatformMsg::StopAgent,
                UiMsg::RestartAgent => PlatformMsg::RestartAgent,
                UiMsg::OpenSettings => PlatformMsg::OpenSettings,
            };
            if tx.send(pm).is_err() {
                break;
            }
        }
    });

    start_tray_thread();

    let app = PerceptaAgentApp::new(platform_rx);

    // Wrap in an Arc so the app can be recovered if the hardware renderer fails to
    // initialize (before calling the app_creator closure).
    let app_cell = std::sync::Arc::new(parking_lot::Mutex::new(Some(app)));
    let app_cell2 = std::sync::Arc::clone(&app_cell);

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

    // Try hardware-accelerated rendering first; fall back to software renderer if it fails.
    // This handles VMs, RDP sessions, and older GPU drivers that lack OpenGL support.
    let run_result = eframe::run_native(
        "Percepta SIEM Agent",
        native_options,
        Box::new(move |_cc| {
            let a = app_cell2
                .lock()
                .take()
                .expect("app was already consumed on first run");
            Box::new(a)
        }),
    );

    if let Err(ref e) = run_result {
        tracing::warn!(
            "Hardware-accelerated renderer failed ({}); retrying with software renderer",
            e
        );
        // If the app_creator closure was never invoked (renderer failed at initialization),
        // the app is still inside app_cell and we can recover it for the software retry.
        if let Some(app_retry) = app_cell.lock().take() {
            let sw_options = eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size([920.0, 640.0])
                    .with_min_inner_size([720.0, 500.0])
                    .with_icon(std::sync::Arc::new(build_icon()))
                    .with_title("Percepta SIEM Agent"),
                vsync: false,
                hardware_acceleration: eframe::HardwareAcceleration::Off,
                follow_system_theme: false,
                ..Default::default()
            };
            return eframe::run_native(
                "Percepta SIEM Agent",
                sw_options,
                Box::new(move |_cc| Box::new(app_retry)),
            )
            .map_err(|e| anyhow::anyhow!("eframe software renderer error: {}", e));
        }
    }

    run_result.map_err(|e| anyhow::anyhow!("eframe error: {}", e))
}
