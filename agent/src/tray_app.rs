#![cfg(target_os = "windows")]

use anyhow::Result;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::config_store;

use native_windows_gui as nwg;

fn set_menu_item_text(item: &nwg::MenuItem, text: &str) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use winapi::shared::minwindef::BOOL;
    use winapi::um::winuser::{SetMenuItemInfoW, MENUITEMINFOW, MIIM_STRING};

    if item.handle.blank() {
        return;
    }

    let (parent_handle, id) = match item.handle.hmenu_item() {
        Some(v) => v,
        None => return,
    };

    let mut wide: Vec<u16> = OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut info = MENUITEMINFOW {
        cbSize: std::mem::size_of::<MENUITEMINFOW>() as u32,
        fMask: MIIM_STRING,
        fType: 0,
        fState: 0,
        wID: 0,
        hSubMenu: ptr::null_mut(),
        hbmpChecked: ptr::null_mut(),
        hbmpUnchecked: ptr::null_mut(),
        dwItemData: 0,
        dwTypeData: wide.as_mut_ptr(),
        cch: (wide.len().saturating_sub(1)) as u32,
        hbmpItem: ptr::null_mut(),
    };

    unsafe {
        // use_position = false because we target by item ID
        SetMenuItemInfoW(parent_handle as *mut _, id, false as BOOL, &mut info);
    }
}

#[derive(Default)]
struct SystemTray {
    window: nwg::MessageWindow,
    icon: nwg::Icon,
    tray: nwg::TrayNotification,
    tray_menu: nwg::Menu,

    status_item: nwg::MenuItem,
    _separator1: nwg::MenuSeparator,
    start_item: nwg::MenuItem,
    stop_item: nwg::MenuItem,
    restart_item: nwg::MenuItem,
    _separator2: nwg::MenuSeparator,
    settings_item: nwg::MenuItem,
    _separator3: nwg::MenuSeparator,
    exit_item: nwg::MenuItem,

    agent_running: Arc<Mutex<bool>>,
    connection_status: Arc<Mutex<String>>,
}

impl SystemTray {
    fn service_name() -> &'static str {
        "PerceptaSIEMAgent"
    }

    fn run_sc(args: &[&str]) -> Result<String, String> {
        let out = Command::new("sc")
            .args(args)
            .output()
            .map_err(|e| format!("Failed to run sc.exe: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if out.status.success() {
            Ok(format!("{}{}", stdout, stderr))
        } else {
            Err(format!("{}{}", stdout, stderr))
        }
    }

    fn refresh_running_state(&self) {
        if let Ok(out) = Self::run_sc(&["query", Self::service_name()]) {
            let running = out.to_ascii_uppercase().contains("RUNNING");
            *self.agent_running.lock().unwrap() = running;
            *self.connection_status.lock().unwrap() = if running {
                "Running".to_string()
            } else {
                "Stopped".to_string()
            };
            self.update_tray_icon(running);
        }
    }

    fn show_settings(&self) {
        // Launch the GUI to edit server address (writes config.json).
        let cfg_path = config_store::default_config_path();

        let mut launched = false;
        if let Ok(cur) = std::env::current_exe() {
            // Prefer launching the same EXE in GUI mode; this keeps "single EXE" semantics.
            if Command::new(&cur).spawn().is_ok() {
                launched = true;
            }
        }

        if !launched {
            nwg::modal_info_message(
                &self.window,
                "Settings",
                &format!(
                    "Open the Percepta GUI to edit server address.\n\nConfig file: {}",
                    cfg_path.display()
                ),
            );
        }
    }

    fn start_agent(&self) {
        let mut running = self.agent_running.lock().unwrap();
        if *running {
            nwg::modal_info_message(&self.window, "Agent Status", "Agent is already running");
            return;
        }

        match Self::run_sc(&["start", Self::service_name()]) {
            Ok(_) => {
                *running = true;
                *self.connection_status.lock().unwrap() = "Running".to_string();
                self.update_tray_icon(true);
                nwg::modal_info_message(&self.window, "Agent Status", "Agent service started");
            }
            Err(e) => {
                nwg::modal_error_message(
                    &self.window,
                    "Agent Status",
                    &format!("Failed to start service:\n{}", e),
                );
                self.refresh_running_state();
            }
        }
    }

    fn stop_agent(&self) {
        let mut running = self.agent_running.lock().unwrap();
        if !*running {
            nwg::modal_info_message(&self.window, "Agent Status", "Agent is not running");
            return;
        }

        match Self::run_sc(&["stop", Self::service_name()]) {
            Ok(_) => {
                *running = false;
                *self.connection_status.lock().unwrap() = "Stopped".to_string();
                self.update_tray_icon(false);
                nwg::modal_info_message(&self.window, "Agent Status", "Agent service stopped");
            }
            Err(e) => {
                nwg::modal_error_message(
                    &self.window,
                    "Agent Status",
                    &format!("Failed to stop service:\n{}", e),
                );
                self.refresh_running_state();
            }
        }
    }

    fn restart_agent(&self) {
        let _ = Self::run_sc(&["stop", Self::service_name()]);
        thread::sleep(Duration::from_secs(1));
        let _ = Self::run_sc(&["start", Self::service_name()]);
        self.refresh_running_state();
        nwg::modal_info_message(&self.window, "Agent Status", "Agent service restarted");
    }

    fn update_tray_icon(&self, connected: bool) {
        let icon_text = if connected {
            "Percepta SIEM Agent - Connected"
        } else {
            "Percepta SIEM Agent - Disconnected"
        };

        self.tray.set_tip(icon_text);
    }

    fn update_menu(&self) {
        let running = *self.agent_running.lock().unwrap();
        let status = self.connection_status.lock().unwrap();

        set_menu_item_text(&self.status_item, &format!("Status: {}", *status));
        self.start_item.set_enabled(!running);
        self.stop_item.set_enabled(running);
        self.restart_item.set_enabled(running);
    }

    fn show_menu(&self) {
        self.update_menu();
        let (x, y) = nwg::GlobalCursor::position();
        self.tray_menu.popup(x, y);
    }

    fn exit(&self) {
        nwg::stop_thread_dispatch();
    }
}

fn build_ui(app: &mut SystemTray) -> Result<(), nwg::NwgError> {
    nwg::MessageWindow::builder().build(&mut app.window)?;

    nwg::Icon::builder()
        .source_system(Some(nwg::OemIcon::WinLogo))
        .build(&mut app.icon)?;

    nwg::Menu::builder()
        .popup(true)
        .parent(&app.window)
        .build(&mut app.tray_menu)?;

    nwg::MenuItem::builder()
        .text("Status: Disconnected")
        .parent(&app.tray_menu)
        .disabled(true)
        .build(&mut app.status_item)?;

    nwg::MenuSeparator::builder()
        .parent(&app.tray_menu)
        .build(&mut app._separator1)?;

    nwg::MenuItem::builder()
        .text("Start Agent")
        .parent(&app.tray_menu)
        .build(&mut app.start_item)?;

    nwg::MenuItem::builder()
        .text("Stop Agent")
        .parent(&app.tray_menu)
        .build(&mut app.stop_item)?;

    nwg::MenuItem::builder()
        .text("Restart Agent")
        .parent(&app.tray_menu)
        .build(&mut app.restart_item)?;

    nwg::MenuSeparator::builder()
        .parent(&app.tray_menu)
        .build(&mut app._separator2)?;

    nwg::MenuItem::builder()
        .text("Settings...")
        .parent(&app.tray_menu)
        .build(&mut app.settings_item)?;

    nwg::MenuSeparator::builder()
        .parent(&app.tray_menu)
        .build(&mut app._separator3)?;

    nwg::MenuItem::builder()
        .text("Exit")
        .parent(&app.tray_menu)
        .build(&mut app.exit_item)?;

    nwg::TrayNotification::builder()
        .parent(&app.window)
        .icon(Some(&app.icon))
        .tip(Some("Percepta SIEM Agent"))
        .build(&mut app.tray)?;

    Ok(())
}

fn connect_events(app: &'static SystemTray) {
    let evt_handler =
        nwg::full_bind_event_handler(&app.window.handle, move |evt, _evt_data, handle| {
            use nwg::Event as E;

            match evt {
                E::OnContextMenu => {
                    if &handle == &app.tray {
                        app.show_menu();
                    }
                }
                E::OnMenuItemSelected => {
                    if &handle == &app.start_item {
                        app.start_agent();
                    } else if &handle == &app.stop_item {
                        app.stop_agent();
                    } else if &handle == &app.restart_item {
                        app.restart_agent();
                    } else if &handle == &app.settings_item {
                        app.show_settings();
                    } else if &handle == &app.exit_item {
                        app.exit();
                    }
                }
                _ => {}
            }
        });

    std::mem::forget(evt_handler);
}

pub fn run_tray() -> Result<()> {
    nwg::init()?;
    nwg::Font::set_global_family("Segoe UI")?;

    let mut app = Box::new(SystemTray {
        agent_running: Arc::new(Mutex::new(false)),
        connection_status: Arc::new(Mutex::new("Disconnected".to_string())),
        ..Default::default()
    });

    build_ui(&mut app)?;
    let app: &'static SystemTray = Box::leak(app);
    connect_events(app);

    // Initialize menu state based on current service status.
    app.refresh_running_state();

    nwg::dispatch_thread_events();
    Ok(())
}
