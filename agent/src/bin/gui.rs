use eframe::egui;
use mdns_sd::{ServiceDaemon, ServiceEvent};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use percepta_agent::config_store;
use percepta_agent::identity::DeviceIdentity;
use percepta_agent::system_info;

#[derive(Serialize, Deserialize, Default)]
struct GuiConfig {
    server: String,
    debug: bool,
}

fn default_config_path() -> PathBuf {
    config_store::default_config_path()
}

fn default_cert_dir() -> PathBuf {
    let fallback = if cfg!(windows) {
        r"C:\ProgramData\percepta_agent\certs"
    } else {
        "./certs"
    };
    std::env::var("PERCEPTA_CERT_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback))
}

fn read_agent_id_for_display(cert_dir: &PathBuf) -> Option<String> {
    let agent_id_txt = cert_dir.join("agent_id.txt");
    if let Ok(s) = fs::read_to_string(&agent_id_txt) {
        let v = s.trim().to_string();
        if !v.is_empty() {
            return Some(v);
        }
    }

    let identity_json = cert_dir.join("identity.json");
    if let Ok(bytes) = fs::read(&identity_json) {
        if let Ok(ident) = serde_json::from_slice::<DeviceIdentity>(&bytes) {
            let v = ident.agent_id.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }

    None
}

struct AgentGui {
    server_input: String,
    status: String,
    debug: bool,
    logs: String,
    config_path: PathBuf,
    core_pid: Option<u32>,
    otk_input: String,
    discovery_receiver: mpsc::Receiver<Option<String>>,
    discovery_sender: mpsc::Sender<Option<String>>,

    // UI state
    show_setup: bool,
    show_logs: bool,
    last_log_refresh: Instant,
    toast: Option<(String, Instant)>,
}

impl Default for AgentGui {
    fn default() -> Self {
        let config_path = default_config_path();
        let mut server_input = String::new();
        let mut debug = false;

        if let Ok(contents) = fs::read_to_string(&config_path) {
            if let Ok(cfg) = serde_json::from_str::<GuiConfig>(&contents) {
                server_input = cfg.server;
                debug = cfg.debug;
            }
        }

        let (tx, rx) = mpsc::channel();

        // Build initial GUI state
        let mut s = Self {
            server_input,
            status: "Not connected".to_string(),
            debug,
            logs: String::new(),
            config_path,
            core_pid: None,
            otk_input: String::new(),
            discovery_receiver: rx,
            discovery_sender: tx,

            show_setup: true,
            show_logs: false,
            last_log_refresh: Instant::now(),
            toast: None,
        };

        // Auto-enroll flow from files next to exe
        #[cfg(target_os = "windows")]
        {
            if let Ok(cur) = std::env::current_exe() {
                if let Some(dir) = cur.parent() {
                    let otk_path = dir.join("otk.txt");
                    let server_cfg = dir.join("server-config.txt");

                    if otk_path.exists() {
                        if let Ok(otk_contents) = fs::read_to_string(&otk_path) {
                            s.otk_input = otk_contents.trim().to_string();
                        }
                    }

                    if server_cfg.exists() {
                        if let Ok(cfg_contents) = fs::read_to_string(&server_cfg) {
                            for line in cfg_contents.lines() {
                                if line.starts_with("grpc_server=") {
                                    let val = line.splitn(2, '=').nth(1).unwrap_or("");
                                    s.server_input = val.trim().to_string();
                                }
                            }
                        }
                    }

                    let cert_dir = PathBuf::from(r"C:\ProgramData\percepta_agent\certs");
                    let ca_fp = cert_dir.join("ca_fingerprint.txt");

                    if (!ca_fp.exists()) && !s.otk_input.is_empty() && !s.server_input.is_empty() {
                        s.status = "Auto-enrolling...".to_string();
                        s.run_enroll_with_otk();
                    }
                }
            }
        }

        s
    }
}

impl AgentGui {
    fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    fn apply_visuals(ctx: &egui::Context) {
        let mut v = egui::Visuals::dark();
        v.window_rounding = egui::Rounding::same(14.0);
        v.menu_rounding = egui::Rounding::same(12.0);
        v.panel_fill = egui::Color32::from_rgb(10, 12, 20);
        v.override_text_color = Some(egui::Color32::from_rgb(230, 238, 255));
        ctx.set_visuals(v);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(10.0, 7.0);
        style.spacing.window_margin = egui::Margin::same(14);
        ctx.set_style(style);
    }

    fn pill(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
        let frame = egui::Frame::none()
            .fill(color.gamma_multiply(0.20))
            .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.50)))
            .rounding(egui::Rounding::same(999.0))
            .inner_margin(egui::Margin::symmetric(10, 6));
        frame.show(ui, |ui| {
            ui.label(egui::RichText::new(text).strong());
        });
    }

    fn status_dot(ui: &mut egui::Ui, running: bool, ctx: &egui::Context) {
        let base = if running {
            egui::Color32::from_rgb(46, 204, 113)
        } else {
            egui::Color32::from_rgb(255, 165, 2)
        };
        let t = ctx.input(|i| i.time) as f32;
        let pulse = 0.55 + 0.45 * (t * 2.2).sin().abs();
        let fill = base.gamma_multiply(pulse);

        let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
        ui.painter()
            .circle_filled(rect.center(), 6.0, fill);
        ui.painter().circle_stroke(
            rect.center(),
            6.0,
            egui::Stroke::new(1.0, base.gamma_multiply(0.7)),
        );
    }

    fn spinner(ui: &mut egui::Ui, active: bool, ctx: &egui::Context) {
        if !active {
            return;
        }
        let size = 16.0;
        let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
        let center = rect.center();
        let r = size * 0.45;
        let t = ctx.input(|i| i.time) as f32;
        let a0 = t * 5.5;
        let a1 = a0 + 2.4;
        let p0 = center + egui::vec2(a0.cos() * r, a0.sin() * r);
        let p1 = center + egui::vec2(a1.cos() * r, a1.sin() * r);
        ui.painter().line_segment(
            [p0, p1],
            egui::Stroke::new(2.5, egui::Color32::from_rgb(0, 212, 255)),
        );
    }

    fn save_config(&self) {
        let cfg = config_store::AgentUiConfig {
            server: self.server_input.clone(),
            debug: self.debug,
        };
        let _ = config_store::save_config(&cfg);
    }

    fn open_logs(&mut self) {
        let mut candidates = vec![];
        if cfg!(windows) {
            candidates.push(PathBuf::from(
                r"C:\ProgramData\percepta_agent\outgoing\agent.log",
            ));
            candidates.push(PathBuf::from(
                r"C:\ProgramData\percepta_agent\outgoing\latest.log",
            ));
        } else {
            if let Ok(home) = std::env::var("HOME") {
                candidates.push(
                    PathBuf::from(home).join(".local/share/percepta-siem/percepta-agent.log"),
                );
            }
            candidates.push(PathBuf::from("./outgoing/agent.log"));
        }

        for p in candidates {
            if p.exists() {
                if let Ok(content) = fs::read_to_string(&p) {
                    self.logs = content;
                    return;
                }
            }
        }
        self.logs = "No log file found in common locations.".to_string();
    }

    fn discover_server(sender: mpsc::Sender<Option<String>>) {
        thread::spawn(move || {
            let service_type = "_percepta-siem._tcp.local.";
            if let Ok(mdns) = ServiceDaemon::new() {
                if let Ok(receiver) = mdns.browse(service_type) {
                    let start_time = Instant::now();
                    while start_time.elapsed() < Duration::from_secs(5) {
                        if let Ok(ServiceEvent::ServiceResolved(info)) =
                            receiver.recv_timeout(Duration::from_secs(1))
                        {
                            if let Some(addr) = info.get_addresses().iter().next() {
                                let server_addr = format!("{}:{}", addr, info.get_port());
                                sender.send(Some(server_addr)).unwrap();
                                return;
                            }
                        }
                    }
                }
            }
            sender.send(None).unwrap();
        });
    }

    fn start_agent_core(&mut self) {
        if self.server_input.is_empty() {
            self.status = "Server address is empty".to_string();
            return;
        }
        self.save_config();
        self.status = format!("Starting agent for server: {}", self.server_input);

        let server = self.server_input.clone();

        let core_names = if cfg!(windows) {
            vec!["percepta-agent.exe", "percepta-agent-core.exe"]
        } else {
            vec!["percepta-agent", "percepta-agent-core"]
        };

        let mut cmd_path = None;

        if let Ok(cur) = std::env::current_exe() {
            if let Some(dir) = cur.parent() {
                for name in &core_names {
                    let p = dir.join(name);
                    if p.exists() {
                        cmd_path = Some(p);
                        break;
                    }
                }
            }
        }

        if cmd_path.is_none() {
            for name in &core_names {
                if let Ok(p) = which::which(name) {
                    cmd_path = Some(p);
                    break;
                }
            }
        }

        if let Some(path) = cmd_path {
            let mut cmd = Command::new(path);
            cmd.arg("--server").arg(&server);

            if cfg!(windows) {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }

            if let Ok(child) = cmd.spawn() {
                self.core_pid = Some(child.id());
                self.status = format!("Agent started (PID: {})", child.id());
            } else {
                self.status = "Failed to start agent process".to_string();
            }
        } else {
            self.status = "Agent executable not found".to_string();
        }
    }

    fn run_auto_enroll_and_start(&mut self) {
        if self.server_input.is_empty() {
            self.status = "Server address is empty".to_string();
            return;
        }
        self.save_config();
        self.status = "Starting auto-enrollment and connect...".to_string();

        let server = self.server_input.clone();
        thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(r) => r,
                Err(_) => return,
            };

            let res: anyhow::Result<()> = rt.block_on(async move {
                let host = server.split(':').next().unwrap_or(&server).to_string();
                let ca_url = format!("http://{}:8080/api/ca_cert", host);
                let otk_url = format!("http://{}:8080/api/enroll/request", host);

                let client = reqwest::Client::new();
                let ca_pem = client.get(&ca_url).send().await?.text().await?;

                let req_body = serde_json::json!({"admin_id": "gui-auto"});
                let otk_json: serde_json::Value = client
                    .post(&otk_url)
                    .json(&req_body)
                    .send()
                    .await?
                    .json()
                    .await?;
                let otk = otk_json
                    .get("otk")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("OTK missing"))?
                    .to_string();

                let cert_dir = PathBuf::from(r"C:\ProgramData\percepta_agent\certs");
                tokio::fs::create_dir_all(&cert_dir).await?;
                tokio::fs::write(cert_dir.join("ca_cert.pem"), ca_pem.as_bytes()).await?;

                let grpc_addr = if server.contains(':') {
                    server.clone()
                } else {
                    format!("{}:50051", server)
                };

                let core_exe = which::which("percepta-agent.exe")
                    .or_else(|_| which::which("percepta-agent-core.exe"))?;

                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;

                let mut child = Command::new(&core_exe)
                    .creation_flags(CREATE_NO_WINDOW)
                    .arg("--enroll")
                    .arg(&otk)
                    .arg("--server")
                    .arg(&grpc_addr)
                    .spawn()?;
                let status = child.wait()?;
                if !status.success() {
                    return Err(anyhow::anyhow!("Enrollment process failed"));
                }

                Command::new(&core_exe)
                    .creation_flags(CREATE_NO_WINDOW)
                    .arg("--server")
                    .arg(&grpc_addr)
                    .spawn()?;
                Ok(())
            });

            if let Err(e) = res {
                eprintln!("Auto-Enroll & Start failed: {:#}", e);
            }
        });
    }

    fn run_enroll_with_otk(&mut self) {
        if self.server_input.is_empty() || self.otk_input.is_empty() {
            self.status = "Server or OTK is empty".to_string();
            return;
        }
        self.status = "Enrolling with OTK...".to_string();

        let server = self.server_input.clone();
        let otk = self.otk_input.clone();

        let core_names = if cfg!(windows) {
            vec!["percepta-agent.exe", "percepta-agent-core.exe"]
        } else {
            vec!["percepta-agent", "percepta-agent-core"]
        };

        // Simplified logic to find and run the command
        if let Ok(path) = which::which(&core_names[0]).or_else(|_| which::which(&core_names[1])) {
            let mut cmd = Command::new(path);
            cmd.arg("--enroll").arg(&otk).arg("--server").arg(&server);
            if cfg!(windows) {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            if cmd.spawn().is_ok() {
                self.status = "Enrollment process started.".to_string();
            } else {
                self.status = "Failed to start enrollment process.".to_string();
            }
        } else {
            self.status = "Agent executable not found in PATH.".to_string();
        }
    }

    fn run_request_renewal(&mut self) {
        if self.server_input.is_empty() {
            self.status = "Server address is empty".to_string();
            return;
        }

        self.status = "Requesting certificate renewal...".to_string();
        let server = self.server_input.clone();

        let core_names = if cfg!(windows) {
            vec!["percepta-agent.exe", "percepta-agent-core.exe"]
        } else {
            vec!["percepta-agent", "percepta-agent-core"]
        };

        if let Ok(path) = which::which(&core_names[0]).or_else(|_| which::which(&core_names[1])) {
            let mut cmd = Command::new(path);
            cmd.arg("--renew").arg("--server").arg(&server);
            if cfg!(windows) {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            if cmd.spawn().is_ok() {
                self.status = "Renewal requested; waiting for approval...".to_string();
            } else {
                self.status = "Failed to start renewal request".to_string();
            }
        } else {
            self.status = "Agent executable not found in PATH.".to_string();
        }
    }

    fn install_service(&mut self) {
        self.status = "Requesting service installation...".to_string();
        let server_arg = self.server_input.clone();
        if let Ok(path) =
            which::which("percepta-agent.exe").or_else(|_| which::which("percepta-agent-core.exe"))
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let mut cmd = Command::new(path);
            cmd.creation_flags(CREATE_NO_WINDOW)
                .arg("--install-service");
            if !server_arg.is_empty() {
                cmd.arg("--server").arg(server_arg);
            }
            if cmd.spawn().is_ok() {
                self.status = "Service install command sent.".to_string();
            } else {
                self.status = "Failed to run install command.".to_string();
            }
        } else {
            self.status = "Agent executable not found.".to_string();
        }
    }

    fn uninstall_service(&mut self) {
        self.status = "Requesting service uninstallation...".to_string();
        if let Ok(path) =
            which::which("percepta-agent.exe").or_else(|_| which::which("percepta-agent-core.exe"))
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            if Command::new(path)
                .creation_flags(CREATE_NO_WINDOW)
                .arg("--uninstall-service")
                .spawn()
                .is_ok()
            {
                self.status = "Service uninstall command sent.".to_string();
            } else {
                self.status = "Failed to run uninstall command.".to_string();
            }
        } else {
            self.status = "Agent executable not found.".to_string();
        }
    }
}

impl eframe::App for AgentGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        Self::apply_visuals(ctx);

        // Check for discovery result
        if let Ok(Some(server_addr)) = self.discovery_receiver.try_recv() {
            self.server_input = server_addr;
            self.status = "Server discovered!".to_string();
            self.toast("Server discovered via mDNS");
        } else if let Ok(None) = self.discovery_receiver.try_recv() {
            self.status = "Discovery failed: No server found.".to_string();
            self.toast("Discovery failed");
        }

        // Keep animations alive.
        ctx.request_repaint_after(Duration::from_millis(16));

        let running = self.core_pid.is_some();
        let discovering = matches!(self.status.as_str(), "Discovering server..." | "Auto-enrolling..." | "Enrolling with OTK..." | "Starting auto-enrollment and connect..." | "Starting agent for server: " );

        egui::CentralPanel::default().show(ctx, |ui| {
            // Header
            egui::Frame::none()
                .fill(egui::Color32::from_rgb(12, 16, 40))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(36, 52, 92)))
                .rounding(egui::Rounding::same(16.0))
                .inner_margin(egui::Margin::symmetric(16, 14))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Percepta Agent").size(22.0).strong());
                            ui.add_space(2.0);
                            ui.label(
                                egui::RichText::new("Secure endpoint collector • gRPC mTLS • SOC-ready")
                                    .color(egui::Color32::from_rgb(170, 186, 220)),
                            );
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            Self::spinner(ui, discovering, ctx);
                            Self::status_dot(ui, running, ctx);
                            ui.add_space(6.0);
                            let pill_color = if running {
                                egui::Color32::from_rgb(46, 204, 113)
                            } else {
                                egui::Color32::from_rgb(255, 165, 2)
                            };
                            let text = if running { "RUNNING" } else { "IDLE" };
                            Self::pill(ui, text, pill_color);
                        });
                    });
                });

            ui.add_space(12.0);

            // Main content split
            ui.columns(2, |cols| {
                // Left: Connection + Controls
                cols[0].vertical(|ui| {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(9, 12, 24))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(30, 44, 78)))
                        .rounding(egui::Rounding::same(14.0))
                        .inner_margin(egui::Margin::symmetric(14, 12))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new("Connection").size(16.0).strong());
                            ui.add_space(8.0);

                            ui.label(egui::RichText::new("Server (gRPC)").strong());
                            let te = ui.add(
                                egui::TextEdit::singleline(&mut self.server_input)
                                    .hint_text("HOST:50051")
                                    .desired_width(f32::INFINITY),
                            );
                            if te.changed() {
                                // Just a visual cue; do not auto-save.
                            }
                            ui.add_space(8.0);

                            ui.horizontal(|ui| {
                                let save = ui.add_sized(
                                    [96.0, 32.0],
                                    egui::Button::new(egui::RichText::new("Save").strong()),
                                );
                                if save.clicked() {
                                    self.save_config();
                                    self.status = "Configuration saved.".to_string();
                                    self.toast("Saved config.json");
                                }

                                let discover = ui.add_sized(
                                    [110.0, 32.0],
                                    egui::Button::new(egui::RichText::new("Discover").strong()),
                                );
                                if discover.clicked() {
                                    self.status = "Discovering server...".to_string();
                                    Self::discover_server(self.discovery_sender.clone());
                                }
                            });

                            ui.add_space(10.0);
                            ui.separator();
                            ui.add_space(8.0);

                            ui.label(egui::RichText::new("Agent Controls").size(16.0).strong());
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                let start = ui.add_sized(
                                    [120.0, 36.0],
                                    egui::Button::new(egui::RichText::new("Start").strong()),
                                );
                                if start.clicked() {
                                    self.start_agent_core();
                                    self.toast("Starting agent...");
                                }

                                let stop = ui.add_enabled_sized(
                                    running,
                                    [120.0, 36.0],
                                    egui::Button::new(egui::RichText::new("Stop").strong()),
                                );
                                if stop.clicked() {
                                    if let Some(pid) = self.core_pid.take() {
                                        if cfg!(windows) {
                                            let _ = Command::new("taskkill")
                                                .arg("/F")
                                                .arg("/PID")
                                                .arg(pid.to_string())
                                                .output();
                                        }
                                        self.status = "Stopped agent process.".to_string();
                                        self.toast("Agent stopped");
                                    }
                                }
                            });
                        });

                    ui.add_space(12.0);

                    // Status card
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(9, 12, 24))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(30, 44, 78)))
                        .rounding(egui::Rounding::same(14.0))
                        .inner_margin(egui::Margin::symmetric(14, 12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Status").size(16.0).strong());
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.label(
                                        egui::RichText::new(format!("Config: {}", self.config_path.display()))
                                            .small()
                                            .color(egui::Color32::from_rgb(150, 168, 205)),
                                    );
                                });
                            });
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new(&self.status).color(egui::Color32::from_rgb(200, 215, 245)));
                            ui.add_space(6.0);

                            let cert_dir = default_cert_dir();
                            let agent_id = read_agent_id_for_display(&cert_dir)
                                .unwrap_or_else(|| "Not initialized".to_string());
                            let current_user = system_info::get_current_username();

                            ui.label(
                                egui::RichText::new(format!("Agent ID (stable): {}", agent_id))
                                    .small()
                                    .color(egui::Color32::from_rgb(150, 168, 205)),
                            );
                            ui.label(
                                egui::RichText::new(format!("Current user: {}", current_user))
                                    .small()
                                    .color(egui::Color32::from_rgb(150, 168, 205)),
                            );

                            ui.checkbox(&mut self.debug, "Debug mode");
                        });
                });

                // Right: Setup + Logs
                cols[1].vertical(|ui| {
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(9, 12, 24))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(30, 44, 78)))
                        .rounding(egui::Rounding::same(14.0))
                        .inner_margin(egui::Margin::symmetric(14, 12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Setup & Services").size(16.0).strong());
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.checkbox(&mut self.show_setup, "Show");
                                });
                            });
                            if self.show_setup {
                                ui.add_space(8.0);
                                ui.label(egui::RichText::new("OTK Enrollment").strong());
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.otk_input)
                                            .hint_text("One-Time Token")
                                            .desired_width(f32::INFINITY),
                                    );
                                    if ui.add_sized([132.0, 32.0], egui::Button::new(egui::RichText::new("Enroll").strong())).clicked() {
                                        self.run_enroll_with_otk();
                                        self.toast("Enrollment started");
                                    }
                                });
                                ui.add_space(8.0);
                                if ui.add_sized([160.0, 34.0], egui::Button::new(egui::RichText::new("Auto-Enroll & Start").strong())).clicked() {
                                    self.run_auto_enroll_and_start();
                                    self.toast("Auto-enroll & start");
                                }

                                ui.add_space(10.0);
                                ui.separator();
                                ui.add_space(10.0);

                                ui.label(egui::RichText::new("Certificate Renewal").strong());
                                if ui.add_sized([170.0, 34.0], egui::Button::new(egui::RichText::new("Request Renewal").strong())).clicked() {
                                    self.run_request_renewal();
                                    self.toast("Renewal requested");
                                }

                                ui.add_space(10.0);
                                ui.separator();
                                ui.add_space(10.0);

                                ui.label(egui::RichText::new("Windows Service").strong());
                                ui.horizontal(|ui| {
                                    if ui.add_sized([150.0, 32.0], egui::Button::new(egui::RichText::new("Install Service").strong())).clicked() {
                                        self.install_service();
                                        self.toast("Service install requested");
                                    }
                                    if ui.add_sized([160.0, 32.0], egui::Button::new(egui::RichText::new("Uninstall Service").strong())).clicked() {
                                        self.uninstall_service();
                                        self.toast("Service uninstall requested");
                                    }
                                });
                            }
                        });

                    ui.add_space(12.0);

                    egui::Frame::none()
                        .fill(egui::Color32::from_rgb(9, 12, 24))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(30, 44, 78)))
                        .rounding(egui::Rounding::same(14.0))
                        .inner_margin(egui::Margin::symmetric(14, 12))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("Logs").size(16.0).strong());
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.checkbox(&mut self.show_logs, "Show");
                                });
                            });
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if ui.add_sized([120.0, 30.0], egui::Button::new("Refresh")).clicked() {
                                    self.open_logs();
                                    self.last_log_refresh = Instant::now();
                                    self.toast("Logs refreshed");
                                }
                                ui.label(
                                    egui::RichText::new(format!("Last refresh: {:.0}s ago", self.last_log_refresh.elapsed().as_secs_f32()))
                                        .small()
                                        .color(egui::Color32::from_rgb(150, 168, 205)),
                                );
                            });

                            if self.show_logs {
                                ui.add_space(8.0);
                                egui::ScrollArea::vertical()
                                    .auto_shrink([false; 2])
                                    .max_height(260.0)
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::TextEdit::multiline(&mut self.logs)
                                                .desired_rows(14)
                                                .desired_width(f32::INFINITY)
                                                .font(egui::TextStyle::Monospace),
                                        );
                                    });
                            }
                        });
                });
            });

            // Toast overlay
            if let Some((msg, at)) = self.toast.clone() {
                if at.elapsed() > Duration::from_secs(3) {
                    self.toast = None;
                } else {
                    let alpha = (1.0 - (at.elapsed().as_secs_f32() / 3.0)).clamp(0.0, 1.0);
                    let bg = egui::Color32::from_rgba_unmultiplied(0, 212, 255, (55.0 * alpha) as u8);
                    let stroke = egui::Color32::from_rgba_unmultiplied(0, 212, 255, (120.0 * alpha) as u8);
                    let txt = egui::Color32::from_rgba_unmultiplied(230, 238, 255, (255.0 * alpha) as u8);

                    let area = egui::Area::new("toast")
                        .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-18.0, -18.0))
                        .interactable(false);
                    area.show(ctx, |ui| {
                        egui::Frame::none()
                            .fill(bg)
                            .stroke(egui::Stroke::new(1.0, stroke))
                            .rounding(egui::Rounding::same(12.0))
                            .inner_margin(egui::Margin::symmetric(12, 10))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(msg).color(txt).strong());
                            });
                    });
                }
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native(
        "Percepta Agent GUI",
        native_options,
        Box::new(|_cc| Box::new(AgentGui::default())),
    )
}
