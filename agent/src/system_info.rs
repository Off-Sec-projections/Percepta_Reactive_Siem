use crate::percepta::event::{Agent, Host, Os as OsInfo};

pub fn get_current_username() -> String {
    // Prefer Windows-style USERNAME, fall back to USER.
    std::env::var("USERNAME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("USER").ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn get_primary_ip() -> Option<String> {
    use std::net::UdpSocket;

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

#[cfg(windows)]
fn get_system_macs_windows() -> Vec<String> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GET_ADAPTERS_ADDRESSES_FLAGS, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    let mut out = Vec::new();

    unsafe {
        let mut buf_len: u32 = 0;
        let _ = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GET_ADAPTERS_ADDRESSES_FLAGS(0),
            None,
            None,
            &mut buf_len,
        );
        if buf_len == 0 {
            return out;
        }

        let mut buf = vec![0u8; buf_len as usize];
        let first = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

        let ret = GetAdaptersAddresses(
            AF_UNSPEC.0 as u32,
            GET_ADAPTERS_ADDRESSES_FLAGS(0),
            None,
            Some(first),
            &mut buf_len,
        );
        if ret != 0 {
            return out;
        }

        let mut cur = first;
        while !cur.is_null() {
            let adapter = &*cur;

            // Prefer active adapters; skip loopback (IF_TYPE_SOFTWARE_LOOPBACK = 24)
            let if_type = adapter.IfType;
            if if_type == 24 {
                cur = adapter.Next;
                continue;
            }

            let len = adapter.PhysicalAddressLength as usize;
            if len >= 6 {
                let bytes = &adapter.PhysicalAddress[..len];
                let nonzero = bytes.iter().any(|b| *b != 0);
                if nonzero {
                    let mac = bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":");
                    if mac.len() == 17 {
                        out.push(mac);
                    }
                }
            }

            cur = adapter.Next;
        }
    }

    out.sort();
    out.dedup();
    out
}

#[cfg(target_os = "linux")]
fn get_system_macs_linux() -> Vec<String> {
    let mut out = Vec::new();

    let entries = match std::fs::read_dir("/sys/class/net") {
        Ok(e) => e,
        Err(_) => return out,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "lo" {
            continue;
        }

        let addr_path = entry.path().join("address");
        let mac = match std::fs::read_to_string(addr_path) {
            Ok(s) => s.trim().to_lowercase(),
            Err(_) => continue,
        };

        if mac.len() != 17 {
            continue;
        }
        if mac == "00:00:00:00:00:00" {
            continue;
        }

        out.push(mac);
    }

    out.sort();
    out.dedup();
    out
}

#[cfg(not(target_os = "linux"))]
fn get_system_macs_linux() -> Vec<String> {
    Vec::new()
}

pub fn get_system_macs() -> Vec<String> {
    let mut macs = get_system_macs_linux();

    #[cfg(windows)]
    {
        macs.extend(get_system_macs_windows());
    }

    macs.sort();
    macs.dedup();
    macs
}

pub fn get_primary_mac() -> Option<String> {
    get_system_macs().into_iter().next()
}

pub fn build_agent(agent_id: &str) -> Agent {
    let hostname = hostname::get()
        .unwrap_or_else(|_| std::ffi::OsString::from("unknown"))
        .to_string_lossy()
        .to_string();
    let ip = get_primary_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    let mac = get_primary_mac().unwrap_or_else(|| "unknown".to_string());
    let os_release = sys_info::os_release().unwrap_or_else(|_| "unknown".to_string());
    let os_type = sys_info::os_type().unwrap_or_else(|_| "unknown".to_string());

    Agent {
        id: agent_id.to_string(),
        hostname,
        ip,
        mac,
        version: env!("CARGO_PKG_VERSION").to_string(),
        os: Some(OsInfo {
            name: os_type,
            version: os_release.clone(),
            kernel: os_release,
        }),
    }
}

pub fn build_host(agent: &Agent) -> Host {
    let mut ips = Vec::new();
    if !agent.ip.trim().is_empty() {
        ips.push(agent.ip.clone());
    }

    let mut macs = get_system_macs();
    if macs.is_empty() {
        let m = agent.mac.trim();
        if !m.is_empty() && m != "unknown" {
            macs.push(agent.mac.clone());
        }
    }

    Host { ip: ips, mac: macs }
}
