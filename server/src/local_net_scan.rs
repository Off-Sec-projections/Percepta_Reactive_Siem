use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct Neighbor {
    pub ip: String,
    pub mac: String,
}

#[derive(Debug, Clone, Default)]
pub struct LocalScanResult {
    pub gateway_ip: String,
    pub neighbors: Vec<Neighbor>,
}

fn normalize_mac(s: &str) -> String {
    let m = s.trim().to_lowercase().replace('-', ":");
    if m == "00:00:00:00:00:00" {
        return String::new();
    }
    m
}

fn parse_proc_net_arp(text: &str) -> Vec<Neighbor> {
    // Format:
    // IP address       HW type     Flags       HW address            Mask     Device
    // 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let ip = parts[0].trim();
        let mac = normalize_mac(parts[3]);
        if ip.is_empty() || mac.is_empty() {
            continue;
        }
        out.push(Neighbor {
            ip: ip.to_string(),
            mac,
        });
    }
    out
}

fn parse_ip_neigh(text: &str) -> Vec<Neighbor> {
    // Example:
    // 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
    // 192.168.1.10 dev wlan0 lladdr aa:bb:... STALE
    // 192.168.1.12 dev wlan0 INCOMPLETE
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut mac = String::new();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        let ip = parts[0].to_string();
        for w in parts.windows(2) {
            if w[0] == "lladdr" {
                mac = normalize_mac(w[1]);
                break;
            }
        }
        if ip.is_empty() || mac.is_empty() {
            continue;
        }
        out.push(Neighbor { ip, mac });
    }
    out
}

fn parse_arp_scan_plain(text: &str) -> Vec<Neighbor> {
    // Typical `arp-scan --localnet` output includes header/footer.
    // We accept lines like: "192.168.1.1\taa:bb:cc:dd:ee:ff\tVendor"
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("Interface:")
            || line.starts_with("Starting")
            || line.starts_with("Ending")
            || line.contains("packets received")
        {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let ip = parts[0].trim();
        let mac = normalize_mac(parts[1]);
        if ip.is_empty() || mac.is_empty() {
            continue;
        }
        out.push(Neighbor {
            ip: ip.to_string(),
            mac,
        });
    }
    out
}

async fn run_cmd_capture(prog: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    let fut = cmd.output();
    let out = match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => v,
        _ => return None,
    };
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

async fn get_default_gateway_ip() -> String {
    // Parse: `ip route show default`
    // Example: default via 192.168.1.1 dev wlan0 proto dhcp metric 600
    let Some(text) = run_cmd_capture(
        "ip",
        &["route", "show", "default"],
        Duration::from_millis(700),
    )
    .await
    else {
        return String::new();
    };
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for w in parts.windows(2) {
            if w[0] == "via" {
                return w[1].trim().to_string();
            }
        }
    }
    String::new()
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let s = v.trim();
            s == "1" || s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

async fn get_default_route_dev() -> String {
    // Parse: `ip route show default`
    // Example: default via 192.168.1.1 dev wlan0 proto dhcp metric 600
    let Some(text) = run_cmd_capture(
        "ip",
        &["route", "show", "default"],
        Duration::from_millis(700),
    )
    .await
    else {
        return String::new();
    };
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for w in parts.windows(2) {
            if w[0] == "dev" {
                return w[1].trim().to_string();
            }
        }
    }
    String::new()
}

async fn get_ipv4_cidr_for_dev(dev: &str) -> Option<(Ipv4Addr, u8)> {
    // Parse: `ip -o -4 addr show dev <dev> scope global`
    // Example: 2: wlan0    inet 192.168.10.11/24 brd 192.168.10.255 scope global dynamic noprefixroute wlan0
    let text = run_cmd_capture(
        "ip",
        &["-o", "-4", "addr", "show", "dev", dev, "scope", "global"],
        Duration::from_millis(700),
    )
    .await?;
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        for w in parts.windows(2) {
            if w[0] == "inet" {
                let cidr = w[1].trim();
                let (ip_s, prefix_s) = cidr.split_once('/')?;
                let ip: Ipv4Addr = ip_s.parse().ok()?;
                let prefix: u8 = prefix_s.parse().ok()?;
                if prefix == 0 || prefix > 32 {
                    return None;
                }
                return Some((ip, prefix));
            }
        }
    }
    None
}

fn ipv4_range_for_prefix(ip: Ipv4Addr, prefix: u8) -> Option<(u32, u32)> {
    // Returns inclusive [start, end] range of the subnet.
    let ip_u = u32::from(ip);
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        (!0u32) << (32 - prefix)
    };
    let net = ip_u & mask;
    let bcast = net | !mask;
    Some((net, bcast))
}

static LAST_PING_SWEEP_MS: AtomicU64 = AtomicU64::new(0);

fn should_run_ping_sweep(now_ms: u64) -> bool {
    // Default: at most once every 5 minutes.
    let min_interval_ms = env_u64("PERCEPTA_LAN_PING_SWEEP_MIN_INTERVAL_MS", 300_000);
    let last = LAST_PING_SWEEP_MS.load(Ordering::Relaxed);
    now_ms.saturating_sub(last) >= min_interval_ms
}

fn mark_ping_sweep(now_ms: u64) {
    LAST_PING_SWEEP_MS.store(now_ms, Ordering::Relaxed);
}

async fn ping_once(ip: Ipv4Addr) {
    // Best-effort; ignore failures.
    let _ = run_cmd_capture(
        "ping",
        &["-n", "-c", "1", "-W", "1", &ip.to_string()],
        Duration::from_millis(1200),
    )
    .await;
}

async fn ping_sweep_ipv4_subnet(ip: Ipv4Addr, prefix: u8, gateway_ip: Option<Ipv4Addr>) {
    // Noble default: bounded + throttled, and avoids huge scans.
    // Only sweep for /24 or smaller subnets (i.e., prefix >= 24) to prevent big network spam.
    if prefix < 24 {
        return;
    }
    let Some((start, end)) = ipv4_range_for_prefix(ip, prefix) else {
        return;
    };

    // Cap max hosts (including network/broadcast) to 256.
    if end.saturating_sub(start) > 255 {
        return;
    }

    let concurrency = env_u64("PERCEPTA_LAN_PING_SWEEP_CONCURRENCY", 32).clamp(1, 128) as usize;

    let me = u32::from(ip);
    let gw = gateway_ip.map(u32::from);

    let mut ips: Vec<Ipv4Addr> = Vec::new();
    for cur in start..=end {
        if cur == start || cur == end {
            continue; // skip network/broadcast
        }
        if cur == me {
            continue;
        }
        if let Some(gw_u) = gw {
            if cur == gw_u {
                continue;
            }
        }
        ips.push(Ipv4Addr::from(cur));
    }

    // Chunked concurrency to keep it gentle.
    for chunk in ips.chunks(concurrency) {
        let mut tasks = Vec::with_capacity(chunk.len());
        for &ip in chunk {
            tasks.push(tokio::spawn(ping_once(ip)));
        }
        for t in tasks {
            let _ = t.await;
        }
    }
}

pub async fn scan_best_effort() -> LocalScanResult {
    let mut all: Vec<Neighbor> = Vec::new();

    let gateway_ip = get_default_gateway_ip().await;

    // 1) Passive: /proc/net/arp
    if let Ok(text) = tokio::fs::read_to_string("/proc/net/arp").await {
        all.extend(parse_proc_net_arp(&text));
    }

    // 2) Passive: ip neigh
    if let Some(text) = run_cmd_capture("ip", &["neigh", "show"], Duration::from_millis(700)).await
    {
        all.extend(parse_ip_neigh(&text));
    }

    // 3) Active (optional/best-effort): arp-scan --localnet
    // This typically requires CAP_NET_RAW. If the binary is present AND allowed, it gives full LAN discovery.
    if std::env::var("PERCEPTA_LAN_ARP_SCAN")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
    {
        if let Some(text) = run_cmd_capture(
            "arp-scan",
            &["--localnet", "--quiet", "--ignoredups"],
            Duration::from_secs(2),
        )
        .await
        {
            all.extend(parse_arp_scan_plain(&text));
        }
    }

    // 4) Noble fallback: gentle ping sweep to populate ARP when discovery is too sparse.
    // This helps when no agents are connected and arp-scan isn't installed/capable.
    // It is throttled and bounded to avoid network spam.
    if env_bool("PERCEPTA_LAN_PING_SWEEP", true) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Only trigger when we have basically no neighbors besides the gateway.
        let unique_ips = {
            let mut s = std::collections::HashSet::new();
            for n in &all {
                s.insert(n.ip.as_str());
            }
            s.len()
        };
        if unique_ips <= 1 && should_run_ping_sweep(now_ms) {
            let dev = get_default_route_dev().await;
            if !dev.is_empty() {
                if let Some((host_ip, prefix)) = get_ipv4_cidr_for_dev(&dev).await {
                    let gw_v4 = gateway_ip.parse::<Ipv4Addr>().ok();
                    mark_ping_sweep(now_ms);
                    ping_sweep_ipv4_subnet(host_ip, prefix, gw_v4).await;

                    // Re-read passive sources after sweep.
                    if let Ok(text) = tokio::fs::read_to_string("/proc/net/arp").await {
                        all.extend(parse_proc_net_arp(&text));
                    }
                    if let Some(text) =
                        run_cmd_capture("ip", &["neigh", "show"], Duration::from_millis(700)).await
                    {
                        all.extend(parse_ip_neigh(&text));
                    }
                }
            }
        }
    }

    // De-dupe: prefer latest mac for ip
    let mut by_ip: HashMap<String, Neighbor> = HashMap::new();
    for n in all {
        let ip = n.ip.trim().to_string();
        let mac = n.mac.trim().to_string();
        if ip.is_empty() || mac.is_empty() {
            continue;
        }
        by_ip.insert(ip.clone(), Neighbor { ip, mac });
    }

    let mut neighbors: Vec<Neighbor> = by_ip.into_values().collect();
    neighbors.sort_by(|a, b| a.ip.cmp(&b.ip));

    LocalScanResult {
        gateway_ip,
        neighbors,
    }
}
