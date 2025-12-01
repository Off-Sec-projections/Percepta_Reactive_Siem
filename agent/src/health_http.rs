//! Minimal HTTP server for agent health endpoint

use crate::system_info;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub async fn run_health_http_server(
    addr: &str,
    events_sent: &'static std::sync::atomic::AtomicU64,
    dedup_saved: &'static std::sync::atomic::AtomicU64,
) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Health HTTP endpoint unavailable ({addr}): {e} — agent continues without it");
            return;
        }
    };
    loop {
        let (mut socket, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let mut buf = [0u8; 1024];
        let n = match socket.read(&mut buf).await {
            Ok(0) => continue,
            Ok(n) => n,
            Err(_) => continue,
        };
        let req = String::from_utf8_lossy(&buf[..n]);
        if req.starts_with("GET /healthz") {
            let mut snapshot = system_info::collect_agent_health_snapshot();
            snapshot.events_sent = events_sent.load(std::sync::atomic::Ordering::Relaxed);
            snapshot.dedup_saved = dedup_saved.load(std::sync::atomic::Ordering::Relaxed);
            let body = serde_json::to_string_pretty(&snapshot).unwrap();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                body.len(), body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        } else {
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    }
}
