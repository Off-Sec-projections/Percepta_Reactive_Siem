use axum::{extract::State, http::HeaderMap, response::IntoResponse, Json};
use tracing::warn;

use crate::enroll::AppState;
use crate::local_net_scan;

/// GET /api/lan/topology
///
/// Returns a best-effort snapshot of LAN devices observed via agents' ARP tables.
pub async fn lan_topology(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    // Best-effort local discovery when agents aren't providing snapshots.
    // Uses passive neighbor tables by default; optionally uses arp-scan when available/capable.
    if state.lan_topology.should_run_server_scan(15).await {
        let scan = local_net_scan::scan_best_effort().await;
        let entries: Vec<(String, String)> =
            scan.neighbors.into_iter().map(|n| (n.ip, n.mac)).collect();
        state
            .lan_topology
            .observe_server_neighbors(&scan.gateway_ip, &entries)
            .await;
    }

    match state.lan_topology.snapshot(host).await {
        Ok(s) => Json(serde_json::json!({
            "status": "ok",
            "error": null,
            "server_host": s.server_host,
            "server_ip": s.server_ip,
            "gateway_ip": s.gateway_ip,
            "agents": s.agents,
            "devices": s.devices,
        }))
        .into_response(),
        Err(e) => {
            warn!("LAN topology snapshot failed: {e:#}");
            Json(serde_json::json!({
                "status": "error",
                "error": "lan topology unavailable",
                "server_host": host,
                "server_ip": "",
                "gateway_ip": "",
                "agents": [],
                "devices": [],
            }))
            .into_response()
        }
    }
}
