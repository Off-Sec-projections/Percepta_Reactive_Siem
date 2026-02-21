use std::sync::Arc;

use openssl::nid::Nid;
use tonic::{Request, Status};
use tracing::{debug, warn};

use crate::certificate_authority::CAService;

/// Extract the peer certificate DER bytes from the tonic request.
///
/// This is synchronous and cheap; callers should do this **before** any `.await`
/// to avoid holding a `Request<Streaming<_>>` reference across an await boundary.
pub fn peer_cert_der<T>(request: &Request<T>) -> Option<Vec<u8>> {
    request
        .peer_certs()
        .and_then(|certs| certs.first().cloned())
        .map(|cert| cert.as_ref().to_vec())
}

/// Validate the peer certificate (CRL check) and extract the agent CN.
///
/// - In mTLS mode, tonic exposes the presented peer certs; pass the DER bytes in.
/// - In plaintext mode (tests/dev), pass `None`; we accept and return `None`.
pub async fn validate_peer_der_and_get_cn(
    peer_cert_der: Option<Vec<u8>>,
    ca_service: &Arc<CAService>,
) -> Result<Option<String>, Status> {
    let Some(peer_cert_der) = peer_cert_der else {
        debug!("No peer certificate presented; accepting stream.");
        return Ok(None);
    };

    let cert = openssl::x509::X509::from_der(&peer_cert_der).map_err(|_| {
        warn!("Could not parse peer certificate from mTLS connection.");
        Status::invalid_argument("Invalid peer certificate")
    })?;

    let serial_bn = cert
        .serial_number()
        .to_bn()
        .map_err(|e| Status::internal(format!("Failed to read serial: {e}")))?;
    let serial_dec = serial_bn
        .to_dec_str()
        .map_err(|e| Status::internal(format!("Failed to format serial: {e}")))?;

    if ca_service.is_certificate_revoked(&serial_dec).await {
        warn!(
            "Rejecting connection from revoked certificate. Serial: {}",
            serial_dec
        );
        return Err(Status::permission_denied("Certificate has been revoked."));
    }

    debug!(
        "Peer certificate is valid and not revoked. Serial: {}",
        serial_dec
    );

    // Extract CN
    for entry in cert.subject_name().entries() {
        if entry.object().nid() == Nid::COMMONNAME {
            if let Ok(cn) = entry.data().as_utf8() {
                return Ok(Some(cn.to_string()));
            }
        }
    }

    Ok(None)
}
