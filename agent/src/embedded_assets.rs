//! Embedded assets bundled into the agent binary for configurationless deployments.

/// Return the embedded CA certificate (PEM) shipped with the agent, if available.
pub fn embedded_ca_cert() -> Option<&'static str> {
    // For GUI-only Windows builds, CA comes from portal bundle
    #[cfg(all(target_os = "windows", feature = "gui"))]
    {
        return None;
    }
    
    #[cfg(not(all(target_os = "windows", feature = "gui")))]
    {
        const PEM: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../certs/ca_cert.pem"));
        let trimmed = PEM.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PEM)
        }
    }
}

/// Return the embedded one-time enrollment token baked into the agent.
pub fn embedded_otk() -> Option<&'static str> {
    const OTK: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../shared/assets/embedded_otk.txt"
    ));
    let trimmed = OTK.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
