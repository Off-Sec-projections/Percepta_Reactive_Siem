use utoipa::OpenApi;

/// OpenAPI documentation for Percepta SIEM API
///
/// This generates interactive API documentation at /api/docs for investors,
/// partners, and integration teams.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Percepta SIEM API",
        version = "1.0.0",
        description = "Enterprise Security Information and Event Management (SIEM) Platform\n\n\
                       Percepta provides real-time threat detection, automated incident response,\n\
                       and compliance management for mid-market enterprises.",
        contact(
            name = "Off-Sec Projections",
            url = "https://percepta-siem.com",
            email = "support@percepta-siem.com"
        ),
        license(
            name = "Commercial License",
            url = "https://percepta-siem.com/license"
        )
    ),
    tags(
        (name = "authentication", description = "User authentication and session management"),
        (name = "alerts", description = "Security alert management and triage"),
        (name = "events", description = "Raw event search and investigation"),
        (name = "playbooks", description = "SOAR playbook automation"),
        (name = "cases", description = "Incident case management"),
        (name = "compliance", description = "Compliance framework mapping"),
        (name = "agents", description = "Agent fleet management")
    ),
    components(
        schemas(
            crate::auth::WhoAmIResponse,
        )
    )
)]
pub struct ApiDoc;
