// Build script for percepta-agent
// This script runs automatically during `cargo build` to generate Rust code from protobuf definitions.
// The generated code will be available as modules in the compiled crate.

use std::io::Result;

fn main() -> Result<()> {
    // Tell cargo to rerun this build script if the proto file changes
    println!("cargo:rerun-if-changed=../shared/proto/siem_core.proto");

    // Configure tonic-build to generate client-only code with serde support
    tonic_build::configure()
        .build_server(false) // Generate client stubs only
        .build_client(true) // Enable client code generation
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]") // Add serde derives to all types
        .type_attribute(
            "google.protobuf.Timestamp",
            "#[serde(default, skip_serializing_if = \"Option::is_none\")]",
        ) // Handle Timestamp serde
        .field_attribute("event_time", "#[serde(skip)]") // Skip timestamp fields for serialization
        .field_attribute("ingest_time", "#[serde(skip)]") // Skip timestamp fields for serialization
        .compile(
            &["../shared/proto/siem_core.proto"], // Proto files to compile
            &["../shared/proto"],                 // Include directories
        )?;

    Ok(())
}
