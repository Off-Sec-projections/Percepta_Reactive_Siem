use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let proto_file = "../shared/proto/siem_core.proto";
    let proto_dir = "../shared/proto";
    
    // Check if proto file exists
    if !std::path::Path::new(proto_file).exists() {
        eprintln!("Warning: Proto file not found at {}", proto_file);
        eprintln!("Creating a minimal proto file for compilation...");
        
        // Create a minimal proto file if it doesn't exist
        std::fs::create_dir_all(proto_dir)?;
        let minimal_proto = r#"
syntax = "proto3";
package percepta.siem.ingestion.v1;
import "google/protobuf/timestamp.proto";

message Event {
    google.protobuf.Timestamp event_time = 1;
    google.protobuf.Timestamp ingest_time = 2;
    string hash = 16;
}

message IngestionResponse {
    bool ack = 1;
    string event_id = 2;
    string message = 3;
}

message EnrollRequest {
    string agent_id = 1;
    string hostname = 2;
    string ip_address = 3;
}

message EnrollResponse {
    string agent_id = 1;
    string certificate_pem = 2;
    string private_key_pem = 3;
    string ca_certificate_pem = 4;
}

service CollectorService {
    rpc StreamEvents(stream Event) returns (stream IngestionResponse);
    rpc EnrollAgent(EnrollRequest) returns (EnrollResponse);
}
"#;
        std::fs::write(proto_file, minimal_proto)?;
    }
    
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .out_dir(out_dir)
        .compile(&[proto_file], &[proto_dir])?;

    // Tell cargo to rerun this build script if the proto file changes
    println!("cargo:rerun-if-changed={}", proto_file);
    
    Ok(())
}
