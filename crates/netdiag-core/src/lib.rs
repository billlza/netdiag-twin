mod artifact_root_migration;
pub mod benchmark;
#[cfg(unix)]
mod bounded_process;
pub mod connectors;
pub use connectors::authentication;
pub mod dataset;
pub mod error;
pub mod evidence_bundle;
mod feature_schema;
mod file_identity;
pub mod hil_review;
mod identifiers;
pub mod ingest;
pub mod lab;
mod managed_temp_directory;
mod metric_quality;
pub mod ml;
pub mod models;
pub mod perf_budget;
pub mod pilot;
pub mod pipeline;
mod python_runtime;
pub mod recommendation;
pub mod reliability;
pub mod report;
mod resource_limits;
pub mod rules;
pub mod storage;
pub mod strict_json;
pub mod telemetry;
pub mod twin;

pub use artifact_root_migration::migrate_legacy_artifact_root;
pub use error::{NetdiagError, Result};
pub use identifiers::validate_portable_id;
pub use pipeline::{
    PipelineResult, WhatIfRequest, diagnose_file, diagnose_ingest, diagnose_ingest_with_whatif,
    diagnose_ingest_with_whatif_and_connector_health,
    diagnose_ingest_with_whatif_and_existing_model_dir, diagnose_ingest_with_whatif_and_model_dir,
};
pub use resource_limits::{
    MAX_CONNECTOR_FLOW_METADATA_ITEMS, MAX_CONNECTOR_METADATA_STRING_BYTES,
    MAX_CONNECTOR_METADATA_TOTAL_STRING_BYTES, MAX_PCAP_PACKET_LIMIT,
};
