pub mod connectors;
pub mod dataset;
pub mod error;
pub mod evidence_bundle;
pub mod ingest;
pub mod lab;
pub mod ml;
pub mod models;
pub mod perf_budget;
pub mod pipeline;
pub mod recommendation;
pub mod report;
pub mod rules;
pub mod storage;
pub mod telemetry;
pub mod twin;

pub use error::{NetdiagError, Result};
pub use pipeline::{
    PipelineResult, WhatIfRequest, diagnose_file, diagnose_ingest, diagnose_ingest_with_whatif,
    diagnose_ingest_with_whatif_and_existing_model_dir, diagnose_ingest_with_whatif_and_model_dir,
};
