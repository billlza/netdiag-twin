pub mod connectors;
pub mod error;
pub mod ingest;
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
};
