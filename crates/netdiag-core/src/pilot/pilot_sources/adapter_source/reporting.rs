use crate::error::NetdiagError;
use crate::models::{ConnectorHealthSnapshot, IngestResult};
use crate::pilot::PilotSource;
use crate::pilot::adapter_contract::adapter_stderr_excerpt;
use std::path::Path;

pub(super) fn adapter_health(
    source: &PilotSource,
    ingest: &IngestResult,
) -> ConnectorHealthSnapshot {
    ConnectorHealthSnapshot::from_ingest("adapter-sample", &source.name, &source.name, ingest)
}

pub(super) fn adapter_exit_error(
    phase: &str,
    adapter: &Path,
    output: &std::process::Output,
    redaction_values: &[String],
) -> NetdiagError {
    let excerpt = adapter_stderr_excerpt(&output.stderr, redaction_values);
    NetdiagError::Connector(format!(
        "adapter process failed (phase={phase}, adapter={:?}, status={}, stderr_excerpt={excerpt:?})",
        adapter.display().to_string(),
        output.status
    ))
}
