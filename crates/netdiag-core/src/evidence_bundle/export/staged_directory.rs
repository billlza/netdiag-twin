use super::{ExportRequest, ReportedRoot};
use crate::error::Result;
use crate::evidence_bundle::context::EvidenceContext;
use crate::evidence_bundle::prepared::validate_requested_extras;
use crate::evidence_bundle::{EvidenceBundleExtraFile, EvidenceBundleManifest};
use crate::storage::{ensure_run_has_no_pending_transaction, with_run_snapshot_locks};
use chrono::Utc;
use std::path::Path;

pub(crate) fn export(
    staged_artifact_root: &Path,
    published_artifact_root: &Path,
    run_id: &str,
    staged_output: &Path,
    published_output: &Path,
    context: EvidenceContext,
    extra_files: &[EvidenceBundleExtraFile],
) -> Result<EvidenceBundleManifest> {
    validate_requested_extras(extra_files)?;
    with_run_snapshot_locks(staged_artifact_root, run_id, &[staged_output], |location| {
        ensure_run_has_no_pending_transaction(&location.run_dir, run_id)?;
        super::export(ExportRequest {
            location,
            run_id,
            write_target: staged_output,
            manifest_output: published_output,
            created_at: Utc::now(),
            context,
            extra_files,
            allow_pending_transaction: false,
            source_overrides: &[],
            reported_root: Some(ReportedRoot {
                staged: staged_artifact_root,
                published: published_artifact_root,
            }),
        })
    })
}
