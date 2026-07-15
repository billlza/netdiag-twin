use super::context::EvidenceContext;
use super::prepared::{PrepareRequest, PreparedEvidenceSnapshots, validate_requested_extras};
use super::{BundleArchive, EvidenceBundleExtraFile, EvidenceBundleManifest};
use crate::error::{IoContext, Result};
use crate::storage::{
    RunLocation, ensure_run_has_no_pending_transaction, with_run_snapshot_locks,
    write_file_atomically,
};
use chrono::{DateTime, Utc};
use std::path::Path;

mod source_overrides;
mod staged_directory;
pub(crate) use source_overrides::EvidenceSourceOverride;
pub(super) use source_overrides::SourceOverrides;
pub(crate) use staged_directory::export as export_staged_directory;

pub(crate) fn export_for_transaction(
    location: &RunLocation,
    run_id: &str,
    staged_output: &Path,
    published_output: &Path,
    created_at: DateTime<Utc>,
    source_overrides: &[EvidenceSourceOverride],
) -> Result<EvidenceBundleManifest> {
    export(ExportRequest {
        location,
        run_id,
        write_target: staged_output,
        manifest_output: published_output,
        created_at,
        context: EvidenceContext::Lab,
        extra_files: &[],
        allow_pending_transaction: true,
        source_overrides,
        reported_root: None,
    })
}

pub(super) fn export_standard(
    artifact_root: &Path,
    run_id: &str,
    output: &Path,
    context: EvidenceContext,
    extra_files: &[EvidenceBundleExtraFile],
) -> Result<EvidenceBundleManifest> {
    export_standard_with_observer(artifact_root, run_id, output, context, extra_files, || {})
}

pub(super) fn export_standard_with_observer(
    artifact_root: &Path,
    run_id: &str,
    output: &Path,
    context: EvidenceContext,
    extra_files: &[EvidenceBundleExtraFile],
    after_snapshots: impl FnOnce(),
) -> Result<EvidenceBundleManifest> {
    export_standard_with_snapshot_observers(
        artifact_root,
        run_id,
        output,
        context,
        extra_files,
        |_| {},
        |_| after_snapshots(),
    )
}

pub(super) fn export_standard_with_snapshot_observers(
    artifact_root: &Path,
    run_id: &str,
    output: &Path,
    context: EvidenceContext,
    extra_files: &[EvidenceBundleExtraFile],
    after_store_created: impl FnOnce(&Path),
    after_snapshots: impl FnOnce(&Path),
) -> Result<EvidenceBundleManifest> {
    validate_requested_extras(extra_files)?;
    with_run_snapshot_locks(artifact_root, run_id, &[output], |location| {
        ensure_run_has_no_pending_transaction(&location.run_dir, run_id)?;
        export_with_observers(
            ExportRequest {
                location,
                run_id,
                write_target: output,
                manifest_output: output,
                created_at: Utc::now(),
                context,
                extra_files,
                allow_pending_transaction: false,
                source_overrides: &[],
                reported_root: None,
            },
            after_store_created,
            after_snapshots,
        )
    })
}

struct ExportRequest<'a> {
    location: &'a RunLocation,
    run_id: &'a str,
    write_target: &'a Path,
    manifest_output: &'a Path,
    created_at: DateTime<Utc>,
    context: EvidenceContext,
    extra_files: &'a [EvidenceBundleExtraFile],
    allow_pending_transaction: bool,
    source_overrides: &'a [EvidenceSourceOverride],
    reported_root: Option<ReportedRoot<'a>>,
}

#[derive(Clone, Copy)]
struct ReportedRoot<'a> {
    staged: &'a Path,
    published: &'a Path,
}

fn export(request: ExportRequest<'_>) -> Result<EvidenceBundleManifest> {
    export_with_observers(request, |_| {}, |_| {})
}

fn export_with_observers(
    request: ExportRequest<'_>,
    after_store_created: impl FnOnce(&Path),
    after_snapshots: impl FnOnce(&Path),
) -> Result<EvidenceBundleManifest> {
    let ExportRequest {
        location,
        run_id,
        write_target,
        manifest_output,
        created_at,
        context,
        extra_files,
        allow_pending_transaction,
        source_overrides,
        reported_root,
    } = request;
    validate_requested_extras(extra_files)?;
    let source_overrides = SourceOverrides::new(source_overrides)?;
    let mut snapshots = PreparedEvidenceSnapshots::capture_with_store_observer(
        PrepareRequest {
            location,
            run_id,
            context,
            requested_extras: extra_files,
            allow_pending_transaction,
            source_overrides: &source_overrides,
        },
        after_store_created,
    )?;
    if let Some(reported_root) = reported_root
        && let Err(error) =
            snapshots.rewrite_reported_root(reported_root.staged, reported_root.published)
    {
        return snapshots.finish(Err(error));
    }
    after_snapshots(snapshots.directory_path());
    let operation = write_file_atomically(write_target, "zip", |file| {
        let file = file.try_clone().with_path(write_target)?;
        let mut archive = BundleArchive::new(file, run_id, manifest_output, created_at);
        archive.add_readme(run_id)?;
        archive.add_snapshot_files(&mut snapshots.files)?;
        archive.add_topology_snapshots(snapshots.report_mut()?)?;
        archive.finish(write_target)
    })
    .map(|(_, manifest)| manifest);
    snapshots.finish(operation)
}
