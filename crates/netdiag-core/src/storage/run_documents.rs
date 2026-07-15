use super::typed_json::{
    MAX_RUN_MANIFEST_BYTES, MAX_RUN_REPORT_BYTES, read_optional_stable_json_bounded,
    read_required_stable_json_bounded,
};
use super::{RunLocation, ensure_run_has_no_pending_transaction, resolve_run_location};
use crate::error::{NetdiagError, Result};
use crate::models::RunManifest;
use crate::report::Report;
use std::path::Path;

pub fn read_manifest(artifact_root: impl AsRef<Path>, run_id: &str) -> Result<RunManifest> {
    let location = resolve_run_location(artifact_root, run_id)?;
    ensure_run_has_no_pending_transaction(&location.run_dir, run_id)?;
    let manifest = read_required_manifest_at(&location.run_dir.join("manifest.json"), &location)?;
    if manifest.run_id != run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "manifest run id {} does not match requested run id {run_id}",
            manifest.run_id
        )));
    }
    Ok(manifest)
}

pub fn read_report(artifact_root: impl AsRef<Path>, run_id: &str) -> Result<Report> {
    let location = resolve_run_location(artifact_root, run_id)?;
    ensure_run_has_no_pending_transaction(&location.run_dir, run_id)?;
    let path = location.run_dir.join("report.json");
    let report: Report =
        read_required_stable_json_bounded(&path, MAX_RUN_REPORT_BYTES, "run report")?;
    if report.run_id != run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "report run id {} does not match requested run id {run_id}",
            report.run_id
        )));
    }
    Ok(report)
}

pub(crate) fn read_manifest_at_location(location: &RunLocation) -> Result<RunManifest> {
    read_required_manifest_at(&location.run_dir.join("manifest.json"), location)
}

pub(super) fn read_required_manifest_at(
    path: &Path,
    location: &RunLocation,
) -> Result<RunManifest> {
    let manifest = read_required_stable_json_bounded(path, MAX_RUN_MANIFEST_BYTES, "run manifest")?;
    ensure_manifest_matches_run_dir(&manifest, &location.run_dir)?;
    Ok(manifest)
}

pub(super) fn read_optional_manifest_at(
    path: &Path,
    run_dir: &Path,
) -> Result<Option<RunManifest>> {
    let manifest = read_optional_stable_json_bounded(path, MAX_RUN_MANIFEST_BYTES, "run manifest")?;
    if let Some(manifest) = &manifest {
        ensure_manifest_matches_run_dir(manifest, run_dir)?;
    }
    Ok(manifest)
}

pub(super) fn ensure_manifest_matches_run_dir(
    manifest: &RunManifest,
    run_dir: &Path,
) -> Result<()> {
    super::typed_json::ensure_manifest_artifact_limit(manifest)?;
    crate::identifiers::validate_portable_id("manifest run id", &manifest.run_id)?;
    let directory_run_id = run_dir
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "run directory has no portable file name: {}",
                run_dir.display()
            ))
        })?;
    if manifest.run_id != directory_run_id {
        return Err(NetdiagError::InvalidTrace(format!(
            "manifest run id {} does not match directory {directory_run_id}",
            manifest.run_id
        )));
    }
    Ok(())
}
