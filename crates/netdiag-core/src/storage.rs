use crate::error::{IoContext, NetdiagError, Result};
use crate::models::{
    ConnectorHealthSnapshot, ConnectorHealthStatus, HilState, MeasurementQualitySummary,
    MetricProvenance, MetricQuality, MetricQualityChange, Recommendation,
    RecommendationStateChange, RunArtifactEntry, RunComparison, RunEvidenceSummary,
    RunHistoryEntry, RunHistoryFilter, RunIndexEntry, RunTimelineEvent, missing_metric_names,
    percent_delta,
};
use crate::report::Report;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

mod action_verification_transaction;
mod artifact_root;
mod atomic_directory;
mod atomic_file;
mod file_lock;
pub(crate) mod hil_transaction;
mod locations;
mod path_status;
mod run_documents;
mod run_snapshot_locks;
mod stable_read;
pub(crate) mod typed_json;

#[cfg(test)]
mod tests;

/// Compatibility alias for the canonical [`crate::hil_review`] application service.
///
/// This alias is retained for one migration cycle and will be removed in the next
/// breaking release. New code must import these items from [`crate::hil_review`].
pub use crate::hil_review::{HilReviewOutcome, review_recommendation};
#[cfg(test)]
pub(crate) use action_verification_transaction::fail_next_manifest_update as fail_next_action_verification_manifest_update;
pub(crate) use action_verification_transaction::{
    RecoveredActionVerificationTransaction, action_verification_journal_path,
    ensure_no_pending_transaction as ensure_no_pending_action_verification_transaction,
    publish_transaction as publish_action_verification_transaction,
    recover_transaction as recover_action_verification_transaction,
};
pub(crate) use artifact_root::{
    ArtifactRootCapability, OwnedArtifactRoot, abandon_run_publication_not_published,
    begin_run_publication, complete_run_publication, create_root_bound_staged_directory,
    discard_root_bound_staged_directory, finish_root_bound_staged_directory,
    migrate_legacy_artifact_root_with_validator, prepare_artifact_root,
    reconcile_nested_run_publication_index, reconcile_run_publication_index,
    with_artifact_root_capability, with_owned_artifact_root,
};
pub use artifact_root::{
    clear_run_history, ensure_artifact_root_owned, validate_artifact_root_path,
};
pub(crate) use atomic_directory::{StagedAtomicDirectory, preserve_published_directory};
pub(crate) use atomic_file::{
    BoundAtomicFileTarget, BoundFileRemovalFailure, NoClobberDisposition, StagedAtomicFile,
    remove_bound_file_durably, remove_file_durably, write_file_atomically,
    write_file_atomically_noclobber_or_existing_to_bound, write_file_atomically_to_bound,
};
#[cfg(test)]
pub(crate) use file_lock::exclusive_file_lock_path;
pub use file_lock::with_exclusive_file_lock;
pub(crate) use file_lock::{
    CoordinationParentScope, coordination_parent_scope, prospective_component_alias,
    with_exclusive_bound_file_lock, with_exclusive_file_locks,
};
pub(crate) use hil_transaction::ensure_no_pending_transaction as ensure_run_has_no_pending_hil_transaction;
pub(crate) use locations::MAX_DISCOVERED_RUN_LOCATIONS;
pub(crate) use locations::find_run_location;
pub use locations::{
    RunLocation, list_run_locations, resolve_run_location, resolve_stored_path, run_dir,
};
pub(crate) use path_status::{PathStatus, optional_regular_file, path_status};
pub(crate) use run_documents::read_manifest_at_location;
pub use run_documents::{read_manifest, read_report};
pub(crate) use run_snapshot_locks::{
    SnapshotOutputTarget, with_resolved_run_snapshot_locks, with_run_snapshot_locks,
    with_transaction_target_locks,
};
pub(crate) use stable_read::bound::{
    read_stable_regular_file_bounded_at, read_stable_regular_file_bounded_at_with,
};
pub(crate) use stable_read::checkpoint::read_stable_regular_file_bounded_with_checkpoint;
pub use stable_read::read_stable_regular_file_bounded;
pub(crate) use stable_read::sha256_stable_regular_file_bounded;
pub(crate) use stable_read::sha256_stable_regular_file_bounded_at;
pub(crate) use typed_json::ensure_manifest_artifact_limit;

pub(crate) fn ensure_run_has_no_pending_transaction(run_dir: &Path, run_id: &str) -> Result<()> {
    hil_transaction::ensure_no_pending_transaction(run_dir, run_id)?;
    action_verification_transaction::ensure_no_pending_transaction(run_dir, run_id)
}

pub fn save_json<T: Serialize + ?Sized>(path: impl AsRef<Path>, value: &T) -> Result<PathBuf> {
    save_json_atomic(path, value)
}

pub fn save_json_atomic<T: Serialize + ?Sized>(
    path: impl AsRef<Path>,
    value: &T,
) -> Result<PathBuf> {
    let path = path.as_ref();
    write_file_atomically(path, "json", |file| {
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, value)?;
        writer.flush().with_path(path)?;
        Ok(())
    })
    .map(|(path, ())| path)
}

pub fn read_json(path: impl AsRef<Path>) -> Result<Value> {
    let path = path.as_ref();
    let bytes = read_stable_regular_file_bounded(path, typed_json::MAX_GENERIC_JSON_BYTES)?
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("JSON document is missing: {}", path.display()))
        })?;
    crate::strict_json::parse_unique_value(&bytes).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "invalid JSON document at {}: {}",
            path.display(),
            crate::strict_json::error_summary(&source)
        ))
    })
}

pub fn list_run_index(artifact_root: impl AsRef<Path>) -> Result<Vec<RunIndexEntry>> {
    let artifact_root = artifact_root.as_ref();
    let index_path = artifact_root.join("run_index.json");
    let mut entries = match typed_json::read_optional_stable_json_bounded::<Vec<RunIndexEntry>>(
        &index_path,
        typed_json::MAX_RUN_INDEX_BYTES,
        "run index",
    )? {
        Some(entries) => {
            typed_json::ensure_collection_limit(
                "run index",
                entries.len(),
                typed_json::MAX_RUN_INDEX_ENTRIES,
            )?;
            entries
        }
        None => scan_run_manifests(artifact_root)?,
    };
    let mut seen = BTreeSet::new();
    for entry in &entries {
        crate::identifiers::validate_portable_id("indexed run id", &entry.run_id)?;
        if !seen.insert(entry.run_id.clone()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate run id in run index: {}",
                entry.run_id
            )));
        }
    }
    for location in list_run_locations(artifact_root)? {
        let manifest_path = location.run_dir.join("manifest.json");
        let Some(manifest) =
            run_documents::read_optional_manifest_at(&manifest_path, &location.run_dir)?
        else {
            continue;
        };
        if !seen.insert(manifest.run_id.clone()) {
            continue;
        }
        let status = read_report(location.artifact_root.clone(), &manifest.run_id)?
            .hil_summary
            .run_status()
            .to_string();
        let stored_run_dir = location.run_dir.strip_prefix(artifact_root).map_err(|_| {
            NetdiagError::InvalidTrace(format!(
                "run directory is outside the artifact root: {}",
                location.run_dir.display()
            ))
        })?;
        entries.push(RunIndexEntry {
            run_id: manifest.run_id,
            sample: manifest.sample,
            created_at: manifest.created_at,
            status,
            run_dir: stored_run_dir.display().to_string(),
        });
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at));
    Ok(entries)
}

pub fn list_run_history(
    artifact_root: impl AsRef<Path>,
    limit: usize,
) -> Result<Vec<RunHistoryEntry>> {
    list_run_history_filtered(artifact_root, RunHistoryFilter::default(), limit)
}

pub fn list_run_history_filtered(
    artifact_root: impl AsRef<Path>,
    filter: RunHistoryFilter,
    limit: usize,
) -> Result<Vec<RunHistoryEntry>> {
    let artifact_root = artifact_root.as_ref();
    let mut entries = Vec::new();
    for index in list_run_index(artifact_root)? {
        let entry = run_history_entry(artifact_root, index)?;
        if !run_history_matches(&entry, &filter) {
            continue;
        }
        entries.push(entry);
        if entries.len() >= limit {
            break;
        }
    }
    Ok(entries)
}

pub fn list_run_timeline(
    artifact_root: impl AsRef<Path>,
    filter: RunHistoryFilter,
    limit: usize,
) -> Result<Vec<RunTimelineEvent>> {
    Ok(list_run_history_filtered(artifact_root, filter, limit)?
        .into_iter()
        .map(|entry| RunTimelineEvent {
            run_id: entry.run_id,
            created_at: entry.created_at,
            sample: entry.sample,
            status: entry.status,
            root_causes: entry.root_causes,
            diagnosis_status: entry.diagnosis_status,
            uncertainty_reason_codes: entry.uncertainty_reason_codes,
            ml_top_label: entry.ml_top_label,
            quality_status: entry.quality_status,
        })
        .collect())
}

pub fn run_history_entry(
    artifact_root: impl AsRef<Path>,
    index: RunIndexEntry,
) -> Result<RunHistoryEntry> {
    let artifact_root = artifact_root.as_ref();
    crate::identifiers::validate_portable_id("run id", &index.run_id)?;
    let location = resolve_run_location(artifact_root, &index.run_id)?;
    ensure_indexed_run_dir_matches(artifact_root, &index.run_dir, &location.run_dir)?;
    let run_dir_path = location.run_dir.clone();
    let manifest = read_manifest(&location.artifact_root, &index.run_id)?;
    let report = read_report(&location.artifact_root, &index.run_id)?;
    ensure_index_matches_documents(&index, &manifest, &report)?;
    let artifact_count = manifest
        .artifact_paths
        .keys()
        .filter(|key| key.as_str() != "run_id")
        .count();
    let history_fields = report_history_fields(&report);
    let measurement_quality = report.measurement_quality.clone();
    let connector_health = read_connector_health(&location.artifact_root, &index.run_id)?;
    let quality = connector_health
        .as_ref()
        .map(|health| health.quality)
        .unwrap_or_else(|| MeasurementQualitySummary::from_provenance(&measurement_quality));
    let quality_status = connector_health
        .as_ref()
        .map(|health| health.status)
        .unwrap_or_else(|| health_status_for_summary(quality, measurement_quality.len()));
    let warning_count = connector_health
        .as_ref()
        .map(|health| health.warning_count)
        .unwrap_or(0);
    let hil_summary = report.hil_summary;
    Ok(RunHistoryEntry {
        run_id: index.run_id,
        sample: index.sample,
        created_at: index.created_at,
        status: index.status,
        run_dir: run_dir_path.display().to_string(),
        root_causes: history_fields.root_causes,
        diagnosis_status: history_fields.diagnosis_status,
        uncertainty_reason_codes: history_fields.uncertainty_reason_codes,
        ml_top_label: history_fields.ml_top_label,
        ml_top_probability: history_fields.ml_top_probability,
        model_kind: history_fields.model_kind,
        synthetic_model: history_fields.synthetic_model,
        measurement_quality,
        quality,
        quality_status,
        warning_count,
        hil_summary,
        artifact_count,
    })
}

fn ensure_index_matches_documents(
    index: &RunIndexEntry,
    manifest: &crate::models::RunManifest,
    report: &Report,
) -> Result<()> {
    let expected_status = report.hil_summary.run_status();
    if index.sample == manifest.sample
        && index.created_at == manifest.created_at
        && index.status == expected_status
    {
        return Ok(());
    }
    Err(NetdiagError::InvalidTrace(format!(
        "run index metadata does not match the trusted manifest and report for {}",
        index.run_id
    )))
}

pub fn run_artifacts(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
) -> Result<Vec<RunArtifactEntry>> {
    run_artifacts_impl(artifact_root.as_ref(), run_id, false)
}

pub(crate) fn run_artifacts_allow_pending(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
) -> Result<Vec<RunArtifactEntry>> {
    run_artifacts_impl(artifact_root.as_ref(), run_id, true)
}

fn run_artifacts_impl(
    artifact_root: &Path,
    run_id: &str,
    allow_pending_transaction: bool,
) -> Result<Vec<RunArtifactEntry>> {
    let location = resolve_run_location(artifact_root, run_id)?;
    run_artifacts_for_location(&location, run_id, allow_pending_transaction)
}

pub(crate) fn run_artifacts_for_location(
    location: &RunLocation,
    run_id: &str,
    allow_pending_transaction: bool,
) -> Result<Vec<RunArtifactEntry>> {
    if !allow_pending_transaction {
        ensure_run_has_no_pending_transaction(&location.run_dir, run_id)?;
    }
    let manifest_path = location.run_dir.join("manifest.json");
    let manifest = run_documents::read_required_manifest_at(&manifest_path, location)?;
    let mut entries = vec![RunArtifactEntry {
        key: "manifest".to_string(),
        path: manifest_path.display().to_string(),
        exists: path_status(&manifest_path)?.exists(),
    }];
    for (key, value) in manifest.artifact_paths {
        if key == "run_id" {
            continue;
        }
        let path = resolve_artifact_path(location, &value)?;
        entries.push(RunArtifactEntry {
            key,
            exists: path_status(&path)?.exists(),
            path: path.display().to_string(),
        });
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(entries)
}

pub fn read_connector_health(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
) -> Result<Option<ConnectorHealthSnapshot>> {
    let location = resolve_run_location(artifact_root, run_id)?;
    let manifest = read_manifest(&location.artifact_root, run_id)?;
    if let Some(stored_path) = manifest.artifact_paths.get("connector_health") {
        let path = resolve_artifact_path(&location, stored_path)?;
        let health = typed_json::read_required_stable_json_bounded(
            &path,
            typed_json::MAX_CONNECTOR_HEALTH_BYTES,
            "manifest-declared connector health",
        )?;
        return Ok(Some(health));
    }

    let default_path = location.run_dir.join("connector_health.json");
    if let Some(health) = typed_json::read_optional_stable_json_bounded(
        &default_path,
        typed_json::MAX_CONNECTOR_HEALTH_BYTES,
        "legacy connector health",
    )? {
        return Ok(Some(health));
    }

    infer_connector_health(&location.artifact_root, run_id).map(Some)
}

pub fn run_evidence(artifact_root: impl AsRef<Path>, run_id: &str) -> Result<RunEvidenceSummary> {
    let artifact_root = artifact_root.as_ref();
    let index = find_run_index(artifact_root, run_id)?;
    let run = run_history_entry(artifact_root, index)?;
    let report = read_report(artifact_root, run_id)?;
    let connector_health = read_connector_health(artifact_root, run_id)?;
    let artifacts = run_artifacts(artifact_root, run_id)?;
    Ok(RunEvidenceSummary {
        run,
        report,
        connector_health,
        artifacts,
    })
}

pub fn compare_runs(
    artifact_root: impl AsRef<Path>,
    left_run_id: &str,
    right_run_id: &str,
) -> Result<RunComparison> {
    let artifact_root = artifact_root.as_ref();
    let left_index = find_run_index(artifact_root, left_run_id)?;
    let right_index = find_run_index(artifact_root, right_run_id)?;
    let left = run_history_entry(artifact_root, left_index)?;
    let right = run_history_entry(artifact_root, right_index)?;
    let left_report = read_report(artifact_root, left_run_id)?;
    let right_report = read_report(artifact_root, right_run_id)?;
    let left_roots = left.root_causes.iter().cloned().collect::<BTreeSet<_>>();
    let right_roots = right.root_causes.iter().cloned().collect::<BTreeSet<_>>();

    Ok(RunComparison {
        latency_p95_delta_pct: percent_delta(
            left_report.trace_summary.overall.latency.p95,
            right_report.trace_summary.overall.latency.p95,
        )?,
        loss_delta_pct: percent_delta(
            left_report.trace_summary.overall.packet_loss_rate,
            right_report.trace_summary.overall.packet_loss_rate,
        )?,
        throughput_delta_pct: percent_delta(
            left_report.trace_summary.overall.throughput_mbps.mean,
            right_report.trace_summary.overall.throughput_mbps.mean,
        )?,
        ml_label_changed: left.ml_top_label != right.ml_top_label,
        new_root_causes: right_roots.difference(&left_roots).cloned().collect(),
        resolved_root_causes: left_roots.difference(&right_roots).cloned().collect(),
        review_status_changed: left.status != right.status,
        recommendation_state_changes: recommendation_state_changes(
            &left_report.recommendations,
            &right_report.recommendations,
        ),
        measurement_quality_changes: metric_quality_changes(
            &left_report.measurement_quality,
            &right_report.measurement_quality,
        ),
        quality_status_changed: left.quality_status != right.quality_status,
        warning_count_delta: right.warning_count as isize - left.warning_count as isize,
        left,
        right,
    })
}

/// Legacy feedback entrypoint retained to return an explicit migration error.
/// Use [`crate::hil_review::review_recommendation`] so reviewer identity and all derived
/// artifacts are committed through the crash-safe HIL transaction.
pub fn write_feedback(
    _artifact_root: impl AsRef<Path>,
    run_id: &str,
    item_id: &str,
    _state: HilState,
    _notes: &str,
) -> Result<PathBuf> {
    Err(NetdiagError::InvalidTrace(format!(
        "write_feedback cannot safely record run {run_id} item {item_id} because its legacy API has no reviewer or final-label fields; use review_recommendation"
    )))
}

fn scan_run_manifests(artifact_root: &Path) -> Result<Vec<RunIndexEntry>> {
    let runs_dir = artifact_root.join("runs");
    match path_status(&runs_dir)? {
        PathStatus::Missing => return Ok(Vec::new()),
        PathStatus::Directory => {}
        _ => {
            return Err(NetdiagError::InvalidTrace(format!(
                "runs path is not a regular directory: {}",
                runs_dir.display()
            )));
        }
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&runs_dir).with_path(&runs_dir)? {
        let entry = entry.with_path(&runs_dir)?;
        let path = entry.path();
        match path_status(&path)? {
            PathStatus::Missing | PathStatus::RegularFile => continue,
            PathStatus::Directory => {}
            PathStatus::Other => {
                return Err(NetdiagError::InvalidTrace(format!(
                    "run directory is not a regular directory: {}",
                    path.display()
                )));
            }
        }
        let Some(run_id) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if run_id.starts_with('.') {
            continue;
        }
        crate::identifiers::validate_portable_id("run directory id", run_id)?;
        let manifest_path = path.join("manifest.json");
        let Some(manifest) = run_documents::read_optional_manifest_at(&manifest_path, &path)?
        else {
            continue;
        };
        let status = read_report(artifact_root, &manifest.run_id)?
            .hil_summary
            .run_status()
            .to_string();
        let stored_run_dir = path.strip_prefix(artifact_root).map_err(|_| {
            NetdiagError::InvalidTrace(format!(
                "run directory is outside the artifact root: {}",
                path.display()
            ))
        })?;
        entries.push(RunIndexEntry {
            run_id: manifest.run_id,
            sample: manifest.sample,
            created_at: manifest.created_at,
            status,
            run_dir: stored_run_dir.display().to_string(),
        });
    }
    Ok(entries)
}

fn ensure_indexed_run_dir_matches(
    artifact_root: &Path,
    stored_run_dir: &str,
    resolved_run_dir: &Path,
) -> Result<()> {
    let indexed_run_dir = resolve_stored_path(artifact_root, stored_run_dir)?;
    let indexed = fs::canonicalize(&indexed_run_dir).with_path(&indexed_run_dir)?;
    let resolved = fs::canonicalize(resolved_run_dir).with_path(resolved_run_dir)?;
    if indexed == resolved {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "run index path {} does not match resolved run directory {}",
            indexed_run_dir.display(),
            resolved_run_dir.display()
        )))
    }
}

fn find_run_index(artifact_root: &Path, run_id: &str) -> Result<RunIndexEntry> {
    list_run_index(artifact_root)?
        .into_iter()
        .find(|entry| entry.run_id == run_id)
        .ok_or_else(|| NetdiagError::InvalidTrace(format!("unknown run id: {run_id}")))
}

fn run_history_matches(entry: &RunHistoryEntry, filter: &RunHistoryFilter) -> bool {
    if let Some(status) = &filter.status
        && !entry.status.eq_ignore_ascii_case(status)
    {
        return false;
    }
    if let Some(root_cause) = &filter.root_cause {
        let root_cause = root_cause.trim().to_ascii_lowercase();
        let has_root = entry.root_causes.iter().any(|root| {
            root.eq_ignore_ascii_case(&root_cause)
                || root.replace('_', "-").eq_ignore_ascii_case(&root_cause)
        });
        if !has_root {
            return false;
        }
    }
    if let Some(quality) = filter.quality
        && entry.quality_status != quality
    {
        return false;
    }
    true
}

fn resolve_artifact_path(location: &RunLocation, value: &str) -> Result<PathBuf> {
    if value.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "manifest artifact path is empty".to_string(),
        ));
    }
    let raw = PathBuf::from(value);
    if raw.is_absolute() {
        return Err(NetdiagError::InvalidTrace(format!(
            "manifest artifact path must be relative: {value}"
        )));
    }
    if raw
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "manifest artifact path escapes the run directory: {value}"
        )));
    }

    let dir = &location.run_dir;
    let mut candidates = vec![dir.join(&raw)];
    candidates.push(location.artifact_root.join(&raw));
    if let Some(lab_run_dir) = &location.lab_run_dir {
        candidates.push(lab_run_dir.join(&raw));
    }
    if let Some(lab_index_root) = &location.lab_index_root {
        candidates.push(lab_index_root.join(&raw));
    }
    for root in [
        Some(&location.artifact_root),
        location.lab_run_dir.as_ref(),
        location.lab_index_root.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if raw.components().next().map(|part| part.as_os_str()) == root.file_name()
            && let Some(parent) = root.parent()
        {
            candidates.push(parent.join(&raw));
        }
    }

    let canonical_run_dir = fs::canonicalize(dir).with_path(dir)?;
    for candidate in candidates {
        if !path_status(&candidate)?.exists() {
            continue;
        }
        let canonical = fs::canonicalize(&candidate).with_path(&candidate)?;
        if !canonical.starts_with(&canonical_run_dir) {
            return Err(NetdiagError::InvalidTrace(format!(
                "manifest artifact path resolves outside the run directory: {}",
                candidate.display()
            )));
        }
        return Ok(candidate);
    }
    Ok(dir.join(raw))
}

fn infer_connector_health(artifact_root: &Path, run_id: &str) -> Result<ConnectorHealthSnapshot> {
    let report = read_report(artifact_root, run_id)?;
    let index = find_run_index(artifact_root, run_id)?;
    let quality = MeasurementQualitySummary::from_provenance(&report.measurement_quality);
    let status = health_status_for_summary(quality, report.measurement_quality.len());
    Ok(ConnectorHealthSnapshot {
        status,
        source_kind: "legacy_artifact".to_string(),
        profile_name: "legacy_artifact".to_string(),
        sample: index.sample,
        rows: report.trace_summary.overall.samples,
        warning_count: 0,
        missing_metrics: missing_metric_names(&report.measurement_quality),
        quality,
        captured_at: index.created_at,
    })
}

fn health_status_for_summary(
    summary: MeasurementQualitySummary,
    provenance_count: usize,
) -> ConnectorHealthStatus {
    if provenance_count == 0 || summary.degraded() {
        ConnectorHealthStatus::Degraded
    } else {
        ConnectorHealthStatus::Ok
    }
}

#[derive(Debug, Default)]
struct ReportHistoryFields {
    root_causes: Vec<String>,
    diagnosis_status: crate::models::DiagnosisStatus,
    uncertainty_reason_codes: Vec<crate::models::UncertaintyReasonCode>,
    ml_top_label: Option<String>,
    ml_top_probability: Option<f64>,
    model_kind: Option<String>,
    synthetic_model: bool,
}

fn report_history_fields(report: &Report) -> ReportHistoryFields {
    let root_causes = report
        .root_causes
        .iter()
        .map(|root| root.symptom.clone())
        .collect();
    let diagnosis_status = report.diagnosis_status;
    let uncertainty_reason_codes = report.uncertainty.reason_codes.clone();
    let top_prediction = report.rule_vs_ml.ml_top.clone();
    let ml_top_label = (!top_prediction.is_empty()).then_some(top_prediction);
    let ml_top_probability = Some(report.rule_vs_ml.ml_top_prob);
    let model_kind = report
        .model_manifest
        .as_ref()
        .map(|manifest| manifest.model_kind.clone());
    let synthetic_model = report
        .model_manifest
        .as_ref()
        .is_some_and(|manifest| manifest.synthetic_fallback);
    ReportHistoryFields {
        root_causes,
        diagnosis_status,
        uncertainty_reason_codes,
        ml_top_label,
        ml_top_probability,
        model_kind,
        synthetic_model,
    }
}

fn recommendation_state_changes(
    left: &[Recommendation],
    right: &[Recommendation],
) -> Vec<RecommendationStateChange> {
    let left_states = left
        .iter()
        .map(|recommendation| {
            (
                recommendation.recommendation_id.clone(),
                recommendation.hil_state,
            )
        })
        .collect::<BTreeMap<_, _>>();
    right
        .iter()
        .filter_map(|recommendation| {
            let left_state = left_states.get(&recommendation.recommendation_id)?;
            if *left_state == recommendation.hil_state {
                return None;
            }
            Some(RecommendationStateChange {
                recommendation_id: recommendation.recommendation_id.clone(),
                left_state: *left_state,
                right_state: recommendation.hil_state,
            })
        })
        .collect()
}

fn metric_quality_changes(
    left: &[MetricProvenance],
    right: &[MetricProvenance],
) -> Vec<MetricQualityChange> {
    let left_quality = left
        .iter()
        .map(|item| (item.field.clone(), item.quality))
        .collect::<BTreeMap<_, _>>();
    right
        .iter()
        .filter_map(|item| {
            let left_quality = left_quality
                .get(&item.field)
                .copied()
                .unwrap_or(MetricQuality::Missing);
            if left_quality == item.quality {
                return None;
            }
            Some(MetricQualityChange {
                field: item.field.clone(),
                left_quality,
                right_quality: item.quality,
            })
        })
        .collect()
}
