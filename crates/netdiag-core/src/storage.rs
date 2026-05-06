use crate::error::{IoContext, NetdiagError, Result};
use crate::models::{
    ConnectorHealthSnapshot, ConnectorHealthStatus, FaultLabel, HilFeedbackRecord, HilReview,
    HilReviewSummary, HilState, IngestResult, MeasurementQualitySummary, MetricProvenance,
    MetricQuality, MetricQualityChange, Recommendation, RecommendationStateChange,
    RunArtifactEntry, RunComparison, RunEvidenceSummary, RunHistoryEntry, RunHistoryFilter,
    RunIndexEntry, RunManifest, RunTimelineEvent,
};
use crate::report::Report;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

pub fn run_dir(artifact_root: impl AsRef<Path>, run_id: &str) -> PathBuf {
    artifact_root.as_ref().join("runs").join(run_id)
}

pub fn save_json<T: Serialize + ?Sized>(path: impl AsRef<Path>, value: &T) -> Result<PathBuf> {
    save_json_atomic(path, value)
}

pub fn save_json_atomic<T: Serialize + ?Sized>(
    path: impl AsRef<Path>,
    value: &T,
) -> Result<PathBuf> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_path(parent)?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("json")
    ));
    let write_result = (|| -> Result<()> {
        let file = File::create(&tmp_path).with_path(&tmp_path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, value)?;
        writer.flush().with_path(&tmp_path)?;
        writer.get_ref().sync_all().with_path(&tmp_path)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    fs::rename(&tmp_path, path).with_path(path)?;
    Ok(path.to_path_buf())
}

pub fn read_json(path: impl AsRef<Path>) -> Result<Value> {
    let path = path.as_ref();
    let file = File::open(path).with_path(path)?;
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

pub fn read_manifest(artifact_root: impl AsRef<Path>, run_id: &str) -> Result<RunManifest> {
    let path = run_dir(artifact_root, run_id).join("manifest.json");
    let file = File::open(&path).with_path(&path)?;
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

pub fn read_report(artifact_root: impl AsRef<Path>, run_id: &str) -> Result<Report> {
    let path = run_dir(artifact_root, run_id).join("report.json");
    let file = File::open(&path).with_path(&path)?;
    Ok(serde_json::from_reader(BufReader::new(file))?)
}

pub fn list_run_index(artifact_root: impl AsRef<Path>) -> Result<Vec<RunIndexEntry>> {
    let artifact_root = artifact_root.as_ref();
    let index_path = artifact_root.join("run_index.json");
    let mut entries = if index_path.exists() {
        match read_json(&index_path)
            .and_then(|value| Ok(serde_json::from_value::<Vec<RunIndexEntry>>(value)?))
        {
            Ok(entries) => entries,
            Err(_) => scan_run_manifests(artifact_root)?,
        }
    } else {
        scan_run_manifests(artifact_root)?
    };
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
    let run_dir_path = PathBuf::from(&index.run_dir);
    let manifest = read_manifest(artifact_root, &index.run_id).ok();
    let report = read_report(artifact_root, &index.run_id).ok();
    let artifact_count = manifest
        .as_ref()
        .map(|manifest| {
            manifest
                .artifact_paths
                .keys()
                .filter(|key| key.as_str() != "run_id")
                .count()
        })
        .unwrap_or(0);
    let (root_causes, ml_top_label, ml_top_probability, model_kind, synthetic_model) = report
        .as_ref()
        .map(report_history_fields)
        .unwrap_or_default();
    let measurement_quality = report
        .as_ref()
        .map(|report| report.measurement_quality.clone())
        .unwrap_or_default();
    let connector_health = read_connector_health(artifact_root, &index.run_id)
        .ok()
        .flatten();
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
    let hil_summary = report
        .as_ref()
        .map(|report| report.hil_summary.clone())
        .unwrap_or_default();
    Ok(RunHistoryEntry {
        run_id: index.run_id,
        sample: index.sample,
        created_at: index.created_at,
        status: index.status,
        run_dir: run_dir_path.display().to_string(),
        root_causes,
        ml_top_label,
        ml_top_probability,
        model_kind,
        synthetic_model,
        measurement_quality,
        quality,
        quality_status,
        warning_count,
        hil_summary,
        artifact_count,
    })
}

pub fn run_artifacts(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
) -> Result<Vec<RunArtifactEntry>> {
    let artifact_root = artifact_root.as_ref();
    let dir = run_dir(artifact_root, run_id);
    let manifest_path = dir.join("manifest.json");
    let file = File::open(&manifest_path).with_path(&manifest_path)?;
    let manifest: RunManifest = serde_json::from_reader(BufReader::new(file))?;
    let mut entries = manifest
        .artifact_paths
        .into_iter()
        .filter_map(|(key, value)| {
            if key == "run_id" {
                return None;
            }
            let path = resolve_artifact_path(artifact_root, run_id, &value);
            Some(RunArtifactEntry {
                key,
                exists: path.exists(),
                path: path.display().to_string(),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(entries)
}

pub fn connector_health_from_ingest(
    source_kind: &str,
    profile_name: &str,
    sample: &str,
    ingest: &IngestResult,
) -> ConnectorHealthSnapshot {
    let quality = MeasurementQualitySummary::from_provenance(&ingest.metric_provenance);
    let missing_metrics = missing_metric_names(&ingest.metric_provenance);
    let status = if ingest.records.is_empty() {
        ConnectorHealthStatus::Error
    } else if !ingest.warnings.is_empty() || quality.degraded() {
        ConnectorHealthStatus::Degraded
    } else {
        ConnectorHealthStatus::Ok
    };
    ConnectorHealthSnapshot {
        status,
        source_kind: source_kind.to_string(),
        profile_name: profile_name.to_string(),
        sample: sample.to_string(),
        rows: ingest.schema.rows,
        warning_count: ingest.warnings.len(),
        missing_metrics,
        quality,
        captured_at: ingest.schema.ingested_at,
    }
}

pub fn write_connector_health(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    health: &ConnectorHealthSnapshot,
) -> Result<PathBuf> {
    let dir = run_dir(artifact_root.as_ref(), run_id);
    let path = dir.join("connector_health.json");
    save_json_atomic(&path, health)?;
    update_manifest_artifact_path(&dir, "connector_health", &path)?;
    Ok(path)
}

pub fn read_connector_health(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
) -> Result<Option<ConnectorHealthSnapshot>> {
    let artifact_root = artifact_root.as_ref();
    if let Ok(manifest) = read_manifest(artifact_root, run_id)
        && let Some(path) = manifest.artifact_paths.get("connector_health")
    {
        let path = resolve_artifact_path(artifact_root, run_id, path);
        if path.exists() {
            let health = serde_json::from_value(read_json(path)?)?;
            return Ok(Some(health));
        }
    }

    let default_path = run_dir(artifact_root, run_id).join("connector_health.json");
    if default_path.exists() {
        let health = serde_json::from_value(read_json(default_path)?)?;
        return Ok(Some(health));
    }

    infer_connector_health(artifact_root, run_id)
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
        ),
        loss_delta_pct: percent_delta(
            left_report.trace_summary.overall.packet_loss_rate,
            right_report.trace_summary.overall.packet_loss_rate,
        ),
        throughput_delta_pct: percent_delta(
            left_report.trace_summary.overall.throughput_mbps.mean,
            right_report.trace_summary.overall.throughput_mbps.mean,
        ),
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

#[derive(Debug, Clone)]
pub struct HilReviewOutcome {
    pub review: HilReview,
    pub recommendations: Vec<Recommendation>,
    pub status: String,
}

pub fn review_recommendation(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    recommendation_id: &str,
    state: HilState,
    notes: &str,
    reviewer: &str,
    final_label: Option<FaultLabel>,
) -> Result<HilReviewOutcome> {
    let artifact_root = artifact_root.as_ref();
    let dir = run_dir(artifact_root, run_id);
    let recommendations_path = dir.join("recommendations.json");
    let mut recommendations: Vec<Recommendation> =
        serde_json::from_value(read_json(&recommendations_path)?)?;
    let Some(recommendation) = recommendations
        .iter_mut()
        .find(|recommendation| recommendation.recommendation_id == recommendation_id)
    else {
        return Err(NetdiagError::UnknownRecommendation(
            recommendation_id.to_string(),
        ));
    };

    let review = HilReview::with_final_label(state, notes.trim(), reviewer.trim(), final_label);
    recommendation.hil_state = state;
    recommendation.review = Some(review.clone());
    save_json_atomic(&recommendations_path, &recommendations)?;

    update_report(&dir, &recommendations)?;
    write_feedback_record(
        &dir,
        HilFeedbackRecord {
            run_id: run_id.to_string(),
            recommendation_id: recommendation_id.to_string(),
            review: review.clone(),
        },
    )?;
    update_manifest_feedback_path(&dir)?;

    let status = HilReviewSummary::from_recommendations(&recommendations)
        .run_status()
        .to_string();
    update_run_index_status(artifact_root, run_id, status.as_str())?;

    Ok(HilReviewOutcome {
        review,
        recommendations,
        status,
    })
}

pub fn write_feedback(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    item_id: &str,
    state: HilState,
    notes: &str,
) -> Result<PathBuf> {
    let path = run_dir(artifact_root, run_id).join("hil_feedback.json");
    let mut feedback = if path.exists() {
        read_json(&path)?
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    feedback.insert(
        item_id.to_string(),
        serde_json::json!({
            "state": state,
            "notes": notes,
        }),
    );
    save_json_atomic(path, &feedback)
}

fn update_report(dir: &Path, recommendations: &[Recommendation]) -> Result<()> {
    let report_path = dir.join("report.json");
    if !report_path.exists() {
        return Ok(());
    }
    let mut report: Report = serde_json::from_value(read_json(&report_path)?)?;
    report.recommendations = recommendations.to_vec();
    report.hil_summary = HilReviewSummary::from_recommendations(recommendations);
    save_json_atomic(report_path, &report)?;
    Ok(())
}

fn write_feedback_record(dir: &Path, record: HilFeedbackRecord) -> Result<()> {
    let path = dir.join("hil_feedback.json");
    let mut feedback = if path.exists() {
        serde_json::from_value::<BTreeMap<String, HilFeedbackRecord>>(read_json(&path)?)?
    } else {
        BTreeMap::new()
    };
    feedback.insert(record.recommendation_id.clone(), record);
    save_json_atomic(path, &feedback)?;
    Ok(())
}

fn update_manifest_feedback_path(dir: &Path) -> Result<()> {
    update_manifest_artifact_path(dir, "hil_feedback", &dir.join("hil_feedback.json"))
}

fn update_run_index_status(artifact_root: &Path, run_id: &str, status: &str) -> Result<()> {
    let index_path = artifact_root.join("run_index.json");
    if !index_path.exists() {
        return Ok(());
    }
    let mut entries: Vec<RunIndexEntry> = serde_json::from_value(read_json(&index_path)?)?;
    for entry in &mut entries {
        if entry.run_id == run_id {
            entry.status = status.to_string();
            break;
        }
    }
    save_json_atomic(index_path, &entries)?;
    Ok(())
}

fn scan_run_manifests(artifact_root: &Path) -> Result<Vec<RunIndexEntry>> {
    let runs_dir = artifact_root.join("runs");
    if !runs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(&runs_dir).with_path(&runs_dir)? {
        let entry = entry.with_path(&runs_dir)?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(run_id) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if run_id.starts_with('.') {
            continue;
        }
        let manifest_path = path.join("manifest.json");
        if !manifest_path.exists() {
            continue;
        }
        let manifest: RunManifest = serde_json::from_value(read_json(&manifest_path)?)?;
        let status = read_report(artifact_root, &manifest.run_id)
            .map(|report| report.hil_summary.run_status().to_string())
            .unwrap_or_else(|_| "complete".to_string());
        entries.push(RunIndexEntry {
            run_id: manifest.run_id,
            sample: manifest.sample,
            created_at: manifest.created_at,
            status,
            run_dir: path.display().to_string(),
        });
    }
    Ok(entries)
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

fn resolve_artifact_path(artifact_root: &Path, run_id: &str, value: &str) -> PathBuf {
    let raw = PathBuf::from(value);
    if raw.is_absolute() {
        return raw;
    }

    let dir = run_dir(artifact_root, run_id);
    let mut candidates = Vec::new();
    if raw.components().count() == 1 {
        candidates.push(dir.join(&raw));
    }
    candidates.push(artifact_root.join(&raw));
    candidates.push(raw.clone());
    candidates.push(dir.join(&raw));

    candidates
        .iter()
        .find(|path| path.exists())
        .cloned()
        .unwrap_or_else(|| candidates.remove(0))
}

fn update_manifest_artifact_path(dir: &Path, key: &str, path: &Path) -> Result<()> {
    let manifest_path = dir.join("manifest.json");
    if !manifest_path.exists() {
        return Ok(());
    }
    let mut manifest: RunManifest = serde_json::from_value(read_json(&manifest_path)?)?;
    manifest
        .artifact_paths
        .insert(key.to_string(), path.display().to_string());
    save_json_atomic(manifest_path, &manifest)?;
    Ok(())
}

fn infer_connector_health(
    artifact_root: &Path,
    run_id: &str,
) -> Result<Option<ConnectorHealthSnapshot>> {
    let Ok(report) = read_report(artifact_root, run_id) else {
        return Ok(None);
    };
    let index = find_run_index(artifact_root, run_id).ok();
    let quality = MeasurementQualitySummary::from_provenance(&report.measurement_quality);
    let status = health_status_for_summary(quality, report.measurement_quality.len());
    Ok(Some(ConnectorHealthSnapshot {
        status,
        source_kind: "legacy_artifact".to_string(),
        profile_name: "legacy_artifact".to_string(),
        sample: index
            .as_ref()
            .map(|index| index.sample.clone())
            .unwrap_or_else(|| run_id.to_string()),
        rows: report.trace_summary.overall.samples,
        warning_count: 0,
        missing_metrics: missing_metric_names(&report.measurement_quality),
        quality,
        captured_at: index
            .as_ref()
            .map(|index| index.created_at)
            .unwrap_or_else(|| report.generated_at),
    }))
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

fn missing_metric_names(provenance: &[MetricProvenance]) -> Vec<String> {
    provenance
        .iter()
        .filter(|item| {
            matches!(
                item.quality,
                MetricQuality::Fallback | MetricQuality::Missing
            )
        })
        .map(|item| item.field.clone())
        .collect()
}

fn report_history_fields(
    report: &Report,
) -> (
    Vec<String>,
    Option<String>,
    Option<f64>,
    Option<String>,
    bool,
) {
    let root_causes = report
        .root_causes
        .iter()
        .map(|root| root.symptom.clone())
        .collect();
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
    (
        root_causes,
        ml_top_label,
        ml_top_probability,
        model_kind,
        synthetic_model,
    )
}

fn percent_delta(left: f64, right: f64) -> Option<f64> {
    if !left.is_finite() || !right.is_finite() || left.abs() < f64::EPSILON {
        return None;
    }
    Some(((right - left) / left.abs()) * 100.0)
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
