use crate::dataset::prepare_training_dataset;
use crate::error::{IoContext, NetdiagError, Result};
pub use crate::feature_schema::FEATURES;
use crate::models::{
    DiagnosisStatus, FaultLabel, FeatureBounds, FeatureImportance, LabelMetrics, MetricProvenance,
    MetricQuality, MlResult, ModelEvaluation, ModelManifest, ModelTrainingConfig,
    ModelTrainingGate, ModelUncertaintyThresholds, Prediction, TelemetryWindow,
    UncertaintyAssessment, UncertaintyReasonCode,
};
use crate::storage::{PathStatus, path_status};
use crate::telemetry::{extract_features_from_windows, mean};
use crate::twin::round_decimal;
use chrono::Utc;
use linfa::Dataset;
use linfa::prelude::Fit;
use linfa_logistic::{MultiFittedLogisticRegression, MultiLogisticRegression};
use ndarray::{Array1, Array2};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const MODEL_FILE_NAME: &str = "rust_logistic_model.json";
pub const MODEL_MANIFEST_FILE_NAME: &str = "model_manifest.json";
pub const MODEL_MANIFEST_SCHEMA: &str = "netdiag-model-manifest/v2";
pub const MODEL_CURRENT_FILE_NAME: &str = "current.json";
pub(crate) const MODEL_PROMOTION_GATE_FILE_NAME: &str = "model_promotion_gate.json";
pub const MODEL_GENERATIONS_DIR_NAME: &str = "generations";
pub const MODEL_CURRENT_SCHEMA: &str = "netdiag-model-current/v1";

mod feedback_export;
mod model_bundle;
mod numeric;
pub use feedback_export::{
    FeedbackExportSummary, FeedbackTrainingRow, export_feedback_training_dataset,
};
pub(crate) use model_bundle::{
    ModelBundleSnapshot, invalidate_model_promotion_gate_locked,
    load_existing_model_bundle_snapshot, load_existing_model_bundle_snapshot_if_present,
    load_model_bundle_snapshot_with_policy, with_model_bundle_lock,
};
use model_bundle::{ensure_publication_supported, write_model_bundle};
use numeric::{
    calibrate_probabilities, finite_l2_norm, scale_row, validate_probability_classes,
    validate_probability_distribution, validate_uncertainty_thresholds,
};

const BASELINES: [[f64; 11]; 6] = [
    [28.0, 50.0, 5.0, 0.10, 0.20, 0.5, 1.0, 100.0, 0.0, 0.0, 0.0],
    [180.0, 280.0, 30.0, 1.3, 2.8, 2.0, 4.0, 15.0, 0.0, 0.0, 0.03],
    [95.0, 170.0, 20.0, 2.5, 1.2, 1.1, 2.5, 50.0, 0.0, 0.0, 0.05],
    [75.0, 160.0, 8.0, 0.3, 0.5, 8.0, 15.0, 80.0, 6.0, 0.2, 0.02],
    [120.0, 210.0, 9.0, 0.5, 1.0, 3.0, 4.0, 70.0, 0.1, 6.0, 0.04],
    [70.0, 150.0, 11.0, 1.3, 1.0, 1.5, 2.0, 45.0, 0.0, 0.0, 0.75],
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustMlModel {
    pub model: MultiFittedLogisticRegression<f64, usize>,
    pub means: Vec<f64>,
    pub stds: Vec<f64>,
}

#[derive(Debug, Clone, Copy)]
pub struct TrainingOptions {
    pub validation_split: f64,
    pub shuffle_seed: Option<u64>,
    pub stratified: bool,
    pub min_rows_per_label: usize,
}

impl Default for TrainingOptions {
    fn default() -> Self {
        Self {
            validation_split: 0.0,
            shuffle_seed: None,
            stratified: false,
            min_rows_per_label: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelLoadPolicy {
    AllowSyntheticFallback,
    ExistingOnly,
}

#[derive(Debug, Clone)]
struct FeatureTrainingRow {
    label: FaultLabel,
    features: Vec<f64>,
}

pub fn infer(
    windows: &[TelemetryWindow],
    run_id: &str,
    artifact_root: impl AsRef<Path>,
) -> Result<MlResult> {
    infer_with_quality(windows, run_id, artifact_root, &[])
}

pub fn infer_with_quality(
    windows: &[TelemetryWindow],
    run_id: &str,
    artifact_root: impl AsRef<Path>,
    provenance: &[MetricProvenance],
) -> Result<MlResult> {
    let model_dir = artifact_root.as_ref().join("model");
    infer_with_quality_from_model_dir(windows, run_id, &model_dir, provenance)
}

pub fn infer_with_quality_from_model_dir(
    windows: &[TelemetryWindow],
    run_id: &str,
    model_dir: impl AsRef<Path>,
    provenance: &[MetricProvenance],
) -> Result<MlResult> {
    infer_with_quality_from_model_dir_with_policy(
        windows,
        run_id,
        model_dir,
        provenance,
        ModelLoadPolicy::AllowSyntheticFallback,
    )
}

pub fn infer_with_quality_from_existing_model_dir(
    windows: &[TelemetryWindow],
    run_id: &str,
    model_dir: impl AsRef<Path>,
    provenance: &[MetricProvenance],
) -> Result<MlResult> {
    infer_with_quality_from_model_dir_with_policy(
        windows,
        run_id,
        model_dir,
        provenance,
        ModelLoadPolicy::ExistingOnly,
    )
}

pub fn infer_with_quality_from_model_dir_with_policy(
    windows: &[TelemetryWindow],
    run_id: &str,
    model_dir: impl AsRef<Path>,
    provenance: &[MetricProvenance],
    load_policy: ModelLoadPolicy,
) -> Result<MlResult> {
    let snapshot = load_model_bundle_snapshot_with_policy(model_dir.as_ref(), load_policy)?;
    infer_with_quality_from_model_bundle_snapshot(windows, run_id, &snapshot, provenance)
}

pub(crate) fn infer_with_quality_from_model_bundle_snapshot(
    windows: &[TelemetryWindow],
    run_id: &str,
    snapshot: &ModelBundleSnapshot,
    provenance: &[MetricProvenance],
) -> Result<MlResult> {
    let model = &snapshot.model;
    let model_manifest = &snapshot.manifest;
    let raw_features = extract_features_from_windows(windows);
    let feature_quality = feature_quality_map(provenance);
    let weighted_features = apply_feature_quality(&raw_features, &feature_quality);
    let scaled = scale_row(&weighted_features, &model.means, &model.stds)?;
    let x = Array2::from_shape_vec((1, FEATURES.len()), scaled.clone())
        .map_err(|err| NetdiagError::Ml(err.to_string()))?;
    let probabilities = model.model.predict_probabilities(&x);
    let classes = model.model.classes().to_vec();
    let calibrated =
        calibrate_probabilities(probabilities.row(0).to_vec(), &classes, &weighted_features)?;
    let mut ranking = Vec::with_capacity(calibrated.len());
    for (idx, prob) in calibrated.iter().enumerate() {
        let class_index = classes.get(idx).copied().ok_or_else(|| {
            NetdiagError::Ml(format!(
                "model returned probability index {idx} without a matching class"
            ))
        })?;
        let label = FaultLabel::from_index(class_index).ok_or_else(|| {
            NetdiagError::Ml(format!(
                "model returned unknown class index {class_index}; expected one of the six known labels"
            ))
        })?;
        ranking.push(Prediction { label, prob: *prob });
    }
    ranking.sort_by(|left, right| right.prob.total_cmp(&left.prob));
    let uncertainty = assess_uncertainty(
        &ranking,
        &weighted_features,
        &scaled,
        &feature_quality,
        Some(model_manifest),
    )?;

    let top_prediction = ranking
        .first()
        .ok_or_else(|| NetdiagError::Ml("model returned no predictions".to_string()))?;
    let top_class_position = classes
        .iter()
        .position(|class| *class == top_prediction.label.index())
        .ok_or_else(|| {
            NetdiagError::Ml(format!(
                "top prediction {} has no matching model class",
                top_prediction.label
            ))
        })?;
    let params = model.model.params();
    let mut top_features = Vec::with_capacity(FEATURES.len());
    for (idx, name) in FEATURES.iter().enumerate() {
        let parameter = params.get((idx, top_class_position)).copied().ok_or_else(|| {
            NetdiagError::Ml(format!(
                "model parameter is missing for feature {name} and class position {top_class_position}"
            ))
        })?;
        let contribution = scaled[idx] * parameter;
        if !contribution.is_finite() {
            return Err(NetdiagError::Ml(format!(
                "feature importance overflowed for feature {name}"
            )));
        }
        top_features.push(FeatureImportance {
            name: (*name).to_string(),
            importance: contribution.abs(),
        });
    }
    top_features.sort_by(|left, right| right.importance.total_cmp(&left.importance));

    let features = FEATURES
        .iter()
        .zip(raw_features)
        .map(|(name, value)| ((*name).to_string(), value))
        .collect::<BTreeMap<_, _>>();

    Ok(MlResult {
        method: "rust_linfa_logistic".to_string(),
        run_id: run_id.to_string(),
        top_predictions: ranking.into_iter().take(5).collect(),
        top_features: top_features.into_iter().take(5).collect(),
        features,
        feature_quality,
        uncertainty,
        model_manifest: Some(model_manifest.clone()),
        model_manifest_hash: Some(snapshot.model_manifest_hash_sha256.clone()),
        model_file_hash: Some(snapshot.model_file_hash_sha256.clone()),
    })
}

fn feature_quality_map(provenance: &[MetricProvenance]) -> BTreeMap<String, MetricQuality> {
    let by_metric = provenance
        .iter()
        .map(|item| (item.field.as_str(), item.quality))
        .collect::<BTreeMap<_, _>>();
    FEATURES
        .iter()
        .map(|feature| {
            let metric = feature_metric(feature);
            (
                (*feature).to_string(),
                by_metric
                    .get(metric)
                    .copied()
                    .unwrap_or(MetricQuality::Missing),
            )
        })
        .collect()
}

fn apply_feature_quality(
    features: &[f64],
    feature_quality: &BTreeMap<String, MetricQuality>,
) -> Vec<f64> {
    FEATURES
        .iter()
        .enumerate()
        .map(|(idx, feature)| {
            let quality = feature_quality
                .get(*feature)
                .copied()
                .unwrap_or(MetricQuality::Missing);
            match quality {
                MetricQuality::Measured | MetricQuality::Estimated => features[idx],
                MetricQuality::Fallback => features[idx] * 0.25,
                MetricQuality::Missing => 0.0,
            }
        })
        .collect()
}

fn feature_metric(feature: &str) -> &'static str {
    match feature {
        "latency_mean" | "latency_p95" => "latency_ms",
        "jitter_std" => "jitter_ms",
        "loss_rate" => "packet_loss_rate",
        "retrans_rate" => "retransmission_rate",
        "timeout" => "timeout_events",
        "retry" => "retry_events",
        "throughput" => "throughput_mbps",
        "dns_events" => "dns_failure_events",
        "tls_events" => "tls_failure_events",
        "quic" => "quic_blocked_ratio",
        _ => "unknown",
    }
}

fn assess_uncertainty(
    ranking: &[Prediction],
    weighted_features: &[f64],
    scaled_features: &[f64],
    feature_quality: &BTreeMap<String, MetricQuality>,
    manifest: Option<&ModelManifest>,
) -> Result<UncertaintyAssessment> {
    let thresholds = manifest
        .and_then(|manifest| manifest.uncertainty_thresholds.clone())
        .unwrap_or_default();
    let metrics = uncertainty_metrics(ranking, weighted_features, scaled_features, &thresholds)?;
    let max_probability = metrics.max_probability;
    let probability_margin = metrics.probability_margin;
    let entropy = metrics.entropy;
    let feature_distance = metrics.feature_distance;
    let feature_bounds_violations = metrics.feature_bounds_violations;

    let mut reasons = Vec::new();
    let mut reason_codes = Vec::new();
    let add_code = |codes: &mut Vec<UncertaintyReasonCode>, code| {
        if !codes.contains(&code) {
            codes.push(code);
        }
    };
    let insufficient_features = feature_quality
        .iter()
        .filter(|(_, quality)| matches!(quality, MetricQuality::Fallback | MetricQuality::Missing))
        .map(|(feature, quality)| format!("{feature}:{}", quality.as_str()))
        .collect::<Vec<_>>();
    let status = if !feature_bounds_violations.is_empty()
        || feature_distance > thresholds.max_feature_distance
    {
        if !feature_bounds_violations.is_empty() {
            reasons
                .push("one or more features are outside the model training envelope".to_string());
            add_code(&mut reason_codes, UncertaintyReasonCode::FeatureOutOfBounds);
        }
        if feature_distance > thresholds.max_feature_distance {
            reasons.push(format!(
                "feature distance {:.4} exceeds threshold {:.4}",
                feature_distance, thresholds.max_feature_distance
            ));
            add_code(
                &mut reason_codes,
                UncertaintyReasonCode::ExtremeFeatureDistance,
            );
        }
        DiagnosisStatus::OutOfDistribution
    } else if !insufficient_features.is_empty()
        || max_probability < thresholds.min_max_probability
        || probability_margin < thresholds.min_probability_margin
        || entropy > thresholds.max_entropy
    {
        if !insufficient_features.is_empty() {
            reasons.push(format!(
                "insufficient evidence from feature quality: {}",
                insufficient_features.join(", ")
            ));
            add_code(
                &mut reason_codes,
                UncertaintyReasonCode::InsufficientEvidence,
            );
        }
        if max_probability < thresholds.min_max_probability {
            reasons.push(format!(
                "max probability {:.4} is below threshold {:.4}",
                max_probability, thresholds.min_max_probability
            ));
            add_code(&mut reason_codes, UncertaintyReasonCode::LowMaxProbability);
            add_code(&mut reason_codes, UncertaintyReasonCode::Ambiguous);
        }
        if probability_margin < thresholds.min_probability_margin {
            reasons.push(format!(
                "probability margin {:.4} is below threshold {:.4}",
                probability_margin, thresholds.min_probability_margin
            ));
            add_code(
                &mut reason_codes,
                UncertaintyReasonCode::LowProbabilityMargin,
            );
            add_code(&mut reason_codes, UncertaintyReasonCode::Ambiguous);
        }
        if entropy > thresholds.max_entropy {
            reasons.push(format!(
                "entropy {:.4} exceeds threshold {:.4}",
                entropy, thresholds.max_entropy
            ));
            add_code(&mut reason_codes, UncertaintyReasonCode::HighEntropy);
            add_code(&mut reason_codes, UncertaintyReasonCode::Ambiguous);
        }
        DiagnosisStatus::Uncertain
    } else {
        reasons.push(
            "prediction is inside the model training envelope with sufficient confidence"
                .to_string(),
        );
        DiagnosisStatus::Known
    };

    Ok(UncertaintyAssessment {
        max_probability: round4(max_probability),
        probability_margin: round4(probability_margin),
        entropy: round4(entropy),
        feature_distance: round4(feature_distance),
        feature_bounds_violations,
        status,
        reasons,
        reason_codes,
    })
}

struct UncertaintyMetrics {
    max_probability: f64,
    probability_margin: f64,
    entropy: f64,
    feature_distance: f64,
    feature_bounds_violations: Vec<String>,
}

fn uncertainty_metrics(
    ranking: &[Prediction],
    weighted_features: &[f64],
    scaled_features: &[f64],
    thresholds: &ModelUncertaintyThresholds,
) -> Result<UncertaintyMetrics> {
    validate_uncertainty_thresholds(thresholds)?;
    if weighted_features.len() != FEATURES.len() || scaled_features.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "uncertainty feature dimensions must both be {}, got weighted={} scaled={}",
            FEATURES.len(),
            weighted_features.len(),
            scaled_features.len()
        )));
    }
    if weighted_features.iter().any(|value| !value.is_finite()) {
        return Err(NetdiagError::Ml(
            "uncertainty assessment received non-finite weighted features".to_string(),
        ));
    }
    let probabilities = ranking
        .iter()
        .map(|prediction| prediction.prob)
        .collect::<Vec<_>>();
    validate_probability_distribution(&probabilities, "calibrated model")?;
    let max_probability = ranking
        .first()
        .map(|prediction| prediction.prob)
        .ok_or_else(|| NetdiagError::Ml("model returned no ranked predictions".to_string()))?;
    let second_probability = ranking
        .get(1)
        .map(|prediction| prediction.prob)
        .ok_or_else(|| {
            NetdiagError::Ml("model returned fewer than two ranked predictions".to_string())
        })?;
    let probability_margin = max_probability - second_probability;
    let entropy = normalized_entropy(&probabilities)?;
    let feature_distance = finite_l2_norm(scaled_features, "scaled inference features")?;
    let mut feature_bounds_violations = Vec::new();
    for (idx, feature) in FEATURES.iter().enumerate() {
        let Some(bounds) = thresholds.feature_bounds.get(*feature) else {
            continue;
        };
        let value = weighted_features[idx];
        if value < bounds.min || value > bounds.max {
            feature_bounds_violations.push(format!(
                "{feature}={:.4} outside [{:.4}, {:.4}]",
                value, bounds.min, bounds.max
            ));
        }
    }
    Ok(UncertaintyMetrics {
        max_probability,
        probability_margin,
        entropy,
        feature_distance,
        feature_bounds_violations,
    })
}

fn normalized_entropy(probabilities: &[f64]) -> Result<f64> {
    validate_probability_distribution(probabilities, "entropy")?;
    let entropy = probabilities
        .iter()
        .filter(|prob| **prob > 0.0)
        .map(|prob| -prob * prob.ln())
        .sum::<f64>();
    let normalized = entropy / (probabilities.len() as f64).ln();
    if !normalized.is_finite() {
        return Err(NetdiagError::Ml(
            "model probability entropy is not finite".to_string(),
        ));
    }
    Ok(normalized)
}

pub fn load_or_train_model(model_dir: &Path) -> Result<RustMlModel> {
    Ok(
        load_model_bundle_snapshot_with_policy(model_dir, ModelLoadPolicy::AllowSyntheticFallback)?
            .model,
    )
}

pub fn load_existing_model(model_dir: &Path) -> Result<RustMlModel> {
    Ok(load_existing_model_bundle_snapshot(model_dir)?.model)
}

#[derive(Debug, Clone)]
pub struct ModelBundleIdentity {
    pub manifest: ModelManifest,
    pub model_file_hash_sha256: String,
    pub model_manifest_hash_sha256: String,
    pub generation: Option<String>,
}

pub fn load_existing_model_bundle_identity(model_dir: &Path) -> Result<ModelBundleIdentity> {
    Ok(load_existing_model_bundle_snapshot(model_dir)?.identity())
}

/// Loads and validates the current model bundle identity when one is present.
///
/// A genuinely absent bundle is `Ok(None)`. Incomplete, tampered, inaccessible,
/// or otherwise invalid bundles remain explicit errors.
pub fn load_existing_model_bundle_identity_if_present(
    model_dir: &Path,
) -> Result<Option<ModelBundleIdentity>> {
    match path_status(model_dir)? {
        PathStatus::Missing => Ok(None),
        PathStatus::Directory => Ok(load_existing_model_bundle_snapshot_if_present(model_dir)?
            .map(|snapshot| snapshot.identity())),
        PathStatus::RegularFile | PathStatus::Other => Err(NetdiagError::Ml(format!(
            "model bundle path is not a regular, non-symlink directory: {}",
            model_dir.display()
        ))),
    }
}

pub(crate) fn validate_model_bundle_for_artifact_root_migration(model_dir: &Path) -> Result<bool> {
    model_bundle::validate_for_artifact_root_migration(model_dir)
}

/// Publishes a manifest-only update as a new immutable generation if the
/// caller's source manifest is still current.
pub fn replace_model_manifest_if_current(
    model_dir: &Path,
    expected_manifest_hash_sha256: &str,
    updated_manifest: &ModelManifest,
) -> Result<ModelBundleIdentity> {
    replace_model_manifest_snapshot_if_current(
        model_dir,
        expected_manifest_hash_sha256,
        updated_manifest,
    )
    .map(|snapshot| snapshot.identity())
}

pub(crate) fn replace_model_manifest_snapshot_if_current(
    model_dir: &Path,
    expected_manifest_hash_sha256: &str,
    updated_manifest: &ModelManifest,
) -> Result<ModelBundleSnapshot> {
    model_bundle::replace_manifest_if_current(
        model_dir,
        expected_manifest_hash_sha256,
        updated_manifest,
    )
}

pub fn train_model_from_jsonl(
    dataset_path: impl AsRef<Path>,
    model_dir: impl AsRef<Path>,
) -> Result<ModelManifest> {
    train_model_from_jsonl_with_validation(dataset_path, model_dir, 0.0)
}

pub fn train_model_from_jsonl_with_validation(
    dataset_path: impl AsRef<Path>,
    model_dir: impl AsRef<Path>,
    validation_split: f64,
) -> Result<ModelManifest> {
    train_model_from_jsonl_with_options(
        dataset_path,
        model_dir,
        TrainingOptions {
            validation_split,
            ..TrainingOptions::default()
        },
    )
}

pub fn train_model_from_jsonl_with_options(
    dataset_path: impl AsRef<Path>,
    model_dir: impl AsRef<Path>,
    options: TrainingOptions,
) -> Result<ModelManifest> {
    let dataset_path = dataset_path.as_ref();
    let model_dir = model_dir.as_ref();
    ensure_publication_supported(model_dir)?;
    let options = normalize_training_options(options)?;
    let prepared_dataset = prepare_training_dataset(dataset_path)?;
    let dataset_hash = prepared_dataset.hash_sha256;
    let rows = prepared_dataset
        .rows
        .into_iter()
        .map(|row| FeatureTrainingRow {
            label: row.label,
            features: row.features,
        })
        .collect::<Vec<_>>();
    let dataset_rows = rows.len();
    let mut gate_failures = Vec::new();
    if options.validation_split > 0.0 && !options.stratified {
        gate_failures.push(
            "training gate requires stratified validation when --validation-split is greater than 0"
                .to_string(),
        );
    }
    let dataset_labels = rows.iter().map(|row| row.label).collect::<BTreeSet<_>>();
    let (training_rows, validation_rows) = partition_training_rows(&rows, options);
    if options.min_rows_per_label > 0 {
        let distribution = label_distribution(&training_rows);
        for label in FaultLabel::ALL {
            let count = distribution
                .get(label.as_str())
                .copied()
                .unwrap_or_default();
            if count < options.min_rows_per_label {
                gate_failures.push(format!(
                    "training split label {} has {} rows, below required {}",
                    label.as_str(),
                    count,
                    options.min_rows_per_label
                ));
            }
        }
    }
    let gate = ModelTrainingGate {
        passed: gate_failures.is_empty(),
        rows: dataset_rows,
        dataset_rows,
        training_rows: training_rows.len(),
        validation_rows: validation_rows.len(),
        min_rows_per_label: options.min_rows_per_label,
        validation_split: options.validation_split,
        stratified: options.stratified,
        failures: gate_failures,
    };
    if !gate.passed {
        return Err(NetdiagError::Ml(format!(
            "dataset training gate failed: {}",
            gate.failures.join("; ")
        )));
    }
    let model = train_model_from_feature_rows(&training_rows)?;
    let evaluation = if validation_rows.is_empty() {
        None
    } else {
        Some(evaluate_model(&model, &validation_rows, &dataset_labels)?)
    };
    let mut manifest = build_model_manifest(
        &model,
        ModelManifestBuild {
            training_source: format!("jsonl:{}", dataset_path.display()),
            training_examples: training_rows.len(),
            label_distribution: label_distribution(&training_rows),
            synthetic_fallback: false,
            dataset_hash_sha256: Some(dataset_hash),
            training_config: Some(ModelTrainingConfig {
                validation_split: options.validation_split,
                shuffle_seed: options.shuffle_seed,
                stratified: options.stratified,
                min_rows_per_label: options.min_rows_per_label,
            }),
            uncertainty_thresholds: Some(uncertainty_thresholds_from_rows(&training_rows, &model)?),
        },
    )?;
    manifest.evaluation = evaluation;
    manifest.training_gate = Some(gate);
    write_model_bundle(model_dir, &model, &manifest)
}

#[cfg(test)]
fn train_default_model() -> Result<RustMlModel> {
    train_model_from_feature_rows(&synthetic_training_rows())
}

fn synthetic_training_rows() -> Vec<FeatureTrainingRow> {
    let mut rng = StdRng::seed_from_u64(2026);
    let mut rows = Vec::new();

    for (label_idx, baseline) in BASELINES.iter().enumerate() {
        for _ in 0..130 {
            let row: Vec<f64> = baseline
                .iter()
                .map(|value| {
                    let std = (value.abs() * 0.15) + 0.01;
                    Normal::new(*value, std)
                        .expect("positive std")
                        .sample(&mut rng)
                        .max(0.0)
                })
                .collect();
            rows.push(FeatureTrainingRow {
                label: FaultLabel::from_index(label_idx)
                    .expect("synthetic baseline indexes are aligned with FaultLabel::ALL"),
                features: row,
            });
        }
    }

    rows
}

fn train_model_from_feature_rows(rows: &[FeatureTrainingRow]) -> Result<RustMlModel> {
    let features = rows
        .iter()
        .map(|row| row.features.clone())
        .collect::<Vec<_>>();
    let targets = rows.iter().map(|row| row.label.index()).collect::<Vec<_>>();
    fit_model(&features, &targets)
}

fn normalize_training_options(options: TrainingOptions) -> Result<TrainingOptions> {
    if !options.validation_split.is_finite() || !(0.0..=0.8).contains(&options.validation_split) {
        return Err(NetdiagError::Ml(format!(
            "validation_split must be finite and between 0.0 and 0.8, got {}",
            options.validation_split
        )));
    }
    Ok(TrainingOptions {
        validation_split: options.validation_split,
        shuffle_seed: options.shuffle_seed,
        stratified: options.stratified,
        min_rows_per_label: options.min_rows_per_label,
    })
}

fn partition_training_rows(
    rows: &[FeatureTrainingRow],
    options: TrainingOptions,
) -> (Vec<FeatureTrainingRow>, Vec<FeatureTrainingRow>) {
    if rows.len() < 3 || options.validation_split <= 0.0 {
        return (
            ordered_rows(rows, options.shuffle_seed)
                .into_iter()
                .map(|(_, row)| row)
                .collect(),
            Vec::new(),
        );
    }

    if options.stratified {
        let mut training_rows = Vec::new();
        let mut validation_rows = Vec::new();
        for label in FaultLabel::ALL {
            let bucket = rows
                .iter()
                .enumerate()
                .filter(|(_, row)| row.label == label)
                .map(|(idx, row)| (idx, row.clone()))
                .collect::<Vec<_>>();
            if bucket.is_empty() {
                continue;
            }
            let ordered = order_indexed_rows(bucket, options.shuffle_seed);
            let validation_count =
                validation_count(ordered.len(), options.validation_split).min(ordered.len() - 1);
            let split_at = ordered.len().saturating_sub(validation_count);
            training_rows.extend(ordered[..split_at].iter().map(|(_, row)| row.clone()));
            validation_rows.extend(ordered[split_at..].iter().map(|(_, row)| row.clone()));
        }
        (training_rows, validation_rows)
    } else {
        let ordered = ordered_rows(rows, options.shuffle_seed);
        let split_at = validation_split_index(ordered.len(), options.validation_split);
        let (training_rows, validation_rows) = ordered.split_at(split_at);
        (
            training_rows.iter().map(|(_, row)| row.clone()).collect(),
            validation_rows.iter().map(|(_, row)| row.clone()).collect(),
        )
    }
}

fn ordered_rows(
    rows: &[FeatureTrainingRow],
    seed: Option<u64>,
) -> Vec<(usize, FeatureTrainingRow)> {
    let indexed = rows
        .iter()
        .enumerate()
        .map(|(idx, row)| (idx, row.clone()))
        .collect::<Vec<_>>();
    order_indexed_rows(indexed, seed)
}

fn order_indexed_rows(
    mut rows: Vec<(usize, FeatureTrainingRow)>,
    seed: Option<u64>,
) -> Vec<(usize, FeatureTrainingRow)> {
    if let Some(seed) = seed {
        rows.sort_by_key(|(idx, row)| seeded_row_key(seed, *idx, row));
    }
    rows
}

fn seeded_row_key(seed: u64, idx: usize, row: &FeatureTrainingRow) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(idx.to_le_bytes());
    hasher.update((row.label.index() as u64).to_le_bytes());
    for value in &row.features {
        hasher.update(value.to_le_bytes());
    }
    hasher.finalize().to_vec()
}

fn validation_split_index(len: usize, split: f64) -> usize {
    if len < 3 || !split.is_finite() || split <= 0.0 {
        return len;
    }
    len.saturating_sub(validation_count(len, split)).max(1)
}

fn validation_count(len: usize, split: f64) -> usize {
    if len < 2 || !split.is_finite() || split <= 0.0 {
        return 0;
    }
    let validation = ((len as f64) * split.clamp(0.0, 0.8)).round() as usize;
    validation.max(1).min(len.saturating_sub(1))
}

fn evaluate_model(
    model: &RustMlModel,
    rows: &[FeatureTrainingRow],
    expected_labels: &BTreeSet<FaultLabel>,
) -> Result<ModelEvaluation> {
    let mut correct = 0usize;
    let mut confusion = dense_confusion_matrix();
    for row in rows {
        let predicted = predict_label(model, &row.features)?;
        if predicted == row.label {
            correct += 1;
        }
        *confusion
            .entry(row.label.as_str().to_string())
            .or_default()
            .entry(predicted.as_str().to_string())
            .or_default() += 1;
    }
    let accuracy = correct as f64 / rows.len().max(1) as f64;
    let per_label = FaultLabel::ALL
        .iter()
        .map(|label| {
            (
                label.as_str().to_string(),
                label_metrics(*label, &confusion),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let macro_f1 =
        per_label.values().map(|metrics| metrics.f1).sum::<f64>() / FaultLabel::ALL.len() as f64;
    let validation_distribution =
        rows.iter()
            .fold(BTreeMap::<FaultLabel, usize>::new(), |mut counts, row| {
                *counts.entry(row.label).or_default() += 1;
                counts
            });
    let missing_validation_labels = expected_labels
        .iter()
        .filter(|label| {
            validation_distribution
                .get(label)
                .copied()
                .unwrap_or_default()
                == 0
        })
        .map(|label| label.as_str().to_string())
        .collect::<Vec<_>>();
    let mut warnings = missing_validation_labels
        .iter()
        .map(|label| format!("validation set has no {label} examples"))
        .collect::<Vec<_>>();
    for label in expected_labels {
        if validation_distribution
            .get(label)
            .copied()
            .unwrap_or_default()
            == 1
        {
            warnings.push(format!(
                "validation set has only 1 {} example; evaluation is noisy",
                label.as_str()
            ));
        }
    }
    Ok(ModelEvaluation {
        validation_examples: rows.len(),
        accuracy: round4(accuracy),
        macro_f1: round4(macro_f1),
        degraded: !warnings.is_empty(),
        warnings,
        missing_validation_labels,
        per_label,
        confusion_matrix: confusion,
    })
}

fn predict_label(model: &RustMlModel, features: &[f64]) -> Result<FaultLabel> {
    validate_model_structure(model)?;
    let scaled = scale_row(features, &model.means, &model.stds)?;
    let x = Array2::from_shape_vec((1, FEATURES.len()), scaled)
        .map_err(|err| NetdiagError::Ml(err.to_string()))?;
    let probabilities = model.model.predict_probabilities(&x);
    let classes = model.model.classes().to_vec();
    let probabilities = probabilities.row(0).to_vec();
    validate_probability_distribution(&probabilities, "evaluation model")?;
    validate_probability_classes(&classes, probabilities.len())?;
    let best_idx = probabilities
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| left.total_cmp(right))
        .map(|(idx, _)| idx)
        .ok_or_else(|| {
            NetdiagError::Ml("evaluation model returned no probabilities".to_string())
        })?;
    let class_index = classes.get(best_idx).copied().ok_or_else(|| {
        NetdiagError::Ml(format!(
            "model returned probability index {best_idx} without a matching class"
        ))
    })?;
    FaultLabel::from_index(class_index).ok_or_else(|| {
        NetdiagError::Ml(format!(
            "model returned unknown class index {class_index}; expected one of the six known labels"
        ))
    })
}

fn dense_confusion_matrix() -> BTreeMap<String, BTreeMap<String, usize>> {
    FaultLabel::ALL
        .iter()
        .map(|actual| {
            (
                actual.as_str().to_string(),
                FaultLabel::ALL
                    .iter()
                    .map(|predicted| (predicted.as_str().to_string(), 0usize))
                    .collect(),
            )
        })
        .collect()
}

fn label_metrics(
    label: FaultLabel,
    confusion: &BTreeMap<String, BTreeMap<String, usize>>,
) -> LabelMetrics {
    let key = label.as_str();
    let tp = confusion
        .get(key)
        .and_then(|predicted| predicted.get(key))
        .copied()
        .unwrap_or(0) as f64;
    let predicted_total = confusion
        .values()
        .map(|predicted| predicted.get(key).copied().unwrap_or(0))
        .sum::<usize>() as f64;
    let support = confusion
        .get(key)
        .map(|predicted| predicted.values().sum::<usize>() as f64)
        .unwrap_or(0.0);
    let precision = if predicted_total > 0.0 {
        tp / predicted_total
    } else {
        0.0
    };
    let recall = if support > 0.0 { tp / support } else { 0.0 };
    let f1 = if precision + recall > 0.0 {
        (2.0 * precision * recall) / (precision + recall)
    } else {
        0.0
    };
    LabelMetrics {
        support: support as usize,
        precision: round4(precision),
        recall: round4(recall),
        f1: round4(f1),
    }
}

fn fit_model(rows: &[Vec<f64>], targets: &[usize]) -> Result<RustMlModel> {
    if rows.is_empty() {
        return Err(NetdiagError::Ml(
            "training dataset must contain at least one row".to_string(),
        ));
    }
    if rows.len() != targets.len() {
        return Err(NetdiagError::Ml(
            "training features and labels have different lengths".to_string(),
        ));
    }
    let distinct_labels = targets.iter().copied().collect::<BTreeSet<_>>();
    if distinct_labels.len() < 2 {
        return Err(NetdiagError::Ml(
            "training dataset must contain at least two labels".to_string(),
        ));
    }
    for (row_idx, row) in rows.iter().enumerate() {
        if row.len() != FEATURES.len() {
            return Err(NetdiagError::Ml(format!(
                "training row {} has {} features, expected {}",
                row_idx + 1,
                row.len(),
                FEATURES.len()
            )));
        }
        if row.iter().any(|value| !value.is_finite()) {
            return Err(NetdiagError::Ml(format!(
                "training row {} contains non-finite features",
                row_idx + 1
            )));
        }
    }

    let means = (0..FEATURES.len())
        .map(|idx| {
            let average = mean(rows.iter().map(|row| row[idx]));
            if !average.is_finite() {
                return Err(NetdiagError::Ml(format!(
                    "training feature {} produced a non-finite mean",
                    FEATURES[idx]
                )));
            }
            Ok(average)
        })
        .collect::<Result<Vec<_>>>()?;
    let stds = (0..FEATURES.len())
        .map(|idx| {
            let scale = rows
                .iter()
                .map(|row| row[idx].abs())
                .fold(0.0_f64, f64::max);
            if scale == 0.0 {
                return Ok(1e-9);
            }
            let normalized_mean = mean(rows.iter().map(|row| row[idx] / scale));
            let normalized_variance = mean(rows.iter().map(|row| {
                let delta = row[idx] / scale - normalized_mean;
                delta * delta
            }));
            let std = normalized_variance.sqrt() * scale;
            if !std.is_finite() {
                return Err(NetdiagError::Ml(format!(
                    "training feature {} produced a non-finite standard deviation",
                    FEATURES[idx]
                )));
            }
            Ok(std.max(1e-9))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut scaled_rows = Vec::with_capacity(rows.len() * FEATURES.len());
    for row in rows {
        scaled_rows.extend(scale_row(row, &means, &stds)?);
    }
    let x = Array2::from_shape_vec((rows.len(), FEATURES.len()), scaled_rows)
        .map_err(|err| NetdiagError::Ml(err.to_string()))?;
    let y = Array1::from(targets.to_vec());
    let dataset = Dataset::new(x, y);
    let model = MultiLogisticRegression::default()
        .alpha(0.1)
        .max_iterations(150)
        .fit(&dataset)
        .map_err(|err| NetdiagError::Ml(err.to_string()))?;
    Ok(RustMlModel { model, means, stds })
}

fn feature_map_to_vec(features: &BTreeMap<String, f64>) -> Result<Vec<f64>> {
    FEATURES
        .iter()
        .map(|name| {
            let value = features.get(*name).copied().ok_or_else(|| {
                NetdiagError::Ml(format!("training feature map is missing {name}"))
            })?;
            if value.is_finite() {
                Ok(value)
            } else {
                Err(NetdiagError::Ml(format!(
                    "training feature {name} is not finite"
                )))
            }
        })
        .collect()
}

/// Explicitly replaces the current bundle with a fresh synthetic bundle.
///
/// The model is trained before acquiring the write lock. Publishing is then
/// serialized with all bundle readers and writers, and the v2 manifest binds
/// the exact model bytes. This is the only reset API used by the desktop app.
pub fn rebuild_synthetic_model_bundle(model_dir: &Path) -> Result<RustMlModel> {
    ensure_publication_supported(model_dir)?;
    let (model, manifest) = synthetic_model_bundle()?;
    write_model_bundle(model_dir, &model, &manifest)?;
    Ok(model)
}

/// Explicitly replaces the model bundle while holding the owning artifact root capability.
pub fn rebuild_synthetic_model_bundle_in_artifact_root(
    artifact_root: &Path,
) -> Result<RustMlModel> {
    let capability = crate::storage::prepare_artifact_root(artifact_root)?;
    crate::storage::with_artifact_root_capability(&capability, |_| {
        rebuild_synthetic_model_bundle(&artifact_root.join("model"))
    })
}

fn synthetic_model_bundle() -> Result<(RustMlModel, ModelManifest)> {
    let rows = synthetic_training_rows();
    let model = train_model_from_feature_rows(&rows)?;
    let manifest = build_model_manifest(
        &model,
        ModelManifestBuild {
            training_source: "synthetic_fallback".to_string(),
            training_examples: BASELINES.len() * 130,
            label_distribution: synthetic_label_distribution(130),
            synthetic_fallback: true,
            dataset_hash_sha256: None,
            training_config: Some(ModelTrainingConfig {
                validation_split: 0.0,
                shuffle_seed: Some(2026),
                stratified: false,
                min_rows_per_label: 0,
            }),
            uncertainty_thresholds: Some(uncertainty_thresholds_from_rows(&rows, &model)?),
        },
    )?;
    Ok((model, manifest))
}

struct ModelManifestBuild {
    training_source: String,
    training_examples: usize,
    label_distribution: BTreeMap<String, usize>,
    synthetic_fallback: bool,
    dataset_hash_sha256: Option<String>,
    training_config: Option<ModelTrainingConfig>,
    uncertainty_thresholds: Option<ModelUncertaintyThresholds>,
}

fn build_model_manifest(model: &RustMlModel, build: ModelManifestBuild) -> Result<ModelManifest> {
    Ok(ModelManifest {
        schema_version: MODEL_MANIFEST_SCHEMA.to_string(),
        model_name: "netdiag_fault_classifier".to_string(),
        model_kind: "linfa_multinomial_logistic_regression".to_string(),
        created_at: Utc::now(),
        training_source: build.training_source,
        dataset_hash_sha256: build.dataset_hash_sha256,
        dataset_id: None,
        dataset_manifest_hash_sha256: None,
        model_file: MODEL_FILE_NAME.to_string(),
        model_file_hash_sha256: String::new(),
        feature_names: FEATURES.iter().map(|name| (*name).to_string()).collect(),
        labels: class_labels(model)?,
        training_examples: build.training_examples,
        label_distribution: build.label_distribution,
        feature_count: FEATURES.len(),
        synthetic_fallback: build.synthetic_fallback,
        training_config: build.training_config,
        evaluation: None,
        training_gate: None,
        uncertainty_thresholds: build.uncertainty_thresholds,
    })
}

fn class_labels(model: &RustMlModel) -> Result<Vec<String>> {
    model
        .model
        .classes()
        .iter()
        .map(|class| {
            FaultLabel::from_index(*class)
                .map(|label| label.as_str().to_string())
                .ok_or_else(|| {
                    NetdiagError::Ml(format!(
                        "model manifest cannot represent unknown class index {class}"
                    ))
                })
        })
        .collect()
}

fn uncertainty_thresholds_from_rows(
    rows: &[FeatureTrainingRow],
    model: &RustMlModel,
) -> Result<ModelUncertaintyThresholds> {
    let mut thresholds = ModelUncertaintyThresholds::default();
    if rows.is_empty() {
        return Ok(thresholds);
    }

    let mut max_distance = 0.0_f64;
    for row in rows {
        let scaled = scale_row(&row.features, &model.means, &model.stds)?;
        max_distance = max_distance.max(finite_l2_norm(&scaled, "scaled training features")?);
    }
    let expanded_distance = max_distance * 2.5;
    if !expanded_distance.is_finite() {
        return Err(NetdiagError::Ml(
            "training feature-distance threshold exceeds the finite f64 range".to_string(),
        ));
    }
    thresholds.max_feature_distance = expanded_distance.max(8.0);

    for (idx, feature) in FEATURES.iter().enumerate() {
        let min = rows
            .iter()
            .map(|row| row.features[idx])
            .fold(f64::INFINITY, f64::min);
        let max = rows
            .iter()
            .map(|row| row.features[idx])
            .fold(f64::NEG_INFINITY, f64::max);
        if !min.is_finite() || !max.is_finite() {
            continue;
        }
        let quarter_span = max * 0.25 - min * 0.25;
        let std = model.stds.get(idx).copied().ok_or_else(|| {
            NetdiagError::Ml(format!(
                "model scaler is missing standard deviation for {feature}"
            ))
        })?;
        let scaled_std = std * 4.0;
        if !quarter_span.is_finite() || !scaled_std.is_finite() {
            return Err(NetdiagError::Ml(format!(
                "training feature bounds for {feature} exceed the finite f64 range"
            )));
        }
        let padding = quarter_span.abs().max(scaled_std);
        let lower_bound = if min <= padding { 0.0 } else { min - padding };
        let upper_bound = max + padding;
        if !lower_bound.is_finite() || !upper_bound.is_finite() {
            return Err(NetdiagError::Ml(format!(
                "training feature bounds for {feature} exceed the finite f64 range"
            )));
        }
        thresholds.feature_bounds.insert(
            (*feature).to_string(),
            FeatureBounds {
                min: lower_bound,
                max: upper_bound,
            },
        );
    }

    validate_uncertainty_thresholds(&thresholds)?;
    Ok(thresholds)
}

fn label_distribution(rows: &[FeatureTrainingRow]) -> BTreeMap<String, usize> {
    let mut distribution = BTreeMap::new();
    for row in rows {
        *distribution
            .entry(row.label.as_str().to_string())
            .or_default() += 1;
    }
    distribution
}

fn synthetic_label_distribution(samples_per_label: usize) -> BTreeMap<String, usize> {
    FaultLabel::ALL
        .iter()
        .map(|label| (label.as_str().to_string(), samples_per_label))
        .collect()
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_path(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer).with_path(path)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn round4(value: f64) -> f64 {
    round_decimal(value, 10_000.0)
}

fn validate_model_structure(model: &RustMlModel) -> Result<()> {
    if model.means.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "stored model means has {} entries, expected {}",
            model.means.len(),
            FEATURES.len()
        )));
    }
    if model.stds.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "stored model stds has {} entries, expected {}",
            model.stds.len(),
            FEATURES.len()
        )));
    }
    if model.means.iter().any(|value| !value.is_finite()) {
        return Err(NetdiagError::Ml(
            "stored model means contain non-finite values".to_string(),
        ));
    }
    if model
        .stds
        .iter()
        .any(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err(NetdiagError::Ml(
            "stored model stds must be finite and positive".to_string(),
        ));
    }
    let classes = model.model.classes();
    if classes.len() < 2 {
        return Err(NetdiagError::Ml(
            "stored model must contain at least two classes".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for class in classes {
        if *class >= FaultLabel::ALL.len() {
            return Err(NetdiagError::Ml(format!(
                "stored model class index {} is outside known fault labels",
                class
            )));
        }
        if !seen.insert(*class) {
            return Err(NetdiagError::Ml(format!(
                "stored model class index {} appears more than once",
                class
            )));
        }
    }
    let params = model.model.params();
    let shape = params.shape();
    if shape.len() != 2 || shape[0] != FEATURES.len() || shape[1] != classes.len() {
        return Err(NetdiagError::Ml(format!(
            "stored model parameter shape {:?} does not match {} features and {} classes",
            shape,
            FEATURES.len(),
            classes.len()
        )));
    }
    if params.iter().any(|value| !value.is_finite()) {
        return Err(NetdiagError::Ml(
            "stored model parameters contain non-finite values".to_string(),
        ));
    }
    let intercept = model.model.intercept();
    if intercept.len() != classes.len() {
        return Err(NetdiagError::Ml(format!(
            "stored model intercept has {} entries, expected {} classes",
            intercept.len(),
            classes.len()
        )));
    }
    if intercept.iter().any(|value| !value.is_finite()) {
        return Err(NetdiagError::Ml(
            "stored model intercept contains non-finite values".to_string(),
        ));
    }
    Ok(())
}

fn validate_model_manifest(
    manifest: &ModelManifest,
    model: &RustMlModel,
    actual_model_file_hash_sha256: &str,
) -> Result<()> {
    validate_model_manifest_metadata(manifest, model)?;
    if !is_lowercase_sha256(&manifest.model_file_hash_sha256) {
        return Err(NetdiagError::Ml(format!(
            "model manifest model_file_hash_sha256 must be a lowercase SHA-256 for {MODEL_FILE_NAME}"
        )));
    }
    if manifest.model_file_hash_sha256 != actual_model_file_hash_sha256 {
        return Err(NetdiagError::Ml(format!(
            "model bundle hash mismatch for {}: manifest={} actual={actual_model_file_hash_sha256}",
            MODEL_FILE_NAME, manifest.model_file_hash_sha256
        )));
    }
    Ok(())
}

fn validate_model_manifest_metadata(manifest: &ModelManifest, model: &RustMlModel) -> Result<()> {
    if manifest.schema_version != MODEL_MANIFEST_SCHEMA {
        return Err(NetdiagError::Ml(format!(
            "unsupported model manifest schema {}; expected {MODEL_MANIFEST_SCHEMA}; retrain or explicitly rebuild the model bundle",
            manifest.schema_version
        )));
    }
    validate_model_manifest_payload(manifest, model)
}

fn validate_model_manifest_payload(manifest: &ModelManifest, model: &RustMlModel) -> Result<()> {
    if manifest.model_file != MODEL_FILE_NAME {
        return Err(NetdiagError::Ml(format!(
            "model manifest points at {}, expected {}",
            manifest.model_file, MODEL_FILE_NAME
        )));
    }
    if manifest.feature_count != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "model manifest feature_count is {}, expected {}",
            manifest.feature_count,
            FEATURES.len()
        )));
    }
    let expected_features = FEATURES
        .iter()
        .map(|feature| (*feature).to_string())
        .collect::<Vec<_>>();
    if manifest.feature_names != expected_features {
        return Err(NetdiagError::Ml(
            "model manifest feature_names do not match inference features".to_string(),
        ));
    }
    let expected_labels = class_labels(model)?;
    if manifest.labels != expected_labels {
        return Err(NetdiagError::Ml(
            "model manifest labels do not match stored model classes".to_string(),
        ));
    }
    if let Some(thresholds) = &manifest.uncertainty_thresholds {
        validate_uncertainty_thresholds(thresholds)?;
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod numeric_tests;
#[cfg(test)]
mod tests;
