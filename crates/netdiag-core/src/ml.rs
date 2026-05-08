use crate::dataset::{DatasetValidationOptions, validate_dataset_jsonl_with_options};
use crate::error::{IoContext, NetdiagError, Result};
use crate::models::{
    DiagnosisStatus, FaultLabel, FeatureBounds, FeatureImportance, HilFeedbackRecord, HilState,
    LabelMetrics, MetricProvenance, MetricQuality, MlResult, ModelEvaluation, ModelManifest,
    ModelTrainingConfig, ModelTrainingGate, ModelUncertaintyThresholds, Prediction, Recommendation,
    RecommendationKind, TelemetryWindow, TraceRecord, UncertaintyAssessment, UncertaintyReasonCode,
};
use crate::report::Report;
use crate::storage::{list_run_locations, read_json, save_json_atomic};
use crate::telemetry::{extract_features_from_windows, mean, summarize_telemetry};
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
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

pub const MODEL_FILE_NAME: &str = "rust_logistic_model.json";
pub const MODEL_MANIFEST_FILE_NAME: &str = "model_manifest.json";

pub const FEATURES: [&str; 11] = [
    "latency_mean",
    "latency_p95",
    "jitter_std",
    "loss_rate",
    "retrans_rate",
    "timeout",
    "retry",
    "throughput",
    "dns_events",
    "tls_events",
    "quic",
];

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelCacheKey {
    canonical_dir: PathBuf,
    manifest_hash: Option<String>,
    model_file_hash: String,
}

#[derive(Debug, Clone)]
struct ModelCacheEntry {
    key: ModelCacheKey,
    model: RustMlModel,
}

static MODEL_CACHE: OnceLock<Mutex<Vec<ModelCacheEntry>>> = OnceLock::new();
const MODEL_CACHE_CAPACITY: usize = 4;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackTrainingRow {
    pub label: FaultLabel,
    pub final_label: FaultLabel,
    pub run_id: String,
    pub source: String,
    pub features: BTreeMap<String, f64>,
    pub rule_labels: Vec<String>,
    pub ml_top: String,
    pub ml_top_prob: f64,
    pub recommendation_id: String,
    pub feedback_state: HilState,
    pub feedback_notes: String,
    pub reviewer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackExportSummary {
    pub output: String,
    pub rows: usize,
    pub skipped_runs: usize,
    pub dataset_hash_sha256: String,
}

#[derive(Debug, Deserialize)]
struct TrainingJsonlRow {
    #[serde(default)]
    label: Option<FaultLabel>,
    #[serde(default)]
    final_label: Option<FaultLabel>,
    #[serde(default)]
    records: Vec<TraceRecord>,
    #[serde(default)]
    features: BTreeMap<String, f64>,
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
    let model_dir = model_dir.as_ref();
    let model = load_model_with_policy(model_dir, load_policy)?;
    let model_path = model_dir.join(MODEL_FILE_NAME);
    let manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
    let model_manifest = read_json(&manifest_path)
        .ok()
        .and_then(|value| serde_json::from_value::<ModelManifest>(value).ok());
    let model_file_hash = model_path
        .exists()
        .then(|| sha256_file(&model_path))
        .transpose()?;
    let model_manifest_hash = manifest_path
        .exists()
        .then(|| sha256_file(&manifest_path))
        .transpose()?;
    let raw_features = extract_features_from_windows(windows);
    let feature_quality = feature_quality_map(provenance);
    let weighted_features = apply_feature_quality(&raw_features, &feature_quality);
    let scaled = scale_row(&weighted_features, &model.means, &model.stds)?;
    let x = Array2::from_shape_vec((1, FEATURES.len()), scaled.clone())
        .map_err(|err| NetdiagError::Ml(err.to_string()))?;
    let probabilities = model.model.predict_probabilities(&x);
    let classes = model.model.classes().to_vec();
    let calibrated =
        calibrate_probabilities(probabilities.row(0).to_vec(), &classes, &weighted_features);
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
        model_manifest.as_ref(),
    );

    let top_class_position = ranking
        .first()
        .and_then(|prediction| {
            classes
                .iter()
                .position(|class| *class == prediction.label.index())
        })
        .unwrap_or(0);
    let params = model.model.params();
    let mut top_features: Vec<FeatureImportance> = FEATURES
        .iter()
        .enumerate()
        .map(|(idx, name)| FeatureImportance {
            name: (*name).to_string(),
            importance: (scaled[idx]
                * params
                    .get((idx, top_class_position))
                    .copied()
                    .unwrap_or(0.0))
            .abs(),
        })
        .collect();
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
        model_manifest,
        model_manifest_hash,
        model_file_hash,
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
                    .unwrap_or(MetricQuality::Measured),
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
                .unwrap_or(MetricQuality::Measured);
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
) -> UncertaintyAssessment {
    let thresholds = manifest
        .and_then(|manifest| manifest.uncertainty_thresholds.clone())
        .unwrap_or_default();
    let max_probability = ranking
        .first()
        .map(|prediction| prediction.prob)
        .unwrap_or(0.0);
    let second_probability = ranking
        .get(1)
        .map(|prediction| prediction.prob)
        .unwrap_or(0.0);
    let probability_margin = max_probability - second_probability;
    let entropy = normalized_entropy(ranking.iter().map(|prediction| prediction.prob));
    let feature_distance = scaled_features
        .iter()
        .map(|value| value * value)
        .sum::<f64>()
        .sqrt();
    let mut feature_bounds_violations = Vec::new();
    for (idx, feature) in FEATURES.iter().enumerate() {
        let Some(bounds) = thresholds.feature_bounds.get(*feature) else {
            continue;
        };
        let Some(value) = weighted_features.get(idx).copied() else {
            continue;
        };
        if value < bounds.min || value > bounds.max {
            feature_bounds_violations.push(format!(
                "{feature}={:.4} outside [{:.4}, {:.4}]",
                value, bounds.min, bounds.max
            ));
        }
    }

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

    UncertaintyAssessment {
        max_probability: round4(max_probability),
        probability_margin: round4(probability_margin),
        entropy: round4(entropy),
        feature_distance: round4(feature_distance),
        feature_bounds_violations,
        status,
        reasons,
        reason_codes,
    }
}

fn normalized_entropy(probabilities: impl Iterator<Item = f64>) -> f64 {
    let probs = probabilities.collect::<Vec<_>>();
    if probs.len() <= 1 {
        return 0.0;
    }
    let entropy = probs
        .iter()
        .filter(|prob| **prob > 0.0 && prob.is_finite())
        .map(|prob| -prob * prob.ln())
        .sum::<f64>();
    entropy / (probs.len() as f64).ln()
}

pub fn load_or_train_model(model_dir: &Path) -> Result<RustMlModel> {
    load_model_with_policy(model_dir, ModelLoadPolicy::AllowSyntheticFallback)
}

pub fn load_existing_model(model_dir: &Path) -> Result<RustMlModel> {
    load_model_with_policy(model_dir, ModelLoadPolicy::ExistingOnly)
}

fn load_model_with_policy(model_dir: &Path, load_policy: ModelLoadPolicy) -> Result<RustMlModel> {
    let model_path = model_dir.join(MODEL_FILE_NAME);
    let manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
    if model_path.exists() {
        let cache_key = model_cache_key(model_dir, &model_path, &manifest_path)?;
        if let Some(model) = lookup_model_cache(&cache_key) {
            validate_model_structure(&model)?;
            validate_or_create_manifest(model_dir, &manifest_path, &model, load_policy)?;
            return Ok(model);
        }
        let file = File::open(&model_path).with_path(&model_path)?;
        let reader = BufReader::new(file);
        let model = serde_json::from_reader::<_, RustMlModel>(reader).map_err(|err| {
            NetdiagError::Ml(format!(
                "cached model {} is not a valid Rust ML model: {err}",
                model_path.display()
            ))
        })?;
        validate_model_structure(&model)?;
        validate_or_create_manifest(model_dir, &manifest_path, &model, load_policy)?;
        insert_model_cache(
            model_cache_key(model_dir, &model_path, &manifest_path)?,
            &model,
        );
        return Ok(model);
    }

    if load_policy == ModelLoadPolicy::ExistingOnly {
        return Err(NetdiagError::Ml(format!(
            "model file {} is missing; train or provision a model bundle before running lab diagnostics",
            model_path.display()
        )));
    }

    std::fs::create_dir_all(model_dir).with_path(model_dir)?;
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
    write_model_bundle(model_dir, &model, &manifest)?;
    insert_model_cache(
        model_cache_key(model_dir, &model_path, &manifest_path)?,
        &model,
    );
    Ok(model)
}

fn validate_or_create_manifest(
    model_dir: &Path,
    manifest_path: &Path,
    model: &RustMlModel,
    load_policy: ModelLoadPolicy,
) -> Result<()> {
    if manifest_path.exists() {
        let manifest: ModelManifest = serde_json::from_value(read_json(manifest_path)?)?;
        validate_model_manifest(&manifest, model)?;
    } else if load_policy == ModelLoadPolicy::ExistingOnly {
        return Err(NetdiagError::Ml(format!(
            "model manifest {} is missing; train or provision a complete model bundle before running lab diagnostics",
            manifest_path.display()
        )));
    } else {
        let manifest = build_model_manifest(
            model,
            ModelManifestBuild {
                training_source: "cached_existing_model".to_string(),
                training_examples: 0,
                label_distribution: BTreeMap::new(),
                synthetic_fallback: false,
                dataset_hash_sha256: None,
                training_config: None,
                uncertainty_thresholds: None,
            },
        )?;
        save_json_atomic(model_dir.join(MODEL_MANIFEST_FILE_NAME), &manifest)?;
    }
    Ok(())
}

fn model_cache_key(
    model_dir: &Path,
    model_path: &Path,
    manifest_path: &Path,
) -> Result<ModelCacheKey> {
    Ok(ModelCacheKey {
        canonical_dir: canonical_model_dir(model_dir)?,
        manifest_hash: manifest_path
            .exists()
            .then(|| sha256_file(manifest_path))
            .transpose()?,
        model_file_hash: sha256_file(model_path)?,
    })
}

fn canonical_model_dir(model_dir: &Path) -> Result<PathBuf> {
    if let Ok(path) = model_dir.canonicalize() {
        return Ok(path);
    }
    if model_dir.is_absolute() {
        Ok(model_dir.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .map_err(|err| NetdiagError::Ml(format!("could not resolve current directory: {err}")))?
            .join(model_dir))
    }
}

fn lookup_model_cache(key: &ModelCacheKey) -> Option<RustMlModel> {
    let cache = MODEL_CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let mut cache = cache.lock().ok()?;
    let index = cache.iter().position(|entry| &entry.key == key)?;
    let entry = cache.remove(index);
    let model = entry.model.clone();
    cache.insert(0, entry);
    Some(model)
}

fn insert_model_cache(key: ModelCacheKey, model: &RustMlModel) {
    let cache = MODEL_CACHE.get_or_init(|| Mutex::new(Vec::new()));
    let Ok(mut cache) = cache.lock() else {
        return;
    };
    cache.retain(|entry| entry.key != key);
    cache.insert(
        0,
        ModelCacheEntry {
            key,
            model: model.clone(),
        },
    );
    if cache.len() > MODEL_CACHE_CAPACITY {
        cache.truncate(MODEL_CACHE_CAPACITY);
    }
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
    let options = normalize_training_options(options);
    let validation = validate_dataset_jsonl_with_options(
        dataset_path,
        DatasetValidationOptions {
            min_rows_per_label: 0,
        },
    )?;
    let mut gate_failures = validation.failures.clone();
    if options.validation_split > 0.0 && !options.stratified {
        gate_failures.push(
            "training gate requires stratified validation when --validation-split is greater than 0"
                .to_string(),
        );
    }
    let rows = read_training_jsonl(dataset_path)?;
    let dataset_hash = sha256_file(dataset_path)?;
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
        rows: validation.rows,
        dataset_rows: validation.rows,
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
    write_model_bundle(model_dir, &model, &manifest)?;
    Ok(manifest)
}

pub fn export_feedback_training_dataset(
    artifact_root: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<FeedbackExportSummary> {
    let artifact_root = artifact_root.as_ref();
    let output_path = output_path.as_ref();
    let mut rows = Vec::new();
    let mut skipped_runs = 0usize;

    for location in list_run_locations(artifact_root)? {
        let report_path = location.run_dir.join("report.json");
        let ml_path = location.run_dir.join("ml_result.json");
        let feedback_path = location.run_dir.join("hil_feedback.json");
        if !report_path.exists() || !ml_path.exists() || !feedback_path.exists() {
            skipped_runs += 1;
            continue;
        }

        let report: Report = serde_json::from_value(read_json(&report_path)?)?;
        let ml: MlResult = serde_json::from_value(read_json(&ml_path)?)?;
        let feedback: BTreeMap<String, HilFeedbackRecord> =
            serde_json::from_value(read_json(&feedback_path)?)?;
        feature_map_to_vec(&ml.features)?;

        let Some((final_label, recommendation, feedback_record)) =
            accepted_feedback_label(&report.recommendations, &feedback)
        else {
            skipped_runs += 1;
            continue;
        };

        rows.push(FeedbackTrainingRow {
            label: final_label,
            final_label,
            run_id: report.run_id,
            source: "hil_accepted".to_string(),
            features: ml.features,
            rule_labels: report.rule_vs_ml.rule_labels,
            ml_top: report.rule_vs_ml.ml_top,
            ml_top_prob: report.rule_vs_ml.ml_top_prob,
            recommendation_id: recommendation.recommendation_id,
            feedback_state: feedback_record.review.state,
            feedback_notes: feedback_record.review.notes,
            reviewer: feedback_record.review.reviewer,
        });
    }

    rows.sort_by(|left, right| {
        left.run_id
            .cmp(&right.run_id)
            .then_with(|| left.recommendation_id.cmp(&right.recommendation_id))
    });
    write_jsonl_atomic(output_path, &rows)?;
    let dataset_hash_sha256 = sha256_file(output_path)?;
    Ok(FeedbackExportSummary {
        output: output_path.display().to_string(),
        rows: rows.len(),
        skipped_runs,
        dataset_hash_sha256,
    })
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

fn normalize_training_options(options: TrainingOptions) -> TrainingOptions {
    TrainingOptions {
        validation_split: if options.validation_split.is_finite() {
            options.validation_split.clamp(0.0, 0.8)
        } else {
            0.0
        },
        shuffle_seed: options.shuffle_seed,
        stratified: options.stratified,
        min_rows_per_label: options.min_rows_per_label,
    }
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
    let best_idx = probabilities
        .row(0)
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| left.total_cmp(right))
        .map(|(idx, _)| idx)
        .unwrap_or(0);
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
        .map(|idx| mean(rows.iter().map(|row| row[idx])))
        .collect::<Vec<_>>();
    let stds = (0..FEATURES.len())
        .map(|idx| {
            let avg = means[idx];
            let variance = mean(rows.iter().map(|row| (row[idx] - avg).powi(2)));
            variance.sqrt().max(1e-9)
        })
        .collect::<Vec<_>>();

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

fn read_training_jsonl(path: &Path) -> Result<Vec<FeatureTrainingRow>> {
    let file = File::open(path).with_path(path)?;
    let reader = BufReader::new(file);
    let mut rows = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_path(path)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: TrainingJsonlRow = serde_json::from_str(trimmed).map_err(|err| {
            NetdiagError::Ml(format!(
                "training dataset {} has invalid JSON on line {}: {err}",
                path.display(),
                idx + 1
            ))
        })?;
        let label = parsed.label.or(parsed.final_label).ok_or_else(|| {
            NetdiagError::Ml(format!(
                "training dataset {} line {} is missing label",
                path.display(),
                idx + 1
            ))
        })?;
        let features = if parsed.records.is_empty() {
            if parsed.features.is_empty() {
                return Err(NetdiagError::Ml(format!(
                    "training dataset {} line {} must include records or features",
                    path.display(),
                    idx + 1
                )));
            }
            feature_map_to_vec(&parsed.features)?
        } else {
            let summary = summarize_telemetry(&parsed.records, 5)?;
            extract_features_from_windows(&summary.windows)
        };
        if features.iter().any(|value| !value.is_finite()) {
            return Err(NetdiagError::Ml(format!(
                "training dataset {} line {} contains non-finite features",
                path.display(),
                idx + 1
            )));
        }
        rows.push(FeatureTrainingRow { label, features });
    }

    if rows.is_empty() {
        return Err(NetdiagError::Ml(format!(
            "training dataset {} contains no rows",
            path.display()
        )));
    }
    Ok(rows)
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

fn write_model_bundle(
    model_dir: &Path,
    model: &RustMlModel,
    manifest: &ModelManifest,
) -> Result<()> {
    validate_model_structure(model)?;
    validate_model_manifest(manifest, model)?;
    std::fs::create_dir_all(model_dir).with_path(model_dir)?;
    save_json_atomic(model_dir.join(MODEL_FILE_NAME), model)?;
    save_json_atomic(model_dir.join(MODEL_MANIFEST_FILE_NAME), manifest)?;
    Ok(())
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
        schema_version: "netdiag-model-manifest/v1".to_string(),
        model_name: "netdiag_fault_classifier".to_string(),
        model_kind: "linfa_multinomial_logistic_regression".to_string(),
        created_at: Utc::now(),
        training_source: build.training_source,
        dataset_hash_sha256: build.dataset_hash_sha256,
        dataset_id: None,
        dataset_manifest_hash_sha256: None,
        model_file: MODEL_FILE_NAME.to_string(),
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
        max_distance =
            max_distance.max(scaled.iter().map(|value| value * value).sum::<f64>().sqrt());
    }
    thresholds.max_feature_distance = (max_distance * 2.5).max(8.0);

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
        let span = (max - min).abs();
        let padding = (span * 0.25).max(model.stds.get(idx).copied().unwrap_or(1.0) * 4.0);
        thresholds.feature_bounds.insert(
            (*feature).to_string(),
            FeatureBounds {
                min: (min - padding).max(0.0),
                max: max + padding,
            },
        );
    }

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
    (value * 10_000.0).round() / 10_000.0
}

fn accepted_feedback_label(
    recommendations: &[Recommendation],
    feedback: &BTreeMap<String, HilFeedbackRecord>,
) -> Option<(FaultLabel, Recommendation, HilFeedbackRecord)> {
    let mut selected = None;
    for record in feedback.values() {
        if record.review.state != HilState::Accepted {
            continue;
        }
        let Some(recommendation) = recommendations
            .iter()
            .find(|item| item.recommendation_id == record.recommendation_id)
        else {
            continue;
        };
        let final_label = record.review.final_label.or_else(|| {
            matches!(
                recommendation.kind,
                RecommendationKind::DiagnosisMitigation | RecommendationKind::Monitoring
            )
            .then_some(recommendation.diagnosis_symptom)
            .flatten()
        });
        let Some(final_label) = final_label else {
            continue;
        };
        if selected.as_ref().is_none_or(
            |(_, best, _): &(FaultLabel, Recommendation, HilFeedbackRecord)| {
                recommendation.confidence > best.confidence
            },
        ) {
            selected = Some((final_label, recommendation.clone(), record.clone()));
        }
    }
    selected
}

fn write_jsonl_atomic<T: Serialize>(path: &Path, rows: &[T]) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_path(parent)?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("jsonl")
    ));
    let write_result = (|| -> Result<()> {
        let file = File::create(&tmp_path).with_path(&tmp_path)?;
        let mut writer = BufWriter::new(file);
        for row in rows {
            serde_json::to_writer(&mut writer, row)?;
            writer.write_all(b"\n").with_path(&tmp_path)?;
        }
        writer.flush().with_path(&tmp_path)?;
        writer.get_ref().sync_all().with_path(&tmp_path)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    std::fs::rename(&tmp_path, path).with_path(path)?;
    Ok(path.to_path_buf())
}

fn validate_model_structure(model: &RustMlModel) -> Result<()> {
    if model.means.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "cached model means has {} entries, expected {}",
            model.means.len(),
            FEATURES.len()
        )));
    }
    if model.stds.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "cached model stds has {} entries, expected {}",
            model.stds.len(),
            FEATURES.len()
        )));
    }
    if model.means.iter().any(|value| !value.is_finite()) {
        return Err(NetdiagError::Ml(
            "cached model means contain non-finite values".to_string(),
        ));
    }
    if model
        .stds
        .iter()
        .any(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err(NetdiagError::Ml(
            "cached model stds must be finite and positive".to_string(),
        ));
    }
    let classes = model.model.classes();
    if classes.len() < 2 {
        return Err(NetdiagError::Ml(
            "cached model must contain at least two classes".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for class in classes {
        if *class >= FaultLabel::ALL.len() {
            return Err(NetdiagError::Ml(format!(
                "cached model class index {} is outside known fault labels",
                class
            )));
        }
        if !seen.insert(*class) {
            return Err(NetdiagError::Ml(format!(
                "cached model class index {} appears more than once",
                class
            )));
        }
    }
    let params = model.model.params();
    let shape = params.shape();
    if shape.len() != 2 || shape[0] != FEATURES.len() || shape[1] != classes.len() {
        return Err(NetdiagError::Ml(format!(
            "cached model parameter shape {:?} does not match {} features and {} classes",
            shape,
            FEATURES.len(),
            classes.len()
        )));
    }
    if params.iter().any(|value| !value.is_finite()) {
        return Err(NetdiagError::Ml(
            "cached model parameters contain non-finite values".to_string(),
        ));
    }
    let intercept = model.model.intercept();
    if intercept.len() != classes.len() {
        return Err(NetdiagError::Ml(format!(
            "cached model intercept has {} entries, expected {} classes",
            intercept.len(),
            classes.len()
        )));
    }
    if intercept.iter().any(|value| !value.is_finite()) {
        return Err(NetdiagError::Ml(
            "cached model intercept contains non-finite values".to_string(),
        ));
    }
    Ok(())
}

fn validate_model_manifest(manifest: &ModelManifest, model: &RustMlModel) -> Result<()> {
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
            "model manifest labels do not match cached model classes".to_string(),
        ));
    }
    Ok(())
}

fn scale_row(row: &[f64], means: &[f64], stds: &[f64]) -> Result<Vec<f64>> {
    if row.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "feature row has {} entries, expected {}",
            row.len(),
            FEATURES.len()
        )));
    }
    if means.len() != FEATURES.len() || stds.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(
            "model scaler dimensions do not match inference features".to_string(),
        ));
    }
    row.iter()
        .enumerate()
        .map(|(idx, value)| {
            let mean = means[idx];
            let std = stds[idx];
            if !value.is_finite() || !mean.is_finite() || !std.is_finite() || std <= 0.0 {
                return Err(NetdiagError::Ml(format!(
                    "feature {} cannot be scaled with non-finite input or scaler",
                    FEATURES[idx]
                )));
            }
            Ok((value - mean) / std.max(1e-9))
        })
        .collect()
}

fn calibrate_probabilities(mut probs: Vec<f64>, classes: &[usize], features: &[f64]) -> Vec<f64> {
    let latency_mean = features.first().copied().unwrap_or(0.0);
    let loss_rate = features.get(3).copied().unwrap_or(0.0);
    let retrans_rate = features.get(4).copied().unwrap_or(0.0);
    let throughput = features.get(7).copied().unwrap_or(0.0);
    let dns_events = features.get(8).copied().unwrap_or(0.0);
    let tls_events = features.get(9).copied().unwrap_or(0.0);
    let quic_ratio = features.get(10).copied().unwrap_or(0.0);

    if dns_events > 0.0 {
        scale_probability(&mut probs, classes, FaultLabel::DnsFailure, 8.0);
    } else {
        scale_probability(&mut probs, classes, FaultLabel::DnsFailure, 0.05);
    }
    if tls_events > 0.0 {
        scale_probability(&mut probs, classes, FaultLabel::TlsFailure, 8.0);
    } else {
        scale_probability(&mut probs, classes, FaultLabel::TlsFailure, 0.05);
    }
    if quic_ratio > 0.25 {
        scale_probability(&mut probs, classes, FaultLabel::UdpQuicBlocked, 6.0);
    } else {
        scale_probability(&mut probs, classes, FaultLabel::UdpQuicBlocked, 0.25);
    }
    if loss_rate > 1.0 && dns_events <= 0.0 && tls_events <= 0.0 && quic_ratio <= 0.25 {
        scale_probability(&mut probs, classes, FaultLabel::RandomLoss, 4.0);
    }
    if latency_mean > 120.0 && retrans_rate > 1.5 && throughput < 35.0 {
        scale_probability(&mut probs, classes, FaultLabel::Congestion, 4.0);
    }

    let total: f64 = probs.iter().sum();
    if total > 0.0 && total.is_finite() {
        for prob in &mut probs {
            *prob /= total;
        }
    }
    probs
}

fn scale_probability(probs: &mut [f64], classes: &[usize], label: FaultLabel, factor: f64) {
    if let Some(index) = classes
        .iter()
        .position(|class| *class == label.index())
        .filter(|index| *index < probs.len())
    {
        probs[index] *= factor;
    }
}

#[allow(dead_code)]
fn model_path(root: &Path) -> PathBuf {
    root.join("model").join(MODEL_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(label: FaultLabel, value: f64) -> FeatureTrainingRow {
        FeatureTrainingRow {
            label,
            features: vec![value; FEATURES.len()],
        }
    }

    fn dataset_line(label: FaultLabel, value: f64) -> String {
        let features = FEATURES
            .iter()
            .map(|feature| ((*feature).to_string(), value))
            .collect::<BTreeMap<_, _>>();
        serde_json::json!({
            "label": label,
            "features": features,
        })
        .to_string()
    }

    fn write_feature_dataset(path: &Path, rows_per_label: usize) {
        let mut lines = Vec::new();
        for label in FaultLabel::ALL {
            for idx in 0..rows_per_label {
                lines.push(dataset_line(
                    label,
                    label.index() as f64 + idx as f64 * 0.01,
                ));
            }
        }
        std::fs::write(path, lines.join("\n")).expect("dataset");
    }

    #[test]
    fn ml_feature_quality_maps_quic_feature_to_quic_blocked_ratio() {
        let quality = feature_quality_map(&[MetricProvenance {
            field: "quic_blocked_ratio".to_string(),
            quality: MetricQuality::Fallback,
            source: "native_pcap".to_string(),
            reason: "pcap cannot prove QUIC policy blocking".to_string(),
        }]);

        assert_eq!(quality.get("quic"), Some(&MetricQuality::Fallback));
    }

    #[test]
    fn diagnosis_status_serializes_as_standalone_status() {
        assert_eq!(
            serde_json::to_string(&DiagnosisStatus::OutOfDistribution).expect("json"),
            "\"out_of_distribution\""
        );
    }

    #[test]
    fn uncertainty_marks_confident_in_domain_prediction_known() {
        let assessment = assess_uncertainty(
            &[
                Prediction {
                    label: FaultLabel::Congestion,
                    prob: 0.91,
                },
                Prediction {
                    label: FaultLabel::Normal,
                    prob: 0.04,
                },
            ],
            &vec![1.0; FEATURES.len()],
            &vec![0.0; FEATURES.len()],
            &BTreeMap::new(),
            None,
        );

        assert_eq!(assessment.status, DiagnosisStatus::Known);
    }

    #[test]
    fn uncertainty_marks_low_confidence_prediction_uncertain() {
        let assessment = assess_uncertainty(
            &[
                Prediction {
                    label: FaultLabel::Normal,
                    prob: 0.32,
                },
                Prediction {
                    label: FaultLabel::Congestion,
                    prob: 0.30,
                },
                Prediction {
                    label: FaultLabel::RandomLoss,
                    prob: 0.20,
                },
            ],
            &vec![1.0; FEATURES.len()],
            &vec![0.0; FEATURES.len()],
            &BTreeMap::new(),
            None,
        );

        assert_eq!(assessment.status, DiagnosisStatus::Uncertain);
        assert!(
            assessment
                .reason_codes
                .contains(&UncertaintyReasonCode::Ambiguous)
        );
        assert!(
            assessment
                .reasons
                .iter()
                .any(|reason| reason.contains("max probability")),
            "{:?}",
            assessment.reasons
        );
    }

    #[test]
    fn uncertainty_marks_extreme_feature_distance_ood() {
        let assessment = assess_uncertainty(
            &[Prediction {
                label: FaultLabel::Normal,
                prob: 0.99,
            }],
            &vec![1.0; FEATURES.len()],
            &vec![9.0; FEATURES.len()],
            &BTreeMap::new(),
            None,
        );

        assert_eq!(assessment.status, DiagnosisStatus::OutOfDistribution);
        assert!(
            assessment
                .reason_codes
                .contains(&UncertaintyReasonCode::ExtremeFeatureDistance)
        );
    }

    #[test]
    fn uncertainty_marks_missing_feature_quality_as_insufficient_evidence() {
        let mut feature_quality = BTreeMap::new();
        feature_quality.insert("latency_p95".to_string(), MetricQuality::Missing);
        let assessment = assess_uncertainty(
            &[Prediction {
                label: FaultLabel::Congestion,
                prob: 0.99,
            }],
            &vec![1.0; FEATURES.len()],
            &vec![0.0; FEATURES.len()],
            &feature_quality,
            None,
        );

        assert_eq!(assessment.status, DiagnosisStatus::Uncertain);
        assert!(
            assessment
                .reason_codes
                .contains(&UncertaintyReasonCode::InsufficientEvidence)
        );
    }

    #[test]
    fn stratified_split_keeps_each_label_in_training() {
        let mut rows = Vec::new();
        for label in FaultLabel::ALL {
            rows.push(row(label, label.index() as f64));
            rows.push(row(label, label.index() as f64 + 0.5));
        }

        let (training, validation) = partition_training_rows(
            &rows,
            TrainingOptions {
                validation_split: 0.5,
                shuffle_seed: Some(2026),
                stratified: true,
                min_rows_per_label: 0,
            },
        );

        assert_eq!(training.len(), FaultLabel::ALL.len());
        assert_eq!(validation.len(), FaultLabel::ALL.len());
        for label in FaultLabel::ALL {
            assert!(training.iter().any(|row| row.label == label), "{label}");
            assert!(validation.iter().any(|row| row.label == label), "{label}");
        }
    }

    #[test]
    fn evaluation_reports_dense_confusion_and_per_label_metrics() {
        let mut confusion = dense_confusion_matrix();
        *confusion
            .entry("congestion".to_string())
            .or_default()
            .entry("congestion".to_string())
            .or_default() = 2;
        *confusion
            .entry("congestion".to_string())
            .or_default()
            .entry("normal".to_string())
            .or_default() = 1;

        let metrics = label_metrics(FaultLabel::Congestion, &confusion);

        assert_eq!(confusion.len(), FaultLabel::ALL.len());
        assert_eq!(metrics.support, 3);
        assert_eq!(metrics.precision, 1.0);
        assert_eq!(metrics.recall, 0.6667);
        assert_eq!(metrics.f1, 0.8);
    }

    #[test]
    fn evaluation_marks_missing_validation_labels_degraded() {
        let training = vec![
            row(FaultLabel::Normal, 10.0),
            row(FaultLabel::Congestion, 200.0),
        ];
        let model = train_model_from_feature_rows(&training).expect("model");
        let expected = [FaultLabel::Normal, FaultLabel::Congestion]
            .into_iter()
            .collect::<BTreeSet<_>>();

        let evaluation =
            evaluate_model(&model, &[row(FaultLabel::Normal, 12.0)], &expected).expect("eval");

        assert!(evaluation.degraded, "{:?}", evaluation.warnings);
        assert_eq!(evaluation.missing_validation_labels, vec!["congestion"]);
        assert!(
            evaluation
                .warnings
                .iter()
                .any(|warning| warning.contains("validation set has no congestion examples")),
            "{:?}",
            evaluation.warnings
        );
    }

    #[test]
    fn training_gate_checks_training_split_distribution() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dataset = temp.path().join("feedback.jsonl");
        write_feature_dataset(&dataset, 2);

        let err = train_model_from_jsonl_with_options(
            &dataset,
            temp.path().join("model"),
            TrainingOptions {
                validation_split: 0.5,
                shuffle_seed: Some(2026),
                stratified: true,
                min_rows_per_label: 2,
            },
        )
        .expect_err("training split should fail gate");

        assert!(
            err.to_string()
                .contains("training split label normal has 1 rows"),
            "{err}"
        );
    }

    #[test]
    fn training_gate_passes_when_training_split_keeps_enough_rows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dataset = temp.path().join("feedback.jsonl");
        write_feature_dataset(&dataset, 3);

        let manifest = train_model_from_jsonl_with_options(
            &dataset,
            temp.path().join("model"),
            TrainingOptions {
                validation_split: 0.34,
                shuffle_seed: Some(2026),
                stratified: true,
                min_rows_per_label: 2,
            },
        )
        .expect("training should pass");

        let gate = manifest.training_gate.expect("gate");
        assert!(gate.passed, "{:?}", gate.failures);
        assert_eq!(gate.dataset_rows, FaultLabel::ALL.len() * 3);
        assert_eq!(gate.training_rows, FaultLabel::ALL.len() * 2);
        assert_eq!(gate.validation_rows, FaultLabel::ALL.len());
        assert!(manifest.uncertainty_thresholds.is_some());
    }

    #[test]
    fn cached_model_with_bad_scaler_dimensions_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_dir = temp.path().join("model");
        std::fs::create_dir_all(&model_dir).expect("model dir");
        let mut model = train_default_model().expect("model");
        model.means.pop();
        save_json_atomic(model_dir.join(MODEL_FILE_NAME), &model).expect("model json");

        let err = load_or_train_model(&model_dir).expect_err("bad cache should fail");

        assert!(err.to_string().contains("cached model means"), "{err}");
    }

    #[test]
    fn cached_model_manifest_must_match_model_shape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_dir = temp.path().join("model");
        std::fs::create_dir_all(&model_dir).expect("model dir");
        let model = train_default_model().expect("model");
        let mut manifest = build_model_manifest(
            &model,
            ModelManifestBuild {
                training_source: "test".to_string(),
                training_examples: 1,
                label_distribution: BTreeMap::new(),
                synthetic_fallback: false,
                dataset_hash_sha256: None,
                training_config: None,
                uncertainty_thresholds: None,
            },
        )
        .expect("manifest");
        manifest.feature_count = FEATURES.len() + 1;
        save_json_atomic(model_dir.join(MODEL_FILE_NAME), &model).expect("model json");
        save_json_atomic(model_dir.join(MODEL_MANIFEST_FILE_NAME), &manifest)
            .expect("manifest json");

        let err = load_or_train_model(&model_dir).expect_err("bad manifest should fail");

        assert!(
            err.to_string().contains("model manifest feature_count"),
            "{err}"
        );
    }

    #[test]
    fn cached_model_with_bad_intercept_shape_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_dir = temp.path().join("model");
        std::fs::create_dir_all(&model_dir).expect("model dir");
        let model = train_default_model().expect("model");
        let mut value = serde_json::to_value(&model).expect("model value");
        let intercept = value
            .get_mut("model")
            .and_then(|model| model.get_mut("intercept"))
            .expect("intercept");
        intercept["dim"] = serde_json::json!([FaultLabel::ALL.len() - 1]);
        intercept["data"]
            .as_array_mut()
            .expect("intercept data")
            .pop();
        save_json_atomic(model_dir.join(MODEL_FILE_NAME), &value).expect("model json");

        let err = load_or_train_model(&model_dir).expect_err("bad cache should fail");

        assert!(err.to_string().contains("cached model intercept"), "{err}");
    }
}
