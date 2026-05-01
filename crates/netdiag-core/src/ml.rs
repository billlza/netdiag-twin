use crate::error::{IoContext, NetdiagError, Result};
use crate::models::{
    FaultLabel, FeatureImportance, HilFeedbackRecord, HilState, MetricProvenance, MetricQuality,
    MlResult, ModelEvaluation, ModelManifest, Prediction, Recommendation, RecommendationKind,
    TelemetryWindow, TraceRecord,
};
use crate::report::Report;
use crate::storage::{read_json, save_json_atomic};
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
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

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
    let model = load_or_train_model(&model_dir)?;
    let model_manifest = read_json(model_dir.join(MODEL_MANIFEST_FILE_NAME))
        .ok()
        .and_then(|value| serde_json::from_value::<ModelManifest>(value).ok());
    let raw_features = extract_features_from_windows(windows);
    let feature_quality = feature_quality_map(provenance);
    let weighted_features = apply_feature_quality(&raw_features, &feature_quality);
    let scaled = scale_row(&weighted_features, &model.means, &model.stds);
    let x = Array2::from_shape_vec((1, FEATURES.len()), scaled.clone())
        .map_err(|err| NetdiagError::Ml(err.to_string()))?;
    let probabilities = model.model.predict_probabilities(&x);
    let classes = model.model.classes().to_vec();
    let calibrated =
        calibrate_probabilities(probabilities.row(0).to_vec(), &classes, &weighted_features);
    let mut ranking: Vec<Prediction> = calibrated
        .iter()
        .enumerate()
        .map(|(idx, prob)| Prediction {
            label: classes
                .get(idx)
                .copied()
                .map(FaultLabel::from_index)
                .unwrap_or(FaultLabel::Normal),
            prob: *prob,
        })
        .collect();
    ranking.sort_by(|left, right| right.prob.total_cmp(&left.prob));

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
        model_manifest,
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
        "quic_blocked" => "quic_blocked_ratio",
        _ => "unknown",
    }
}

pub fn load_or_train_model(model_dir: &Path) -> Result<RustMlModel> {
    let model_path = model_dir.join(MODEL_FILE_NAME);
    let manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
    if model_path.exists()
        && let Ok(file) = File::open(&model_path)
    {
        let reader = BufReader::new(file);
        if let Ok(model) = serde_json::from_reader::<_, RustMlModel>(reader) {
            if !manifest_path.exists() {
                let manifest = build_model_manifest("cached_existing_model", 0, false, &model);
                save_json_atomic(&manifest_path, &manifest)?;
            }
            return Ok(model);
        }
    }

    std::fs::create_dir_all(model_dir).with_path(model_dir)?;
    let model = train_default_model()?;
    let manifest = build_model_manifest("synthetic_fallback", BASELINES.len() * 130, true, &model);
    write_model_bundle(model_dir, &model, &manifest)?;
    Ok(model)
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
    let dataset_path = dataset_path.as_ref();
    let model_dir = model_dir.as_ref();
    let rows = read_training_jsonl(dataset_path)?;
    let split_at = validation_split_index(rows.len(), validation_split);
    let (training_rows, validation_rows) = rows.split_at(split_at);
    let training_rows = if training_rows.is_empty() {
        rows.as_slice()
    } else {
        training_rows
    };
    let model = train_model_from_feature_rows(training_rows)?;
    let evaluation = if validation_rows.is_empty() || validation_rows.len() == rows.len() {
        None
    } else {
        Some(evaluate_model(&model, validation_rows)?)
    };
    let mut manifest = build_model_manifest(
        format!("jsonl:{}", dataset_path.display()),
        training_rows.len(),
        false,
        &model,
    );
    manifest.evaluation = evaluation;
    write_model_bundle(model_dir, &model, &manifest)?;
    Ok(manifest)
}

pub fn export_feedback_training_dataset(
    artifact_root: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<FeedbackExportSummary> {
    let artifact_root = artifact_root.as_ref();
    let output_path = output_path.as_ref();
    let runs_root = artifact_root.join("runs");
    let mut rows = Vec::new();
    let mut skipped_runs = 0usize;

    for entry in std::fs::read_dir(&runs_root).with_path(&runs_root)? {
        let entry = entry.with_path(&runs_root)?;
        let run_dir = entry.path();
        if !run_dir.is_dir()
            || run_dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with('.'))
        {
            continue;
        }

        let report_path = run_dir.join("report.json");
        let ml_path = run_dir.join("ml_result.json");
        let feedback_path = run_dir.join("hil_feedback.json");
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

    write_jsonl_atomic(output_path, &rows)?;
    Ok(FeedbackExportSummary {
        output: output_path.display().to_string(),
        rows: rows.len(),
        skipped_runs,
    })
}

fn train_default_model() -> Result<RustMlModel> {
    let mut rng = StdRng::seed_from_u64(2026);
    let mut rows = Vec::new();
    let mut targets = Vec::new();

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
            rows.push(row);
            targets.push(label_idx);
        }
    }

    fit_model(&rows, &targets)
}

fn train_model_from_feature_rows(rows: &[FeatureTrainingRow]) -> Result<RustMlModel> {
    let features = rows
        .iter()
        .map(|row| row.features.clone())
        .collect::<Vec<_>>();
    let targets = rows.iter().map(|row| row.label.index()).collect::<Vec<_>>();
    fit_model(&features, &targets)
}

fn validation_split_index(len: usize, split: f64) -> usize {
    if len < 3 || !split.is_finite() || split <= 0.0 {
        return len;
    }
    let validation = ((len as f64) * split.clamp(0.0, 0.8)).round() as usize;
    len.saturating_sub(validation.max(1)).max(1)
}

fn evaluate_model(model: &RustMlModel, rows: &[FeatureTrainingRow]) -> Result<ModelEvaluation> {
    let mut correct = 0usize;
    let mut confusion = BTreeMap::<String, BTreeMap<String, usize>>::new();
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
    let macro_f1 = FaultLabel::ALL
        .iter()
        .map(|label| label_f1(*label, &confusion))
        .sum::<f64>()
        / FaultLabel::ALL.len() as f64;
    Ok(ModelEvaluation {
        validation_examples: rows.len(),
        accuracy: round4(accuracy),
        macro_f1: round4(macro_f1),
        confusion_matrix: confusion,
    })
}

fn predict_label(model: &RustMlModel, features: &[f64]) -> Result<FaultLabel> {
    let scaled = scale_row(features, &model.means, &model.stds);
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
    Ok(classes
        .get(best_idx)
        .copied()
        .map(FaultLabel::from_index)
        .unwrap_or(FaultLabel::Normal))
}

fn label_f1(label: FaultLabel, confusion: &BTreeMap<String, BTreeMap<String, usize>>) -> f64 {
    let key = label.as_str();
    let tp = confusion
        .get(key)
        .and_then(|predicted| predicted.get(key))
        .copied()
        .unwrap_or(0) as f64;
    let fp = confusion
        .values()
        .map(|predicted| predicted.get(key).copied().unwrap_or(0))
        .sum::<usize>() as f64
        - tp;
    let fn_ = confusion
        .get(key)
        .map(|predicted| predicted.values().sum::<usize>() as f64)
        .unwrap_or(0.0)
        - tp;
    if tp == 0.0 {
        0.0
    } else {
        (2.0 * tp) / (2.0 * tp + fp + fn_)
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

    let scaled_rows = rows
        .iter()
        .flat_map(|row| scale_row(row, &means, &stds))
        .collect::<Vec<_>>();
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
    std::fs::create_dir_all(model_dir).with_path(model_dir)?;
    save_json_atomic(model_dir.join(MODEL_FILE_NAME), model)?;
    save_json_atomic(model_dir.join(MODEL_MANIFEST_FILE_NAME), manifest)?;
    Ok(())
}

fn build_model_manifest(
    training_source: impl Into<String>,
    training_examples: usize,
    synthetic_fallback: bool,
    model: &RustMlModel,
) -> ModelManifest {
    ModelManifest {
        schema_version: "netdiag-model-manifest/v1".to_string(),
        model_name: "netdiag_fault_classifier".to_string(),
        model_kind: "linfa_multinomial_logistic_regression".to_string(),
        created_at: Utc::now(),
        training_source: training_source.into(),
        model_file: MODEL_FILE_NAME.to_string(),
        feature_names: FEATURES.iter().map(|name| (*name).to_string()).collect(),
        labels: model
            .model
            .classes()
            .iter()
            .map(|class| FaultLabel::from_index(*class).as_str().to_string())
            .collect(),
        training_examples,
        feature_count: FEATURES.len(),
        synthetic_fallback,
        evaluation: None,
    }
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

fn scale_row(row: &[f64], means: &[f64], stds: &[f64]) -> Vec<f64> {
    row.iter()
        .enumerate()
        .map(|(idx, value)| (value - means[idx]) / stds[idx].max(1e-9))
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
