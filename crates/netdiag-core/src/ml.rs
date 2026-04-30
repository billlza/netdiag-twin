use crate::error::{IoContext, NetdiagError, Result};
use crate::models::{FaultLabel, FeatureImportance, MlResult, Prediction, TelemetryWindow};
use crate::telemetry::{extract_features_from_windows, mean};
use linfa::Dataset;
use linfa::prelude::Fit;
use linfa_logistic::{MultiFittedLogisticRegression, MultiLogisticRegression};
use ndarray::{Array1, Array2};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand_distr::{Distribution, Normal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

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

pub fn infer(
    windows: &[TelemetryWindow],
    run_id: &str,
    artifact_root: impl AsRef<Path>,
) -> Result<MlResult> {
    let model_dir = artifact_root.as_ref().join("model");
    let model = load_or_train_model(&model_dir)?;
    let raw_features = extract_features_from_windows(windows);
    let scaled = scale_row(&raw_features, &model.means, &model.stds);
    let x = Array2::from_shape_vec((1, FEATURES.len()), scaled.clone())
        .map_err(|err| NetdiagError::Ml(err.to_string()))?;
    let probabilities = model.model.predict_probabilities(&x);
    let calibrated = calibrate_probabilities(probabilities.row(0).to_vec(), &raw_features);
    let mut ranking: Vec<Prediction> = calibrated
        .iter()
        .enumerate()
        .map(|(idx, prob)| Prediction {
            label: FaultLabel::from_index(idx),
            prob: *prob,
        })
        .collect();
    ranking.sort_by(|left, right| right.prob.total_cmp(&left.prob));

    let top_index = ranking
        .first()
        .map(|prediction| prediction.label.index())
        .unwrap_or(0);
    let params = model.model.params();
    let mut top_features: Vec<FeatureImportance> = FEATURES
        .iter()
        .enumerate()
        .map(|(idx, name)| FeatureImportance {
            name: (*name).to_string(),
            importance: (scaled[idx] * params[[idx, top_index]]).abs(),
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
    })
}

pub fn load_or_train_model(model_dir: &Path) -> Result<RustMlModel> {
    let model_path = model_dir.join("rust_logistic_model.json");
    if model_path.exists()
        && let Ok(file) = File::open(&model_path)
    {
        let reader = BufReader::new(file);
        if let Ok(model) = serde_json::from_reader::<_, RustMlModel>(reader) {
            return Ok(model);
        }
    }

    std::fs::create_dir_all(model_dir).with_path(model_dir)?;
    let model = train_default_model()?;
    let file = File::create(&model_path).with_path(&model_path)?;
    serde_json::to_writer_pretty(BufWriter::new(file), &model)?;
    Ok(model)
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
    let y = Array1::from(targets);
    let dataset = Dataset::new(x, y);
    let model = MultiLogisticRegression::default()
        .alpha(0.1)
        .max_iterations(150)
        .fit(&dataset)
        .map_err(|err| NetdiagError::Ml(err.to_string()))?;
    Ok(RustMlModel { model, means, stds })
}

fn scale_row(row: &[f64], means: &[f64], stds: &[f64]) -> Vec<f64> {
    row.iter()
        .enumerate()
        .map(|(idx, value)| (value - means[idx]) / stds[idx].max(1e-9))
        .collect()
}

fn calibrate_probabilities(mut probs: Vec<f64>, features: &[f64]) -> Vec<f64> {
    let latency_mean = features[0];
    let loss_rate = features[3];
    let retrans_rate = features[4];
    let throughput = features[7];
    let dns_events = features[8];
    let tls_events = features[9];
    let quic_ratio = features[10];

    if dns_events > 0.0 {
        probs[FaultLabel::DnsFailure.index()] *= 8.0;
    } else {
        probs[FaultLabel::DnsFailure.index()] *= 0.05;
    }
    if tls_events > 0.0 {
        probs[FaultLabel::TlsFailure.index()] *= 8.0;
    } else {
        probs[FaultLabel::TlsFailure.index()] *= 0.05;
    }
    if quic_ratio > 0.25 {
        probs[FaultLabel::UdpQuicBlocked.index()] *= 6.0;
    } else {
        probs[FaultLabel::UdpQuicBlocked.index()] *= 0.25;
    }
    if loss_rate > 1.0 && dns_events <= 0.0 && tls_events <= 0.0 && quic_ratio <= 0.25 {
        probs[FaultLabel::RandomLoss.index()] *= 4.0;
    }
    if latency_mean > 120.0 && retrans_rate > 1.5 && throughput < 35.0 {
        probs[FaultLabel::Congestion.index()] *= 4.0;
    }

    let total: f64 = probs.iter().sum();
    if total > 0.0 && total.is_finite() {
        for prob in &mut probs {
            *prob /= total;
        }
    }
    probs
}

#[allow(dead_code)]
fn model_path(root: &Path) -> PathBuf {
    root.join("model").join("rust_logistic_model.json")
}
