use crate::error::{NetdiagError, Result};
use crate::ml::ModelBundleSnapshot;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

mod benchmark_identity;
mod calibration;
mod gates;
mod input;
mod model_state;
mod snapshot;
use benchmark_identity::benchmark_model_match_gate;
use calibration::{CalibrationGateOptions, calibration_gates};
use gates::{evaluation_gates, known_label_coverage_gate, ood_coverage_gate, training_gate};
use input::{read_benchmark_report, read_calibration_report};
use model_state::load_promotion_snapshot;
use snapshot::persist_if_current;

const MODEL_PROMOTION_GATE_SCHEMA: &str = "netdiag-model-promotion-gate/v1";
const MAX_CALIBRATION_AGE_DAYS: u64 = 3_650;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPromotionOptions {
    pub model_dir: PathBuf,
    pub benchmark_report: PathBuf,
    pub calibration_report: PathBuf,
    #[serde(default)]
    pub min_rows_per_label: usize,
    #[serde(default = "default_min_accuracy")]
    pub min_accuracy: f64,
    #[serde(default = "default_min_macro_f1")]
    pub min_macro_f1: f64,
    #[serde(default)]
    pub allow_missing_evaluation: bool,
    #[serde(default = "default_max_ood_false_positive_rate")]
    pub max_ood_false_positive_rate: f64,
    #[serde(default = "default_max_ood_false_negative_rate")]
    pub max_ood_false_negative_rate: f64,
    #[serde(default = "default_max_rule_ml_disagreement_hotspot_rate")]
    pub max_rule_ml_disagreement_hotspot_rate: f64,
    #[serde(default = "default_max_calibration_age_days")]
    pub max_calibration_age_days: u64,
    #[serde(default = "default_min_expected_ood_runs")]
    pub min_expected_ood_runs: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPromotionReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub passed: bool,
    pub model_dir: String,
    pub benchmark_report: String,
    pub calibration_report: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_manifest_hash_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_file_hash_sha256: Option<String>,
    #[serde(default)]
    pub gates: Vec<ModelPromotionGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPromotionGate {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

pub fn evaluate_model_promotion(options: ModelPromotionOptions) -> Result<ModelPromotionReport> {
    validate_rate_threshold("min_accuracy", options.min_accuracy)?;
    validate_rate_threshold("min_macro_f1", options.min_macro_f1)?;
    validate_rate_threshold(
        "max_ood_false_positive_rate",
        options.max_ood_false_positive_rate,
    )?;
    validate_rate_threshold(
        "max_ood_false_negative_rate",
        options.max_ood_false_negative_rate,
    )?;
    validate_rate_threshold(
        "max_rule_ml_disagreement_hotspot_rate",
        options.max_rule_ml_disagreement_hotspot_rate,
    )?;
    if !(1..=MAX_CALIBRATION_AGE_DAYS).contains(&options.max_calibration_age_days) {
        return Err(NetdiagError::InvalidTrace(format!(
            "max_calibration_age_days must be between 1 and {MAX_CALIBRATION_AGE_DAYS}"
        )));
    }

    let snapshot = load_promotion_snapshot(&options.model_dir)?;
    evaluate_model_promotion_snapshot(options, snapshot)
}

fn evaluate_model_promotion_snapshot(
    options: ModelPromotionOptions,
    snapshot: ModelBundleSnapshot,
) -> Result<ModelPromotionReport> {
    let model_dir = options.model_dir;
    let benchmark_report = options.benchmark_report;
    let calibration_report = options.calibration_report;
    let manifest = snapshot.manifest.clone();
    let benchmark = read_benchmark_report(&benchmark_report)?;
    let calibration = read_calibration_report(&calibration_report);
    let model_manifest_hash_sha256 = Some(snapshot.model_manifest_hash_sha256.clone());
    let model_file_hash_sha256 = Some(snapshot.model_file_hash_sha256.clone());

    let mut gates = Vec::new();
    gates.push(gate(
        "model_load",
        true,
        "immutable model bundle snapshot loaded successfully",
    ));
    gates.push(gate(
        "synthetic_fallback",
        !manifest.synthetic_fallback,
        if manifest.synthetic_fallback {
            "synthetic fallback models cannot be promoted"
        } else {
            "model was trained from a registered dataset"
        },
    ));
    gates.push(gate(
        "dataset_hash",
        manifest.dataset_hash_sha256.is_some(),
        if manifest.dataset_hash_sha256.is_some() {
            "dataset_hash_sha256 is present"
        } else {
            "dataset_hash_sha256 is required"
        },
    ));
    gates.push(training_gate(&manifest));
    gates.push(known_label_coverage_gate(
        &manifest,
        options.min_rows_per_label,
    ));
    gates.extend(evaluation_gates(
        &manifest,
        options.min_accuracy,
        options.min_macro_f1,
        options.allow_missing_evaluation,
    ));
    gates.push(ood_coverage_gate(&benchmark));
    gates.push(benchmark_model_match_gate(
        &benchmark,
        &manifest,
        model_manifest_hash_sha256.as_deref(),
        model_file_hash_sha256.as_deref(),
    ));
    gates.extend(calibration_gates(
        calibration.as_ref().map_err(String::as_str),
        &manifest,
        &CalibrationGateOptions {
            max_ood_false_positive_rate: options.max_ood_false_positive_rate,
            max_ood_false_negative_rate: options.max_ood_false_negative_rate,
            max_rule_ml_disagreement_hotspot_rate: options.max_rule_ml_disagreement_hotspot_rate,
            max_calibration_age_days: options.max_calibration_age_days,
            min_expected_ood_runs: options.min_expected_ood_runs,
        },
        model_manifest_hash_sha256.as_deref(),
        model_file_hash_sha256.as_deref(),
    ));
    gates.push(gate(
        "benchmark_report",
        benchmark.passed,
        if benchmark.passed {
            "benchmark report passed"
        } else {
            "benchmark report failed"
        },
    ));

    let passed = gates.iter().all(|gate| gate.passed);
    let report = ModelPromotionReport {
        schema: MODEL_PROMOTION_GATE_SCHEMA.to_string(),
        generated_at: Utc::now(),
        passed,
        model_dir: model_dir.display().to_string(),
        benchmark_report: benchmark_report.display().to_string(),
        calibration_report: calibration_report.display().to_string(),
        model_manifest_hash_sha256,
        model_file_hash_sha256,
        gates,
    };
    persist_if_current(&model_dir, &snapshot, &report)?;
    Ok(report)
}

pub(super) fn gate(
    name: impl Into<String>,
    passed: bool,
    message: impl Into<String>,
) -> ModelPromotionGate {
    ModelPromotionGate {
        name: name.into(),
        passed,
        message: message.into(),
    }
}

fn validate_rate_threshold(name: &str, value: f64) -> Result<()> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "{name} must be a finite rate between 0.0 and 1.0"
        )))
    }
}

fn default_min_accuracy() -> f64 {
    0.90
}

fn default_min_macro_f1() -> f64 {
    0.90
}

fn default_max_ood_false_positive_rate() -> f64 {
    0.05
}

fn default_max_ood_false_negative_rate() -> f64 {
    0.05
}

fn default_max_rule_ml_disagreement_hotspot_rate() -> f64 {
    0.10
}

fn default_max_calibration_age_days() -> u64 {
    30
}

fn default_min_expected_ood_runs() -> usize {
    1
}

#[cfg(test)]
mod tests;
