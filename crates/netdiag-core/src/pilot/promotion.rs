use crate::benchmark::BenchmarkReport;
use crate::error::{IoContext, Result};
use crate::ml::{MODEL_FILE_NAME, MODEL_MANIFEST_FILE_NAME, load_existing_model};
use crate::models::ModelManifest;
use crate::storage::{read_json, save_json_atomic};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

mod gates;
use gates::{evaluation_gates, known_label_coverage_gate, ood_coverage_gate, training_gate};

const MODEL_PROMOTION_GATE_SCHEMA: &str = "netdiag-model-promotion-gate/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPromotionOptions {
    pub model_dir: PathBuf,
    pub benchmark_report: PathBuf,
    #[serde(default)]
    pub min_rows_per_label: usize,
    #[serde(default = "default_min_accuracy")]
    pub min_accuracy: f64,
    #[serde(default = "default_min_macro_f1")]
    pub min_macro_f1: f64,
    #[serde(default)]
    pub allow_missing_evaluation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelPromotionReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub passed: bool,
    pub model_dir: String,
    pub benchmark_report: String,
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
    let model_dir = options.model_dir;
    let benchmark_report = options.benchmark_report;
    let manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
    let model_path = model_dir.join(MODEL_FILE_NAME);
    let manifest: ModelManifest = serde_json::from_value(read_json(&manifest_path)?)?;
    let benchmark: BenchmarkReport = serde_json::from_value(read_json(&benchmark_report)?)?;

    let mut gates = Vec::new();
    gates.push(match load_existing_model(&model_dir) {
        Ok(_) => gate("model_load", true, "model bundle loads successfully"),
        Err(err) => gate("model_load", false, err.to_string()),
    });
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
        model_manifest_hash_sha256: manifest_path
            .is_file()
            .then(|| sha256_file(&manifest_path))
            .transpose()?,
        model_file_hash_sha256: model_path
            .is_file()
            .then(|| sha256_file(&model_path))
            .transpose()?,
        gates,
    };
    save_json_atomic(model_dir.join("model_promotion_gate.json"), &report)?;
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

fn sha256_file(path: &Path) -> Result<String> {
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
    Ok(format!("{:x}", hasher.finalize()))
}

fn default_min_accuracy() -> f64 {
    0.90
}

fn default_min_macro_f1() -> f64 {
    0.90
}

#[cfg(test)]
mod tests;
