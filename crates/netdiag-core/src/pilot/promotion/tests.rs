use super::calibration::{CalibrationGateOptions, calibration_gates};
use super::*;
use crate::benchmark::{BenchmarkCheck, BenchmarkEnvironment, BenchmarkReport, BenchmarkSection};
use crate::lab::{
    LabCalibrationDistribution, LabCalibrationHotspot, LabCalibrationLabelStats,
    LabCalibrationOodStats, LabCalibrationReport,
};
use crate::ml::{TrainingOptions, train_model_from_jsonl_with_options};
use crate::models::{
    ConnectorHealthStatus, FaultLabel, LabelMetrics, ModelEvaluation, ModelTrainingGate,
    ModelUncertaintyThresholds,
};
use crate::storage::{read_json, save_json_atomic};
use chrono::Duration;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn manifest() -> ModelManifest {
    let labels = FaultLabel::ALL
        .iter()
        .map(|label| label.as_str().to_string())
        .collect::<Vec<_>>();
    let label_distribution = FaultLabel::ALL
        .iter()
        .map(|label| (label.as_str().to_string(), 2))
        .collect::<BTreeMap<_, _>>();
    let rows = FaultLabel::ALL.len() * 2;
    ModelManifest {
        schema_version: "netdiag-model/v1".to_string(),
        model_name: "test".to_string(),
        model_kind: "rust-logistic".to_string(),
        created_at: Utc::now(),
        training_source: "test".to_string(),
        dataset_hash_sha256: Some("hash".to_string()),
        dataset_id: None,
        dataset_manifest_hash_sha256: None,
        model_file: MODEL_FILE_NAME.to_string(),
        feature_names: vec!["latency_mean".to_string()],
        labels,
        training_examples: rows,
        label_distribution,
        feature_count: 1,
        synthetic_fallback: false,
        training_config: None,
        evaluation: None,
        training_gate: Some(ModelTrainingGate {
            passed: true,
            rows,
            dataset_rows: rows,
            training_rows: rows,
            validation_rows: 0,
            min_rows_per_label: 1,
            validation_split: 0.0,
            stratified: false,
            failures: Vec::new(),
        }),
        uncertainty_thresholds: None,
    }
}

fn complete_evaluation() -> ModelEvaluation {
    ModelEvaluation {
        validation_examples: FaultLabel::ALL.len() * 2,
        accuracy: 0.95,
        macro_f1: 0.94,
        degraded: false,
        warnings: Vec::new(),
        missing_validation_labels: Vec::new(),
        per_label: FaultLabel::ALL
            .iter()
            .map(|label| {
                (
                    label.as_str().to_string(),
                    LabelMetrics {
                        support: 2,
                        precision: 0.95,
                        recall: 0.95,
                        f1: 0.95,
                    },
                )
            })
            .collect(),
        confusion_matrix: BTreeMap::new(),
    }
}

fn calibration_options() -> CalibrationGateOptions {
    CalibrationGateOptions {
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    }
}

fn calibration_report() -> LabCalibrationReport {
    let per_label = FaultLabel::ALL
        .iter()
        .map(|label| {
            (
                label.as_str().to_string(),
                LabCalibrationLabelStats {
                    runs: 1,
                    accepted_known_runs: 1,
                    rule_correct: 1,
                    ml_correct: 1,
                    rule_accuracy: 1.0,
                    ml_accuracy: 1.0,
                    known_rate: 1.0,
                    uncertain_rate: 0.0,
                    out_of_distribution_rate: 0.0,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    LabCalibrationReport {
        schema: "netdiag-lab-calibration/v1".to_string(),
        generated_at: Utc::now(),
        artifact_root: "artifacts".to_string(),
        model_manifest_path: "artifacts/model/model_manifest.json".to_string(),
        model_manifest_hash_sha256: Some("manifest-hash".to_string()),
        model_file_hash_sha256: Some("model-hash".to_string()),
        dataset_hash_sha256: Some("hash".to_string()),
        evaluated_runs: FaultLabel::ALL.len() + 1,
        known_runs: FaultLabel::ALL.len(),
        uncertain_runs: 0,
        out_of_distribution_runs: 1,
        skipped_runs: 0,
        per_label,
        ood: LabCalibrationOodStats {
            expected_ood_runs: 1,
            expected_known_runs: FaultLabel::ALL.len(),
            false_positive_runs: 0,
            false_negative_runs: 0,
            false_positive_rate: 0.0,
            false_negative_rate: 0.0,
        },
        rule_ml_disagreement_hotspots: Vec::new(),
        feature_distance_distribution: LabCalibrationDistribution {
            count: FaultLabel::ALL.len() + 1,
            p50: 1.0,
            p95: 2.0,
            max: 3.0,
        },
        suggested_rule_thresholds: BTreeMap::new(),
        applied: true,
        previous_thresholds: None,
        calibrated_thresholds: ModelUncertaintyThresholds::default(),
        warnings: Vec::new(),
    }
}

fn calibrated_manifest() -> ModelManifest {
    let mut manifest = manifest();
    manifest.uncertainty_thresholds = Some(ModelUncertaintyThresholds::default());
    manifest
}

fn gate_by_name<'a>(gates: &'a [ModelPromotionGate], name: &str) -> &'a ModelPromotionGate {
    gates
        .iter()
        .find(|gate| gate.name == name)
        .unwrap_or_else(|| panic!("missing gate {name}: {gates:?}"))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root")
        .to_path_buf()
}

fn provision_test_model(artifacts: &Path) {
    train_model_from_jsonl_with_options(
        repo_root().join("examples/datasets/pilot-smoke-training.jsonl"),
        artifacts.join("model"),
        TrainingOptions {
            min_rows_per_label: 1,
            ..TrainingOptions::default()
        },
    )
    .expect("trained smoke model");
}

fn write_passing_benchmark(path: &Path) {
    let report = benchmark_report(vec![ood_section(ConnectorHealthStatus::Ok)], true);
    save_json_atomic(path, &report).expect("benchmark report");
}

fn write_passing_calibration(artifacts: &Path) -> PathBuf {
    let model_dir = artifacts.join("model");
    let manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
    let mut manifest: ModelManifest =
        serde_json::from_value(read_json(&manifest_path).expect("manifest"))
            .expect("manifest json");
    let thresholds = ModelUncertaintyThresholds::default();
    manifest.uncertainty_thresholds = Some(thresholds.clone());
    save_json_atomic(&manifest_path, &manifest).expect("manifest thresholds");

    let mut report = calibration_report();
    report.artifact_root = artifacts.display().to_string();
    report.model_manifest_path = manifest_path.display().to_string();
    report.model_manifest_hash_sha256 = Some(sha256_file(&manifest_path).expect("manifest hash"));
    report.model_file_hash_sha256 =
        Some(sha256_file(&model_dir.join(MODEL_FILE_NAME)).expect("model hash"));
    report.dataset_hash_sha256 = manifest.dataset_hash_sha256.clone();
    report.calibrated_thresholds = thresholds;
    let calibration_path = artifacts.join("lab_calibration_report.json");
    save_json_atomic(&calibration_path, &report).expect("calibration report");
    calibration_path
}

fn benchmark_report(sections: Vec<BenchmarkSection>, passed: bool) -> BenchmarkReport {
    BenchmarkReport {
        schema: "netdiag-benchmark-report/v1".to_string(),
        generated_at: Utc::now(),
        suite: "test".to_string(),
        passed,
        artifacts: "test".to_string(),
        output: "test".to_string(),
        environment: BenchmarkEnvironment {
            os: "test".to_string(),
            arch: "test".to_string(),
            profile: "test".to_string(),
        },
        sections,
        reliability: None,
    }
}

fn ood_section(status: ConnectorHealthStatus) -> BenchmarkSection {
    BenchmarkSection {
        name: "ood benchmark preflight".to_string(),
        status,
        elapsed_millis: 1.0,
        checks: vec![BenchmarkCheck {
            name: "ood-cpu-saturation".to_string(),
            status,
            message: "static preflight passed".to_string(),
            details: None,
        }],
    }
}

#[test]
fn evaluation_gates_require_metrics_unless_explicitly_allowed() {
    let missing = evaluation_gates(&manifest(), 0.9, 0.9, false);
    assert_eq!(missing.len(), 1);
    assert!(!missing[0].passed);

    let allowed = evaluation_gates(&manifest(), 0.9, 0.9, true);
    assert!(allowed[0].passed);
}

#[test]
fn evaluation_gates_report_degraded_and_threshold_failures() {
    let mut manifest = manifest();
    manifest.evaluation = Some(ModelEvaluation {
        validation_examples: 2,
        accuracy: 0.50,
        macro_f1: 0.40,
        degraded: true,
        warnings: vec!["low validation coverage".to_string()],
        missing_validation_labels: vec!["congestion".to_string()],
        per_label: BTreeMap::from([(
            "normal".to_string(),
            LabelMetrics {
                support: 2,
                precision: 0.5,
                recall: 0.5,
                f1: 0.5,
            },
        )]),
        confusion_matrix: BTreeMap::new(),
    });

    let gates = evaluation_gates(&manifest, 0.9, 0.9, false);
    assert!(
        gates
            .iter()
            .any(|gate| gate.name == "evaluation_present" && gate.passed)
    );
    assert!(
        gates
            .iter()
            .any(|gate| gate.name == "evaluation_degraded" && !gate.passed)
    );
    assert!(
        gates
            .iter()
            .any(|gate| gate.name == "evaluation_labels" && !gate.passed)
    );
    assert!(
        gates
            .iter()
            .any(|gate| gate.name == "accuracy" && !gate.passed)
    );
    assert!(
        gates
            .iter()
            .any(|gate| gate.name == "macro_f1" && !gate.passed)
    );
}

#[test]
fn evaluation_gates_pass_complete_validation_metrics() {
    let mut manifest = manifest();
    manifest.evaluation = Some(complete_evaluation());

    let gates = evaluation_gates(&manifest, 0.9, 0.9, false);

    assert!(gates.iter().all(|gate| gate.passed));
}

#[test]
fn evaluation_gates_require_metrics_for_every_known_label() {
    let mut manifest = manifest();
    let mut evaluation = complete_evaluation();
    evaluation.per_label.remove(FaultLabel::TlsFailure.as_str());
    manifest.evaluation = Some(evaluation);

    let gates = evaluation_gates(&manifest, 0.9, 0.9, false);
    let labels = gates
        .iter()
        .find(|gate| gate.name == "evaluation_labels")
        .expect("evaluation labels gate");

    assert!(!labels.passed);
    assert!(labels.message.contains(FaultLabel::TlsFailure.as_str()));
}

#[test]
fn training_gate_reports_pass_fail_and_missing_states() {
    let passing_manifest = manifest();
    let passed = training_gate(&passing_manifest);
    assert!(passed.passed);
    assert!(
        passed
            .message
            .contains(&format!("{} training rows", FaultLabel::ALL.len() * 2))
    );

    let mut failed_manifest = manifest();
    let gate = failed_manifest.training_gate.as_mut().expect("gate");
    gate.passed = false;
    gate.failures.push("too few rows".to_string());
    let failed = training_gate(&failed_manifest);
    assert!(!failed.passed);
    assert!(failed.message.contains("too few rows"));

    let mut missing_manifest = manifest();
    missing_manifest.training_gate = None;
    let missing = training_gate(&missing_manifest);
    assert!(!missing.passed);
    assert!(missing.message.contains("required"));
}

#[test]
fn known_label_coverage_gate_lists_labels_below_minimum() {
    let mut manifest = manifest();
    manifest
        .label_distribution
        .insert("congestion".to_string(), 0);
    let gate = known_label_coverage_gate(&manifest, 1);
    assert!(!gate.passed);
    assert!(gate.message.contains("congestion=0"));
}

#[test]
fn known_label_coverage_gate_rejects_missing_known_labels() {
    let mut manifest = manifest();
    manifest
        .labels
        .retain(|label| label != FaultLabel::UdpQuicBlocked.as_str());
    let gate = known_label_coverage_gate(&manifest, 1);
    assert!(!gate.passed);
    assert!(gate.message.contains(FaultLabel::UdpQuicBlocked.as_str()));
}

#[test]
fn known_label_coverage_gate_passes_when_all_known_labels_meet_minimum() {
    let gate = known_label_coverage_gate(&manifest(), 2);
    assert!(gate.passed);
    assert!(gate.message.contains("at least 2 rows"));
}

#[test]
fn ood_coverage_gate_requires_ood_benchmark_section() {
    let report = benchmark_report(Vec::new(), true);
    let gate = ood_coverage_gate(&report);
    assert!(!gate.passed);
    assert!(gate.message.contains("missing explicit OOD coverage"));
}

#[test]
fn ood_coverage_gate_rejects_ood_failures() {
    let report = benchmark_report(vec![ood_section(ConnectorHealthStatus::Error)], false);
    let gate = ood_coverage_gate(&report);
    assert!(!gate.passed);
    assert!(gate.message.contains("ood-cpu-saturation"));
}

#[test]
fn ood_coverage_gate_passes_explicit_ood_examples() {
    let report = benchmark_report(vec![ood_section(ConnectorHealthStatus::Ok)], true);
    let gate = ood_coverage_gate(&report);
    assert!(gate.passed);
    assert!(gate.message.contains("explicit OOD examples"));
}

#[test]
fn calibration_gates_require_artifact_and_model_match() {
    let missing = calibration_gates(
        Err("missing file"),
        &calibrated_manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );
    let present = gate_by_name(&missing, "calibration_present");
    assert!(!present.passed);
    assert!(present.message.contains("missing file"));

    let mut report = calibration_report();
    report.model_manifest_hash_sha256 = Some("stale".to_string());
    let mismatch = calibration_gates(
        Ok(&report),
        &calibrated_manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );
    let model_match = gate_by_name(&mismatch, "calibration_model_match");
    assert!(!model_match.passed);
    assert!(model_match.message.contains("manifest hash mismatch"));
}

#[test]
fn calibration_gates_pass_with_applied_current_lab_artifact() {
    let report = calibration_report();
    let gates = calibration_gates(
        Ok(&report),
        &calibrated_manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );

    assert!(
        gates.iter().all(|gate| gate.passed),
        "unexpected failed gates: {gates:?}"
    );
}

#[test]
fn calibration_gates_reject_unapplied_stale_or_unintegrated_artifacts() {
    let mut unapplied = calibration_report();
    unapplied.applied = false;
    let gates = calibration_gates(
        Ok(&unapplied),
        &calibrated_manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );
    assert!(!gate_by_name(&gates, "calibration_applied").passed);

    let mut stale = calibration_report();
    stale.generated_at = Utc::now() - Duration::days(31);
    let gates = calibration_gates(
        Ok(&stale),
        &calibrated_manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );
    assert!(!gate_by_name(&gates, "calibration_freshness").passed);

    let gates = calibration_gates(
        Ok(&calibration_report()),
        &manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );
    assert!(!gate_by_name(&gates, "calibration_thresholds_integrated").passed);
}

#[test]
fn calibration_gates_reject_bad_ood_behavior_and_hotspots() {
    let mut report = calibration_report();
    report.ood.expected_known_runs = 20;
    report.ood.false_positive_runs = 1;
    report.ood.false_positive_rate = 0.05;
    let gates = calibration_gates(
        Ok(&report),
        &calibrated_manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );
    assert!(gate_by_name(&gates, "ood_false_positive_rate").passed);

    report.ood.false_positive_runs = 2;
    report.ood.false_positive_rate = 0.10;
    report.ood.expected_ood_runs = 10;
    report.ood.false_negative_runs = 2;
    report.ood.false_negative_rate = 0.20;
    report.rule_ml_disagreement_hotspots = vec![LabCalibrationHotspot {
        scenario_id: "lab-hotspot".to_string(),
        scenario_name: "Lab Hotspot".to_string(),
        disagreements: 2,
        runs: 10,
        rate: 0.20,
    }];
    let gates = calibration_gates(
        Ok(&report),
        &calibrated_manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );
    assert!(!gate_by_name(&gates, "ood_false_positive_rate").passed);
    assert!(!gate_by_name(&gates, "ood_false_negative_rate").passed);
    let hotspots = gate_by_name(&gates, "rule_ml_disagreement_hotspots");
    assert!(!hotspots.passed);
    assert!(hotspots.message.contains("lab-hotspot"));
}

#[test]
fn calibration_gates_require_known_label_and_ood_coverage() {
    let mut report = calibration_report();
    report
        .per_label
        .get_mut(FaultLabel::TlsFailure.as_str())
        .expect("label")
        .accepted_known_runs = 0;
    report.ood.expected_ood_runs = 0;
    let gates = calibration_gates(
        Ok(&report),
        &calibrated_manifest(),
        &calibration_options(),
        Some("manifest-hash"),
        Some("model-hash"),
    );
    let coverage = gate_by_name(&gates, "calibration_coverage");
    assert!(!coverage.passed);
    assert!(coverage.message.contains(FaultLabel::TlsFailure.as_str()));
    assert!(coverage.message.contains("expected OOD runs"));
}

#[test]
fn model_promotion_options_reject_invalid_thresholds() {
    let result = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: "missing/model".into(),
        benchmark_report: "missing/benchmark.json".into(),
        calibration_report: "missing/calibration.json".into(),
        min_rows_per_label: 1,
        min_accuracy: f64::NAN,
        min_macro_f1: 0.9,
        allow_missing_evaluation: true,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    });

    let message = result.expect_err("invalid threshold").to_string();
    assert!(message.contains("min_accuracy"));
}

#[test]
fn model_promotion_gate_requires_evaluation_unless_explicitly_allowed() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let benchmark_report = temp.path().join("benchmark_report.json");
    write_passing_benchmark(&benchmark_report);
    let calibration_report = write_passing_calibration(&artifacts);

    let strict = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: artifacts.join("model"),
        benchmark_report: benchmark_report.clone(),
        calibration_report: calibration_report.clone(),
        min_rows_per_label: 1,
        min_accuracy: 0.9,
        min_macro_f1: 0.9,
        allow_missing_evaluation: false,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    })
    .expect("strict gate");
    assert!(!strict.passed);
    assert!(
        strict
            .gates
            .iter()
            .any(|gate| gate.name == "evaluation_present" && !gate.passed)
    );

    let allowed = evaluate_model_promotion(ModelPromotionOptions {
        model_dir: artifacts.join("model"),
        benchmark_report,
        calibration_report,
        min_rows_per_label: 1,
        min_accuracy: 0.9,
        min_macro_f1: 0.9,
        allow_missing_evaluation: true,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 30,
        min_expected_ood_runs: 1,
    })
    .expect("allowed gate");
    assert!(allowed.passed);
}

#[test]
fn default_promotion_thresholds_are_release_grade() {
    assert_eq!(default_min_accuracy(), 0.90);
    assert_eq!(default_min_macro_f1(), 0.90);
    assert_eq!(default_max_ood_false_positive_rate(), 0.05);
    assert_eq!(default_max_ood_false_negative_rate(), 0.05);
    assert_eq!(default_max_rule_ml_disagreement_hotspot_rate(), 0.10);
    assert_eq!(default_max_calibration_age_days(), 30);
    assert_eq!(default_min_expected_ood_runs(), 1);
}
