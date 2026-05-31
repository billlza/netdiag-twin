use super::*;
use crate::benchmark::{BenchmarkCheck, BenchmarkEnvironment, BenchmarkReport, BenchmarkSection};
use crate::models::{
    ConnectorHealthStatus, FaultLabel, LabelMetrics, ModelEvaluation, ModelTrainingGate,
};
use std::collections::BTreeMap;

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
fn default_promotion_thresholds_are_release_grade() {
    assert_eq!(default_min_accuracy(), 0.90);
    assert_eq!(default_min_macro_f1(), 0.90);
}
