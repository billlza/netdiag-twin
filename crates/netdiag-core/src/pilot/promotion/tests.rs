use super::*;
use crate::models::{LabelMetrics, ModelEvaluation, ModelTrainingGate};
use std::collections::BTreeMap;

fn manifest() -> ModelManifest {
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
        labels: vec!["normal".to_string(), "congestion".to_string()],
        training_examples: 4,
        label_distribution: BTreeMap::from([
            ("normal".to_string(), 2),
            ("congestion".to_string(), 2),
        ]),
        feature_count: 1,
        synthetic_fallback: false,
        training_config: None,
        evaluation: None,
        training_gate: Some(ModelTrainingGate {
            passed: true,
            rows: 4,
            dataset_rows: 4,
            training_rows: 4,
            validation_rows: 0,
            min_rows_per_label: 1,
            validation_split: 0.0,
            stratified: false,
            failures: Vec::new(),
        }),
        uncertainty_thresholds: None,
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
    manifest.evaluation = Some(ModelEvaluation {
        validation_examples: 4,
        accuracy: 0.95,
        macro_f1: 0.94,
        degraded: false,
        warnings: Vec::new(),
        missing_validation_labels: Vec::new(),
        per_label: BTreeMap::from([
            (
                "normal".to_string(),
                LabelMetrics {
                    support: 2,
                    precision: 1.0,
                    recall: 0.9,
                    f1: 0.95,
                },
            ),
            (
                "congestion".to_string(),
                LabelMetrics {
                    support: 2,
                    precision: 0.9,
                    recall: 1.0,
                    f1: 0.95,
                },
            ),
        ]),
        confusion_matrix: BTreeMap::new(),
    });

    let gates = evaluation_gates(&manifest, 0.9, 0.9, false);

    assert!(gates.iter().all(|gate| gate.passed));
}

#[test]
fn training_gate_reports_pass_fail_and_missing_states() {
    let passing_manifest = manifest();
    let passed = training_gate(&passing_manifest);
    assert!(passed.passed);
    assert!(passed.message.contains("4 training rows"));

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
fn label_distribution_gate_lists_missing_labels() {
    let mut manifest = manifest();
    manifest
        .label_distribution
        .insert("congestion".to_string(), 0);
    let gate = label_distribution_gate(&manifest, 1);
    assert!(!gate.passed);
    assert!(gate.message.contains("congestion=0"));
}

#[test]
fn label_distribution_gate_passes_when_all_labels_meet_minimum() {
    let gate = label_distribution_gate(&manifest(), 2);
    assert!(gate.passed);
    assert!(gate.message.contains("at least 2 rows"));
}

#[test]
fn default_promotion_thresholds_are_release_grade() {
    assert_eq!(default_min_accuracy(), 0.90);
    assert_eq!(default_min_macro_f1(), 0.90);
}
