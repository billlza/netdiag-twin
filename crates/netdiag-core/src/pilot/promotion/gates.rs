use super::{ModelPromotionGate, gate};
use crate::benchmark::BenchmarkReport;
use crate::models::{ConnectorHealthStatus, FaultLabel, ModelManifest};
use std::collections::BTreeSet;

pub(super) fn training_gate(manifest: &ModelManifest) -> ModelPromotionGate {
    match &manifest.training_gate {
        Some(training_gate) if training_gate.passed => gate(
            "training_gate",
            true,
            format!(
                "training gate passed with {} training rows",
                training_gate.training_rows
            ),
        ),
        Some(training_gate) => gate(
            "training_gate",
            false,
            format!(
                "training gate failed: {}",
                training_gate.failures.join("; ")
            ),
        ),
        None => gate("training_gate", false, "training_gate is required"),
    }
}

pub(super) fn known_label_coverage_gate(
    manifest: &ModelManifest,
    min_rows_per_label: usize,
) -> ModelPromotionGate {
    let declared = manifest
        .labels
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let missing_declared = FaultLabel::ALL
        .iter()
        .filter_map(|label| {
            let label = label.as_str();
            (!declared.contains(label)).then_some(label.to_string())
        })
        .collect::<Vec<_>>();
    let below_minimum = FaultLabel::ALL
        .iter()
        .filter_map(|label| {
            let label = label.as_str();
            let rows = manifest.label_distribution.get(label).copied().unwrap_or(0);
            (rows < min_rows_per_label).then(|| format!("{label}={rows}"))
        })
        .collect::<Vec<_>>();
    let passed = missing_declared.is_empty() && below_minimum.is_empty();
    gate(
        "known_label_coverage",
        passed,
        known_label_coverage_message(passed, min_rows_per_label, missing_declared, below_minimum),
    )
}

fn known_label_coverage_message(
    passed: bool,
    min_rows_per_label: usize,
    missing_declared: Vec<String>,
    below_minimum: Vec<String>,
) -> String {
    if passed {
        return format!("all known labels have at least {min_rows_per_label} rows");
    }
    let mut failures = Vec::new();
    if !missing_declared.is_empty() {
        failures.push(format!(
            "manifest.labels missing known labels: {}",
            missing_declared.join(", ")
        ));
    }
    if !below_minimum.is_empty() {
        failures.push(format!(
            "known labels below min_rows_per_label {min_rows_per_label}: {}",
            below_minimum.join(", ")
        ));
    }
    failures.join("; ")
}

pub(super) fn evaluation_gates(
    manifest: &ModelManifest,
    min_accuracy: f64,
    min_macro_f1: f64,
    allow_missing_evaluation: bool,
) -> Vec<ModelPromotionGate> {
    let Some(evaluation) = &manifest.evaluation else {
        return vec![gate(
            "evaluation_present",
            allow_missing_evaluation,
            if allow_missing_evaluation {
                "evaluation is missing but explicitly allowed"
            } else {
                "evaluation is required for model promotion"
            },
        )];
    };
    let missing_known = missing_known_validation_labels(manifest);
    vec![
        gate("evaluation_present", true, "evaluation is present"),
        gate(
            "evaluation_degraded",
            !evaluation.degraded,
            if evaluation.degraded {
                "evaluation is marked degraded"
            } else {
                "evaluation is not degraded"
            },
        ),
        gate(
            "evaluation_labels",
            evaluation.missing_validation_labels.is_empty() && missing_known.is_empty(),
            evaluation_labels_message(&evaluation.missing_validation_labels, &missing_known),
        ),
        gate(
            "accuracy",
            evaluation.accuracy >= min_accuracy,
            format!(
                "accuracy {:.4} requires >= {:.4}",
                evaluation.accuracy, min_accuracy
            ),
        ),
        gate(
            "macro_f1",
            evaluation.macro_f1 >= min_macro_f1,
            format!(
                "macro_f1 {:.4} requires >= {:.4}",
                evaluation.macro_f1, min_macro_f1
            ),
        ),
    ]
}

fn missing_known_validation_labels(manifest: &ModelManifest) -> Vec<String> {
    let Some(evaluation) = &manifest.evaluation else {
        return Vec::new();
    };
    FaultLabel::ALL
        .iter()
        .filter_map(|label| {
            let label = label.as_str();
            let explicitly_missing = evaluation
                .missing_validation_labels
                .iter()
                .any(|missing| missing == label);
            let missing_metrics = evaluation
                .per_label
                .get(label)
                .is_none_or(|metrics| metrics.support == 0);
            (explicitly_missing || missing_metrics).then_some(label.to_string())
        })
        .collect()
}

fn evaluation_labels_message(missing_validation: &[String], missing_known: &[String]) -> String {
    if missing_validation.is_empty() && missing_known.is_empty() {
        return "all known labels were present in validation".to_string();
    }
    if missing_known.is_empty() {
        return format!(
            "missing validation labels: {}",
            missing_validation.join(", ")
        );
    }
    format!(
        "missing known validation labels: {}",
        missing_known.join(", ")
    )
}

pub(super) fn ood_coverage_gate(benchmark: &BenchmarkReport) -> ModelPromotionGate {
    let Some(section) = benchmark
        .sections
        .iter()
        .find(|section| section.name == "ood benchmark preflight")
    else {
        return gate(
            "ood_coverage",
            false,
            "benchmark report is missing explicit OOD coverage",
        );
    };
    if section.checks.is_empty() {
        return gate(
            "ood_coverage",
            false,
            "OOD benchmark section has no explicit OOD examples",
        );
    }
    let failed = section
        .checks
        .iter()
        .filter(|check| check.status == ConnectorHealthStatus::Error)
        .map(|check| check.name.clone())
        .collect::<Vec<_>>();
    gate(
        "ood_coverage",
        failed.is_empty(),
        if failed.is_empty() {
            format!(
                "{} explicit OOD examples passed benchmark preflight",
                section.checks.len()
            )
        } else {
            format!("OOD benchmark failures: {}", failed.join(", "))
        },
    )
}
