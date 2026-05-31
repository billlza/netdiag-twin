use super::{ModelPromotionGate, gate};
use crate::lab::LabCalibrationReport;
use crate::models::{FaultLabel, ModelManifest};
use chrono::{Duration, Utc};

const CALIBRATION_SCHEMA: &str = "netdiag-lab-calibration/v1";

#[derive(Debug, Clone, Copy)]
pub(super) struct CalibrationGateOptions {
    pub max_ood_false_positive_rate: f64,
    pub max_ood_false_negative_rate: f64,
    pub max_rule_ml_disagreement_hotspot_rate: f64,
    pub max_calibration_age_days: u64,
    pub min_expected_ood_runs: usize,
}

pub(super) fn calibration_gates(
    calibration: std::result::Result<&LabCalibrationReport, &str>,
    manifest: &ModelManifest,
    options: &CalibrationGateOptions,
    current_manifest_hash: Option<&str>,
    current_model_hash: Option<&str>,
) -> Vec<ModelPromotionGate> {
    let report = match calibration {
        Ok(report) => report,
        Err(err) => {
            return vec![gate(
                "calibration_present",
                false,
                format!("calibration report is required: {err}"),
            )];
        }
    };

    vec![
        gate("calibration_present", true, "calibration report loaded"),
        calibration_schema_gate(report),
        calibration_applied_gate(report),
        calibration_freshness_gate(report, options.max_calibration_age_days),
        calibration_model_match_gate(report, manifest, current_manifest_hash, current_model_hash),
        calibration_thresholds_integrated_gate(report, manifest),
        calibration_coverage_gate(report, options.min_expected_ood_runs),
        ood_false_positive_gate(report, options.max_ood_false_positive_rate),
        ood_false_negative_gate(report, options.max_ood_false_negative_rate),
        rule_ml_disagreement_hotspot_gate(report, options.max_rule_ml_disagreement_hotspot_rate),
    ]
}

fn calibration_schema_gate(report: &LabCalibrationReport) -> ModelPromotionGate {
    gate(
        "calibration_schema",
        report.schema == CALIBRATION_SCHEMA,
        if report.schema == CALIBRATION_SCHEMA {
            "calibration schema is supported".to_string()
        } else {
            format!(
                "unsupported calibration schema {}; expected {CALIBRATION_SCHEMA}",
                report.schema
            )
        },
    )
}

fn calibration_applied_gate(report: &LabCalibrationReport) -> ModelPromotionGate {
    gate(
        "calibration_applied",
        report.applied,
        if report.applied {
            "calibration thresholds were applied to the model manifest".to_string()
        } else {
            "calibration report was not applied to the model manifest".to_string()
        },
    )
}

fn calibration_freshness_gate(
    report: &LabCalibrationReport,
    max_age_days: u64,
) -> ModelPromotionGate {
    let age = Utc::now().signed_duration_since(report.generated_at);
    if age < -Duration::minutes(5) {
        return gate(
            "calibration_freshness",
            false,
            "calibration report timestamp is in the future",
        );
    }
    let max_age = Duration::days(i64::try_from(max_age_days).unwrap_or(i64::MAX));
    gate(
        "calibration_freshness",
        age <= max_age,
        format!(
            "calibration age {:.2} days requires <= {} days",
            age.num_seconds().max(0) as f64 / 86_400.0,
            max_age_days
        ),
    )
}

fn calibration_model_match_gate(
    report: &LabCalibrationReport,
    manifest: &ModelManifest,
    current_manifest_hash: Option<&str>,
    current_model_hash: Option<&str>,
) -> ModelPromotionGate {
    let mut failures = Vec::new();
    match (
        report.model_manifest_hash_sha256.as_deref(),
        current_manifest_hash,
    ) {
        (Some(report_hash), Some(current_hash)) if report_hash == current_hash => {}
        (Some(report_hash), Some(current_hash)) => failures.push(format!(
            "manifest hash mismatch calibration={report_hash} current={current_hash}"
        )),
        _ => failures.push("model manifest hash missing".to_string()),
    }
    match (report.model_file_hash_sha256.as_deref(), current_model_hash) {
        (Some(report_hash), Some(current_hash)) if report_hash == current_hash => {}
        (Some(report_hash), Some(current_hash)) => failures.push(format!(
            "model file hash mismatch calibration={report_hash} current={current_hash}"
        )),
        _ => failures.push("model file hash missing".to_string()),
    }
    match (
        report.dataset_hash_sha256.as_deref(),
        manifest.dataset_hash_sha256.as_deref(),
    ) {
        (Some(report_hash), Some(manifest_hash)) if report_hash == manifest_hash => {}
        (Some(report_hash), Some(manifest_hash)) => failures.push(format!(
            "dataset hash mismatch calibration={report_hash} manifest={manifest_hash}"
        )),
        _ => failures.push("dataset hash missing".to_string()),
    }
    gate(
        "calibration_model_match",
        failures.is_empty(),
        if failures.is_empty() {
            "calibration artifact matches model and dataset hashes".to_string()
        } else {
            failures.join("; ")
        },
    )
}

fn calibration_thresholds_integrated_gate(
    report: &LabCalibrationReport,
    manifest: &ModelManifest,
) -> ModelPromotionGate {
    let integrated = manifest
        .uncertainty_thresholds
        .as_ref()
        .is_some_and(|thresholds| thresholds == &report.calibrated_thresholds);
    gate(
        "calibration_thresholds_integrated",
        integrated,
        if integrated {
            "model manifest contains calibrated uncertainty thresholds".to_string()
        } else {
            "model manifest does not contain the calibration report thresholds".to_string()
        },
    )
}

fn calibration_coverage_gate(
    report: &LabCalibrationReport,
    min_expected_ood_runs: usize,
) -> ModelPromotionGate {
    let missing_labels = FaultLabel::ALL
        .iter()
        .filter_map(|label| {
            let label = label.as_str();
            let accepted_runs = report
                .per_label
                .get(label)
                .map(|stats| stats.accepted_known_runs)
                .unwrap_or_default();
            (accepted_runs == 0).then_some(label.to_string())
        })
        .collect::<Vec<_>>();
    let ood_covered = report.ood.expected_ood_runs >= min_expected_ood_runs
        && report.out_of_distribution_runs >= min_expected_ood_runs;
    let passed = missing_labels.is_empty() && ood_covered;
    let message = if passed {
        format!(
            "calibration covers all known labels and {} expected OOD runs",
            report.ood.expected_ood_runs
        )
    } else {
        calibration_coverage_failure_message(report, min_expected_ood_runs, &missing_labels)
    };
    gate("calibration_coverage", passed, message)
}

fn calibration_coverage_failure_message(
    report: &LabCalibrationReport,
    min_expected_ood_runs: usize,
    missing_labels: &[String],
) -> String {
    let mut failures = Vec::new();
    if !missing_labels.is_empty() {
        failures.push(format!(
            "calibration missing known labels: {}",
            missing_labels.join(", ")
        ));
    }
    if report.ood.expected_ood_runs < min_expected_ood_runs {
        failures.push(format!(
            "expected OOD runs {} requires >= {}",
            report.ood.expected_ood_runs, min_expected_ood_runs
        ));
    }
    if report.out_of_distribution_runs < min_expected_ood_runs {
        failures.push(format!(
            "accepted OOD runs {} requires >= {}",
            report.out_of_distribution_runs, min_expected_ood_runs
        ));
    }
    failures.join("; ")
}

fn ood_false_positive_gate(report: &LabCalibrationReport, max_rate: f64) -> ModelPromotionGate {
    let has_known_examples = report.ood.expected_known_runs > 0;
    let expected_rate = behavior_rate(
        report.ood.false_positive_runs,
        report.ood.expected_known_runs,
    );
    let rate_is_valid = rate_matches(report.ood.false_positive_rate, expected_rate);
    let passed = has_known_examples && rate_is_valid && expected_rate <= max_rate;
    gate(
        "ood_false_positive_rate",
        passed,
        if !has_known_examples {
            "OOD false positive rate requires accepted known calibration runs".to_string()
        } else if !rate_is_valid {
            format!(
                "OOD false positive rate artifact mismatch stored={:.4} recomputed={:.4}",
                report.ood.false_positive_rate, expected_rate
            )
        } else {
            format!(
                "OOD false positive rate {:.4} requires <= {:.4}",
                expected_rate, max_rate
            )
        },
    )
}

fn ood_false_negative_gate(report: &LabCalibrationReport, max_rate: f64) -> ModelPromotionGate {
    let has_ood_examples = report.ood.expected_ood_runs > 0;
    let expected_rate = behavior_rate(report.ood.false_negative_runs, report.ood.expected_ood_runs);
    let rate_is_valid = rate_matches(report.ood.false_negative_rate, expected_rate);
    let passed = has_ood_examples && rate_is_valid && expected_rate <= max_rate;
    gate(
        "ood_false_negative_rate",
        passed,
        if !has_ood_examples {
            "OOD false negative rate requires accepted OOD calibration runs".to_string()
        } else if !rate_is_valid {
            format!(
                "OOD false negative rate artifact mismatch stored={:.4} recomputed={:.4}",
                report.ood.false_negative_rate, expected_rate
            )
        } else {
            format!(
                "OOD false negative rate {:.4} requires <= {:.4}",
                expected_rate, max_rate
            )
        },
    )
}

fn rule_ml_disagreement_hotspot_gate(
    report: &LabCalibrationReport,
    max_hotspot_rate: f64,
) -> ModelPromotionGate {
    let invalid = report
        .rule_ml_disagreement_hotspots
        .iter()
        .filter(|hotspot| {
            hotspot.runs == 0
                || !rate_matches(
                    hotspot.rate,
                    behavior_rate(hotspot.disagreements, hotspot.runs),
                )
        })
        .map(|hotspot| {
            format!(
                "{} stored={:.4} recomputed={:.4} ({}/{})",
                hotspot.scenario_id,
                hotspot.rate,
                behavior_rate(hotspot.disagreements, hotspot.runs),
                hotspot.disagreements,
                hotspot.runs
            )
        })
        .collect::<Vec<_>>();
    let hotspots = report
        .rule_ml_disagreement_hotspots
        .iter()
        .filter(|hotspot| hotspot.rate > max_hotspot_rate)
        .map(|hotspot| {
            format!(
                "{}={:.4} ({}/{})",
                hotspot.scenario_id, hotspot.rate, hotspot.disagreements, hotspot.runs
            )
        })
        .collect::<Vec<_>>();
    let passed = invalid.is_empty() && hotspots.is_empty();
    gate(
        "rule_ml_disagreement_hotspots",
        passed,
        if !invalid.is_empty() {
            format!(
                "rule/ML disagreement hotspot artifact mismatch: {}",
                invalid.join(", ")
            )
        } else if hotspots.is_empty() {
            format!(
                "no rule/ML disagreement hotspots above {:.4}",
                max_hotspot_rate
            )
        } else {
            format!(
                "rule/ML disagreement hotspots above {:.4}: {}",
                max_hotspot_rate,
                hotspots.join(", ")
            )
        },
    )
}

fn behavior_rate(count: usize, denominator: usize) -> f64 {
    ((count as f64 / denominator.max(1) as f64) * 10_000.0).round() / 10_000.0
}

fn rate_matches(stored: f64, recomputed: f64) -> bool {
    stored.is_finite() && (stored - recomputed).abs() <= 0.0001
}
