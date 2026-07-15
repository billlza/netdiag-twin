use super::{
    LabAcceptanceReport, LabSummaryFailure, LabSummaryLabelStats, LabSummaryReport,
    LabSummaryScenarioStats, read_lab_run_index, round4,
};
use crate::error::{NetdiagError, Result};
use crate::models::ConnectorHealthStatus;
use crate::storage::resolve_stored_path;
use chrono::Utc;
use std::collections::BTreeMap;
use std::path::Path;

mod read;
use read::{lab_acceptance as read_lab_acceptance, lab_comparison as read_lab_comparison};

pub fn summarize_lab_runs(artifact_root: impl AsRef<Path>) -> Result<LabSummaryReport> {
    let artifact_root = artifact_root.as_ref();
    let index = read_lab_run_index(artifact_root)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "lab run index is missing: {}",
            artifact_root.join("lab_run_index.json").display()
        ))
    })?;
    let mut by_label = BTreeMap::<String, LabSummaryAccumulator>::new();
    let mut by_scenario = BTreeMap::<String, LabSummaryAccumulator>::new();
    let mut scenario_names = BTreeMap::<String, String>::new();
    let mut quality = BTreeMap::<String, usize>::new();
    let mut diagnosis_statuses = BTreeMap::<String, usize>::new();
    let mut failures = Vec::new();
    let mut passed = 0usize;

    for entry in &index.runs {
        let acceptance_path = resolve_stored_path(artifact_root, &entry.acceptance_path)?;
        let acceptance = match read_lab_acceptance(&acceptance_path) {
            Ok(acceptance) => acceptance,
            Err(err) => {
                failures.push(summary_failure(
                    entry,
                    format!("acceptance unavailable: {err}"),
                ));
                continue;
            }
        };
        let comparison_path = resolve_stored_path(artifact_root, &entry.comparison_path)?;
        let comparison = match read_lab_comparison(&comparison_path) {
            Ok(comparison) => comparison,
            Err(err) => {
                failures.push(summary_failure(
                    entry,
                    format!("comparison unavailable: {err}"),
                ));
                continue;
            }
        };
        if acceptance.passed {
            passed += 1;
        } else {
            failures.push(LabSummaryFailure {
                run_id: entry.run_id.clone(),
                scenario_id: entry.scenario_id.clone(),
                failures: acceptance.failures.clone(),
            });
        }
        *quality
            .entry(acceptance.quality_status.as_str().to_string())
            .or_default() += 1;
        *diagnosis_statuses
            .entry(acceptance.actual_diagnosis_status.as_str().to_string())
            .or_default() += 1;
        let expected = acceptance
            .expected_label
            .map(|label| label.as_str().to_string());
        let expected_key = expected
            .clone()
            .unwrap_or_else(|| format!("status:{}", acceptance.actual_diagnosis_status.as_str()));
        let rule_correct = expected.as_ref().is_some_and(|expected| {
            acceptance
                .actual_rule_labels
                .iter()
                .any(|label| label == expected)
        });
        let ml_correct = expected
            .as_ref()
            .is_some_and(|expected| acceptance.actual_ml_top == *expected);
        let quality_degraded = acceptance.quality_status != ConnectorHealthStatus::Ok;
        record_summary_sample(
            by_label.entry(expected_key).or_default(),
            &acceptance,
            rule_correct,
            ml_correct,
            quality_degraded,
            !comparison.rule_ml_agreement,
        );
        scenario_names.insert(entry.scenario_id.clone(), entry.scenario_name.clone());
        record_summary_sample(
            by_scenario.entry(entry.scenario_id.clone()).or_default(),
            &acceptance,
            rule_correct,
            ml_correct,
            quality_degraded,
            !comparison.rule_ml_agreement,
        );
    }

    Ok(LabSummaryReport {
        schema: "netdiag-lab-summary/v1".to_string(),
        generated_at: Utc::now(),
        artifact_root: artifact_root.display().to_string(),
        total_runs: index.runs.len(),
        passed,
        failed: index.runs.len().saturating_sub(passed),
        by_label: by_label
            .into_iter()
            .map(|(label, stats)| (label, stats.into_summary()))
            .collect(),
        by_scenario: by_scenario
            .into_iter()
            .map(|(scenario_id, stats)| {
                let name = scenario_names
                    .remove(&scenario_id)
                    .unwrap_or_else(|| scenario_id.clone());
                (scenario_id, stats.into_scenario_summary(name))
            })
            .collect(),
        quality,
        diagnosis_statuses,
        failures,
    })
}

fn summary_failure(entry: &super::LabRunIndexEntry, message: String) -> LabSummaryFailure {
    LabSummaryFailure {
        run_id: entry.run_id.clone(),
        scenario_id: entry.scenario_id.clone(),
        failures: vec![message],
    }
}

#[derive(Debug, Clone, Default)]
struct LabSummaryAccumulator {
    runs: usize,
    passed: usize,
    rule_correct: usize,
    ml_correct: usize,
    quality_degraded: usize,
    rule_ml_disagreement: usize,
}

impl LabSummaryAccumulator {
    fn into_summary(self) -> LabSummaryLabelStats {
        let denominator = self.runs.max(1) as f64;
        LabSummaryLabelStats {
            runs: self.runs,
            passed: self.passed,
            rule_accuracy: round4(self.rule_correct as f64 / denominator),
            ml_accuracy: round4(self.ml_correct as f64 / denominator),
        }
    }

    fn into_scenario_summary(self, scenario_name: String) -> LabSummaryScenarioStats {
        let denominator = self.runs.max(1) as f64;
        LabSummaryScenarioStats {
            scenario_name,
            runs: self.runs,
            passed: self.passed,
            failed: self.runs.saturating_sub(self.passed),
            rule_accuracy: round4(self.rule_correct as f64 / denominator),
            ml_accuracy: round4(self.ml_correct as f64 / denominator),
            quality_degraded_rate: round4(self.quality_degraded as f64 / denominator),
            rule_ml_disagreement_rate: round4(self.rule_ml_disagreement as f64 / denominator),
        }
    }
}

fn record_summary_sample(
    stats: &mut LabSummaryAccumulator,
    acceptance: &LabAcceptanceReport,
    rule_correct: bool,
    ml_correct: bool,
    quality_degraded: bool,
    rule_ml_disagreement: bool,
) {
    stats.runs += 1;
    stats.passed += usize::from(acceptance.passed);
    stats.rule_correct += usize::from(rule_correct);
    stats.ml_correct += usize::from(ml_correct);
    stats.quality_degraded += usize::from(quality_degraded);
    stats.rule_ml_disagreement += usize::from(rule_ml_disagreement);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_lab_index_fails_closed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let error = summarize_lab_runs(temp.path()).expect_err("missing index must fail");
        assert!(error.to_string().contains("lab run index is missing"));
    }
}
