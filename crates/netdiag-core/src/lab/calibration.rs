use super::{LabAcceptanceReport, LabRunComparison, LabRunIndex, LabRunIndexEntry, round4};
use crate::error::{NetdiagError, Result};
use crate::ml::with_model_bundle_lock;
use crate::models::{DiagnosisStatus, FaultLabel, MlResult, ModelUncertaintyThresholds};
use crate::storage::typed_json::{
    MAX_LAB_ACCEPTANCE_BYTES, MAX_LAB_COMPARISON_BYTES, MAX_ML_RESULT_BYTES,
    read_required_stable_json_bounded,
};
use crate::storage::{resolve_stored_path, run_dir, save_json_atomic};
use crate::telemetry::quantile;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

mod evidence_identity;
mod model_identity;
mod report;
mod rule_events;
mod thresholds;
use evidence_identity::{
    validate_acceptance_identity, validate_comparison_identity, validate_ml_identity,
};
use model_identity::{CalibrationModelIdentity, require_lab_run_index};
use report::{CalibrationReportContext, build_report};
use rule_events::read_rule_threshold_confidences;
use thresholds::{calibrated_thresholds, calibration_distribution};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabCalibrationReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub artifact_root: String,
    pub model_manifest_path: String,
    /// Manifest hash captured before calibration mutates uncertainty thresholds.
    pub source_model_manifest_hash_sha256: String,
    /// Current manifest hash after calibration has been applied, or the source hash for dry runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_manifest_hash_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_file_hash_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_hash_sha256: Option<String>,
    pub evaluated_runs: usize,
    pub known_runs: usize,
    pub uncertain_runs: usize,
    pub out_of_distribution_runs: usize,
    pub skipped_runs: usize,
    #[serde(default)]
    pub per_label: BTreeMap<String, LabCalibrationLabelStats>,
    pub ood: LabCalibrationOodStats,
    #[serde(default)]
    pub rule_ml_disagreement_hotspots: Vec<LabCalibrationHotspot>,
    pub feature_distance_distribution: LabCalibrationDistribution,
    #[serde(default)]
    pub suggested_rule_thresholds: BTreeMap<String, f64>,
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_thresholds: Option<ModelUncertaintyThresholds>,
    pub calibrated_thresholds: ModelUncertaintyThresholds,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabCalibrationLabelStats {
    pub runs: usize,
    #[serde(default)]
    pub accepted_known_runs: usize,
    pub rule_correct: usize,
    pub ml_correct: usize,
    pub rule_accuracy: f64,
    pub ml_accuracy: f64,
    pub known_rate: f64,
    pub uncertain_rate: f64,
    pub out_of_distribution_rate: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabCalibrationOodStats {
    pub expected_ood_runs: usize,
    pub expected_known_runs: usize,
    pub false_positive_runs: usize,
    pub false_negative_runs: usize,
    pub false_positive_rate: f64,
    pub false_negative_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabCalibrationHotspot {
    pub scenario_id: String,
    pub scenario_name: String,
    pub disagreements: usize,
    pub runs: usize,
    pub rate: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabCalibrationDistribution {
    pub count: usize,
    pub p50: f64,
    pub p95: f64,
    pub max: f64,
}

pub fn calibrate_lab_uncertainty(
    artifact_root: impl AsRef<Path>,
    dry_run: bool,
) -> Result<LabCalibrationReport> {
    let artifact_root = artifact_root.as_ref();
    crate::storage::ensure_artifact_root_owned(artifact_root)?;
    let model_dir = artifact_root.join("model");
    with_model_bundle_lock(&model_dir, || {
        calibrate_lab_uncertainty_locked(artifact_root, dry_run, &model_dir)
    })
}

fn calibrate_lab_uncertainty_locked(
    artifact_root: &Path,
    dry_run: bool,
    model_dir: &Path,
) -> Result<LabCalibrationReport> {
    let (mut manifest, source_identity) = CalibrationModelIdentity::load(model_dir)?;
    let previous_thresholds = manifest.uncertainty_thresholds.clone();
    let index = require_lab_run_index(artifact_root)?;
    let inputs = LabCalibrationInputs::collect(artifact_root, &index, &source_identity)?;
    inputs.ensure_known_runs()?;

    let previous = previous_thresholds.clone().unwrap_or_default();
    let calibrated_thresholds = calibrated_thresholds(&inputs, &previous);
    let applied = !dry_run && inputs.has_lab_grade_coverage();
    source_identity.ensure_source_bundle_unchanged(model_dir)?;
    let published_snapshot = if applied {
        manifest.uncertainty_thresholds = Some(calibrated_thresholds.clone());
        Some(source_identity.publish_manifest(model_dir, &manifest)?)
    } else {
        None
    };
    let model_manifest_path = published_snapshot
        .as_ref()
        .map(|snapshot| snapshot.manifest_path.as_path())
        .unwrap_or_else(|| source_identity.source_manifest_path());
    let current_manifest_hash_sha256 = published_snapshot
        .as_ref()
        .map(|snapshot| snapshot.model_manifest_hash_sha256.clone())
        .unwrap_or_else(|| source_identity.source_manifest_hash_sha256.clone());

    let report = build_report(
        CalibrationReportContext {
            artifact_root,
            model_manifest_path,
            source_identity: &source_identity,
            current_manifest_hash_sha256,
            previous_thresholds,
            calibrated_thresholds,
            applied,
        },
        inputs,
    );
    if !dry_run {
        save_json_atomic(artifact_root.join("lab_calibration_report.json"), &report)?;
    }
    Ok(report)
}

#[derive(Debug, Clone, Default)]
struct LabCalibrationInputs {
    known_max_probability: Vec<f64>,
    known_margin: Vec<f64>,
    known_entropy: Vec<f64>,
    known_distance: Vec<f64>,
    ood_distance: Vec<f64>,
    known_runs: usize,
    uncertain_runs: usize,
    out_of_distribution_runs: usize,
    skipped_runs: usize,
    evaluated_runs: usize,
    per_label: BTreeMap<String, LabCalibrationLabelAccumulator>,
    expected_ood_runs: usize,
    expected_known_runs: usize,
    ood_false_positive_runs: usize,
    ood_false_negative_runs: usize,
    scenario_hotspots: BTreeMap<String, LabCalibrationHotspotAccumulator>,
    feature_distances: Vec<f64>,
    rule_threshold_samples: BTreeMap<String, Vec<f64>>,
    known_feature_values: BTreeMap<String, Vec<f64>>,
}

impl LabCalibrationInputs {
    fn collect(
        artifact_root: &Path,
        index: &LabRunIndex,
        source_identity: &CalibrationModelIdentity,
    ) -> Result<Self> {
        let mut inputs = Self::default();
        for entry in &index.runs {
            let (acceptance, ml, lab_run_dir) =
                inputs.load_run(artifact_root, entry, source_identity)?;
            inputs.add_comparison(artifact_root, entry, &acceptance)?;
            inputs.add_expected_behavior(entry, &lab_run_dir, &acceptance)?;
            if !acceptance.passed {
                inputs.skipped_runs += 1;
                continue;
            }
            inputs.add_accepted_status(&acceptance, &ml);
        }
        Ok(inputs)
    }

    fn load_run(
        &mut self,
        artifact_root: &Path,
        entry: &LabRunIndexEntry,
        source_identity: &CalibrationModelIdentity,
    ) -> Result<(LabAcceptanceReport, MlResult, std::path::PathBuf)> {
        let acceptance_path = resolve_stored_path(artifact_root, &entry.acceptance_path)?;
        let acceptance = read_required_stable_json_bounded::<LabAcceptanceReport>(
            &acceptance_path,
            MAX_LAB_ACCEPTANCE_BYTES,
            "lab acceptance report",
        )
        .map_err(|err| {
            NetdiagError::InvalidTrace(format!(
                "lab calibration could not read indexed acceptance artifact {}: {err}",
                acceptance_path.display()
            ))
        })?;
        validate_acceptance_identity(entry, &acceptance)?;
        source_identity.validate_acceptance(entry, &acceptance)?;
        self.evaluated_runs += 1;
        let lab_run_dir = resolve_stored_path(artifact_root, &entry.lab_run_dir)?;
        let ml_path = run_dir(&lab_run_dir, &entry.run_id)?.join("ml_result.json");
        let ml = read_required_stable_json_bounded::<MlResult>(
            &ml_path,
            MAX_ML_RESULT_BYTES,
            "ML result",
        )
        .map_err(|err| {
            NetdiagError::InvalidTrace(format!(
                "lab calibration could not read indexed ml_result.json {}: {err}",
                ml_path.display()
            ))
        })?;
        validate_ml_identity(entry, &acceptance, &ml, source_identity)?;
        if ml.uncertainty.feature_distance.is_finite() {
            self.feature_distances.push(ml.uncertainty.feature_distance);
        }
        Ok((acceptance, ml, lab_run_dir))
    }

    fn add_comparison(
        &mut self,
        artifact_root: &Path,
        entry: &LabRunIndexEntry,
        acceptance: &LabAcceptanceReport,
    ) -> Result<()> {
        let comparison_path = resolve_stored_path(artifact_root, &entry.comparison_path)?;
        let comparison = read_required_stable_json_bounded::<LabRunComparison>(
            &comparison_path,
            MAX_LAB_COMPARISON_BYTES,
            "lab run comparison",
        )
        .map_err(|err| {
            NetdiagError::InvalidTrace(format!(
                "lab calibration could not read indexed comparison artifact {}: {err}",
                comparison_path.display()
            ))
        })?;
        validate_comparison_identity(entry, acceptance, &comparison)?;
        if acceptance.expected_label.is_none() {
            return Ok(());
        }
        let hotspot = self
            .scenario_hotspots
            .entry(entry.scenario_id.clone())
            .or_insert_with(|| LabCalibrationHotspotAccumulator {
                scenario_name: entry.scenario_name.clone(),
                ..Default::default()
            });
        hotspot.runs += 1;
        if !comparison.rule_ml_agreement {
            hotspot.disagreements += 1;
        }
        Ok(())
    }

    fn add_expected_behavior(
        &mut self,
        entry: &LabRunIndexEntry,
        lab_run_dir: &Path,
        acceptance: &LabAcceptanceReport,
    ) -> Result<()> {
        if let Some(expected_label) = acceptance.expected_label {
            self.add_expected_known(entry, lab_run_dir, acceptance, expected_label)?;
        } else {
            self.expected_ood_runs += 1;
            if acceptance.actual_diagnosis_status == DiagnosisStatus::Known {
                self.ood_false_negative_runs += 1;
            }
        }
        Ok(())
    }

    fn add_expected_known(
        &mut self,
        entry: &LabRunIndexEntry,
        lab_run_dir: &Path,
        acceptance: &LabAcceptanceReport,
        expected_label: FaultLabel,
    ) -> Result<()> {
        self.expected_known_runs += 1;
        let label_key = expected_label.as_str().to_string();
        let stats = self.per_label.entry(label_key.clone()).or_default();
        stats.runs += 1;
        match acceptance.actual_diagnosis_status {
            DiagnosisStatus::Known => stats.known += 1,
            DiagnosisStatus::Uncertain => stats.uncertain += 1,
            DiagnosisStatus::OutOfDistribution => {
                stats.out_of_distribution += 1;
                self.ood_false_positive_runs += 1;
            }
        }
        if acceptance.passed && acceptance.actual_diagnosis_status == DiagnosisStatus::Known {
            stats.accepted_known_runs += 1;
        }
        if acceptance
            .actual_rule_labels
            .iter()
            .any(|label| label == expected_label.as_str())
        {
            stats.rule_correct += 1;
        }
        if acceptance.actual_ml_top == expected_label.as_str() {
            stats.ml_correct += 1;
        }
        self.add_rule_threshold_samples(
            entry,
            lab_run_dir,
            expected_label,
            label_key,
            acceptance.passed && acceptance.actual_diagnosis_status == DiagnosisStatus::Known,
        )?;
        Ok(())
    }

    fn add_rule_threshold_samples(
        &mut self,
        entry: &LabRunIndexEntry,
        lab_run_dir: &Path,
        expected_label: FaultLabel,
        label_key: String,
        require_events: bool,
    ) -> Result<()> {
        let events_path = run_dir(lab_run_dir, &entry.run_id)?.join("diagnosis_events.json");
        let Some(confidences) = read_rule_threshold_confidences(
            &events_path,
            require_events,
            &entry.run_id,
            expected_label,
        )?
        else {
            return Ok(());
        };
        self.rule_threshold_samples
            .entry(label_key)
            .or_default()
            .extend(confidences);
        Ok(())
    }

    fn add_accepted_status(&mut self, acceptance: &LabAcceptanceReport, ml: &MlResult) {
        match acceptance.actual_diagnosis_status {
            DiagnosisStatus::Known => self.add_accepted_known(ml),
            DiagnosisStatus::Uncertain => {
                self.uncertain_runs += 1;
                if acceptance.expected_label.is_none() {
                    self.out_of_distribution_runs += 1;
                    self.ood_distance.push(ml.uncertainty.feature_distance);
                }
            }
            DiagnosisStatus::OutOfDistribution => {
                self.out_of_distribution_runs += 1;
                self.ood_distance.push(ml.uncertainty.feature_distance);
            }
        }
    }

    fn add_accepted_known(&mut self, ml: &MlResult) {
        self.known_runs += 1;
        self.known_max_probability
            .push(ml.uncertainty.max_probability);
        self.known_margin.push(ml.uncertainty.probability_margin);
        self.known_entropy.push(ml.uncertainty.entropy);
        self.known_distance.push(ml.uncertainty.feature_distance);
        for (name, value) in &ml.features {
            if value.is_finite() {
                self.known_feature_values
                    .entry(name.clone())
                    .or_default()
                    .push(*value);
            }
        }
    }

    fn ensure_known_runs(&self) -> Result<()> {
        if self.known_runs == 0 {
            Err(NetdiagError::InvalidTrace(
                "lab calibration requires at least one accepted known-status lab run".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn has_lab_grade_coverage(&self) -> bool {
        self.accepted_known_label_count() == FaultLabel::ALL.len()
            && self.out_of_distribution_runs > 0
            && self.expected_ood_runs > 0
    }

    fn accepted_known_label_count(&self) -> usize {
        FaultLabel::ALL
            .iter()
            .filter(|label| {
                self.per_label
                    .get(label.as_str())
                    .is_some_and(|stats| stats.accepted_known_runs > 0)
            })
            .count()
    }

    fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.out_of_distribution_runs == 0 {
            warnings.push(
                "no accepted out_of_distribution lab runs; feature-distance threshold uses known-run envelope only"
                    .to_string(),
            );
        }
        let covered_labels = self.accepted_known_label_count();
        if self.known_runs < FaultLabel::ALL.len() {
            warnings.push(format!(
                "only {} accepted known-status runs; calibrate with at least one accepted run per known label before treating thresholds as lab-grade",
                self.known_runs
            ));
        }
        if !self.has_lab_grade_coverage() {
            warnings.push(format!(
                "calibration coverage is not lab-grade ({covered_labels}/{} labels, {} accepted OOD runs); thresholds are reported but model_manifest.json was not updated",
                FaultLabel::ALL.len(),
                self.out_of_distribution_runs
            ));
        }
        warnings
    }

    fn per_label_stats(&self) -> BTreeMap<String, LabCalibrationLabelStats> {
        self.per_label
            .clone()
            .into_iter()
            .map(|(label, stats)| (label, stats.into_stats()))
            .collect()
    }

    fn hotspots(&self) -> Vec<LabCalibrationHotspot> {
        self.scenario_hotspots
            .clone()
            .into_iter()
            .filter_map(|(scenario_id, stats)| {
                (stats.disagreements > 0).then(|| stats.into_hotspot(scenario_id))
            })
            .collect()
    }

    fn suggested_rule_thresholds(&self) -> BTreeMap<String, f64> {
        self.rule_threshold_samples
            .iter()
            .filter(|(_, samples)| !samples.is_empty())
            .map(|(label, samples)| {
                (
                    label.clone(),
                    round4(quantile(samples, 0.05).clamp(0.50, 0.95)),
                )
            })
            .collect()
    }

    fn ood_stats(&self) -> LabCalibrationOodStats {
        LabCalibrationOodStats {
            expected_ood_runs: self.expected_ood_runs,
            expected_known_runs: self.expected_known_runs,
            false_positive_runs: self.ood_false_positive_runs,
            false_negative_runs: self.ood_false_negative_runs,
            false_positive_rate: round4(
                self.ood_false_positive_runs as f64 / self.expected_known_runs.max(1) as f64,
            ),
            false_negative_rate: round4(
                self.ood_false_negative_runs as f64 / self.expected_ood_runs.max(1) as f64,
            ),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct LabCalibrationLabelAccumulator {
    runs: usize,
    accepted_known_runs: usize,
    rule_correct: usize,
    ml_correct: usize,
    known: usize,
    uncertain: usize,
    out_of_distribution: usize,
}

impl LabCalibrationLabelAccumulator {
    fn into_stats(self) -> LabCalibrationLabelStats {
        let denominator = self.runs.max(1) as f64;
        LabCalibrationLabelStats {
            runs: self.runs,
            accepted_known_runs: self.accepted_known_runs,
            rule_correct: self.rule_correct,
            ml_correct: self.ml_correct,
            rule_accuracy: round4(self.rule_correct as f64 / denominator),
            ml_accuracy: round4(self.ml_correct as f64 / denominator),
            known_rate: round4(self.known as f64 / denominator),
            uncertain_rate: round4(self.uncertain as f64 / denominator),
            out_of_distribution_rate: round4(self.out_of_distribution as f64 / denominator),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct LabCalibrationHotspotAccumulator {
    scenario_name: String,
    runs: usize,
    disagreements: usize,
}

impl LabCalibrationHotspotAccumulator {
    fn into_hotspot(self, scenario_id: String) -> LabCalibrationHotspot {
        let denominator = self.runs.max(1) as f64;
        LabCalibrationHotspot {
            scenario_id,
            scenario_name: self.scenario_name,
            disagreements: self.disagreements,
            runs: self.runs,
            rate: round4(self.disagreements as f64 / denominator),
        }
    }
}
