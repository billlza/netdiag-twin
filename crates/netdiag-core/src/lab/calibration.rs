use super::{
    LabAcceptanceReport, LabRunComparison, LabRunIndex, LabRunIndexEntry, read_lab_run_index,
    round4,
};
use crate::error::{NetdiagError, Result};
use crate::ml::{MODEL_FILE_NAME, MODEL_MANIFEST_FILE_NAME, load_existing_model, sha256_file};
use crate::models::{
    DiagnosisEvent, DiagnosisStatus, FaultLabel, FeatureBounds, MlResult, ModelManifest,
    ModelUncertaintyThresholds,
};
use crate::storage::{read_json, resolve_stored_path, run_dir, save_json, save_json_atomic};
use crate::telemetry::quantile;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabCalibrationReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub artifact_root: String,
    pub model_manifest_path: String,
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
    let model_dir = artifact_root.join("model");
    load_existing_model(&model_dir)?;
    let model_manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
    let mut manifest: ModelManifest =
        serde_json::from_value(read_json(&model_manifest_path)?).map_err(NetdiagError::from)?;
    let dataset_hash_sha256 = manifest.dataset_hash_sha256.clone();
    let previous_thresholds = manifest.uncertainty_thresholds.clone();
    let index = require_lab_run_index(artifact_root)?;
    let inputs = LabCalibrationInputs::collect(artifact_root, &index);
    inputs.ensure_known_runs()?;

    let previous = previous_thresholds.clone().unwrap_or_default();
    let calibrated_thresholds = calibrated_thresholds(&inputs, &previous);
    let applied = !dry_run && inputs.has_lab_grade_coverage();
    if applied {
        manifest.uncertainty_thresholds = Some(calibrated_thresholds.clone());
        save_json(&model_manifest_path, &manifest)?;
    }

    let report = build_report(
        CalibrationReportContext {
            artifact_root,
            model_dir: &model_dir,
            model_manifest_path: &model_manifest_path,
            dataset_hash_sha256,
            previous_thresholds,
            calibrated_thresholds,
            applied,
        },
        inputs,
    )?;
    if !dry_run {
        save_json_atomic(artifact_root.join("lab_calibration_report.json"), &report)?;
    }
    Ok(report)
}

struct CalibrationReportContext<'a> {
    artifact_root: &'a Path,
    model_dir: &'a Path,
    model_manifest_path: &'a Path,
    dataset_hash_sha256: Option<String>,
    previous_thresholds: Option<ModelUncertaintyThresholds>,
    calibrated_thresholds: ModelUncertaintyThresholds,
    applied: bool,
}

fn require_lab_run_index(artifact_root: &Path) -> Result<LabRunIndex> {
    read_lab_run_index(artifact_root)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "lab calibration requires {}, but no lab run index exists under {}",
            artifact_root.join("lab_run_index.json").display(),
            artifact_root.display()
        ))
    })
}

fn calibrated_thresholds(
    inputs: &LabCalibrationInputs,
    previous: &ModelUncertaintyThresholds,
) -> ModelUncertaintyThresholds {
    let known_distance_p95 = quantile(&inputs.known_distance, 0.95);
    ModelUncertaintyThresholds {
        min_max_probability: round4(
            quantile(&inputs.known_max_probability, 0.05).clamp(0.05, 0.99),
        ),
        min_probability_margin: round4(quantile(&inputs.known_margin, 0.05).clamp(0.0, 0.80)),
        max_entropy: round4(quantile(&inputs.known_entropy, 0.95).clamp(0.05, 1.0)),
        max_feature_distance: round4(max_feature_distance(inputs, known_distance_p95)),
        feature_bounds: calibrated_feature_bounds(&inputs.known_feature_values, previous),
    }
}

fn max_feature_distance(inputs: &LabCalibrationInputs, known_distance_p95: f64) -> f64 {
    let from_ood = inputs
        .ood_distance
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .min_by(f64::total_cmp)
        .filter(|distance| *distance > known_distance_p95)
        .map(|min_ood_distance| (known_distance_p95 + min_ood_distance) / 2.0);
    from_ood.unwrap_or(known_distance_p95 * 1.25).max(1.0)
}

fn build_report(
    context: CalibrationReportContext<'_>,
    inputs: LabCalibrationInputs,
) -> Result<LabCalibrationReport> {
    Ok(LabCalibrationReport {
        schema: "netdiag-lab-calibration/v1".to_string(),
        generated_at: Utc::now(),
        artifact_root: context.artifact_root.display().to_string(),
        model_manifest_path: context.model_manifest_path.display().to_string(),
        model_manifest_hash_sha256: Some(sha256_file(context.model_manifest_path)?),
        model_file_hash_sha256: Some(sha256_file(&context.model_dir.join(MODEL_FILE_NAME))?),
        dataset_hash_sha256: context.dataset_hash_sha256,
        evaluated_runs: inputs.evaluated_runs,
        known_runs: inputs.known_runs,
        uncertain_runs: inputs.uncertain_runs,
        out_of_distribution_runs: inputs.out_of_distribution_runs,
        skipped_runs: inputs.skipped_runs,
        per_label: inputs.per_label_stats(),
        ood: inputs.ood_stats(),
        rule_ml_disagreement_hotspots: inputs.hotspots(),
        feature_distance_distribution: calibration_distribution(&inputs.feature_distances),
        suggested_rule_thresholds: inputs.suggested_rule_thresholds(),
        applied: context.applied,
        previous_thresholds: context.previous_thresholds,
        calibrated_thresholds: context.calibrated_thresholds,
        warnings: inputs.warnings(),
    })
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
    fn collect(artifact_root: &Path, index: &LabRunIndex) -> Self {
        let mut inputs = Self::default();
        for entry in &index.runs {
            let Some((acceptance, ml, lab_run_dir)) = inputs.load_run(artifact_root, entry) else {
                continue;
            };
            inputs.add_comparison(artifact_root, entry);
            inputs.add_expected_behavior(entry, &lab_run_dir, &acceptance);
            if !acceptance.passed {
                inputs.skipped_runs += 1;
                continue;
            }
            inputs.add_accepted_status(&acceptance, &ml);
        }
        inputs
    }

    fn load_run(
        &mut self,
        artifact_root: &Path,
        entry: &LabRunIndexEntry,
    ) -> Option<(LabAcceptanceReport, MlResult, std::path::PathBuf)> {
        let acceptance_path = resolve_stored_path(artifact_root, &entry.acceptance_path);
        let acceptance = match read_json(&acceptance_path).and_then(|value| {
            serde_json::from_value::<LabAcceptanceReport>(value).map_err(Into::into)
        }) {
            Ok(acceptance) => acceptance,
            Err(_) => {
                self.skipped_runs += 1;
                return None;
            }
        };
        self.evaluated_runs += 1;
        let lab_run_dir = resolve_stored_path(artifact_root, &entry.lab_run_dir);
        let ml_path = run_dir(&lab_run_dir, &entry.run_id).join("ml_result.json");
        let ml = match read_json(&ml_path)
            .and_then(|value| serde_json::from_value::<MlResult>(value).map_err(Into::into))
        {
            Ok(ml) => ml,
            Err(_) => {
                self.skipped_runs += 1;
                return None;
            }
        };
        if ml.uncertainty.feature_distance.is_finite() {
            self.feature_distances.push(ml.uncertainty.feature_distance);
        }
        Some((acceptance, ml, lab_run_dir))
    }

    fn add_comparison(&mut self, artifact_root: &Path, entry: &LabRunIndexEntry) {
        let comparison_path = resolve_stored_path(artifact_root, &entry.comparison_path);
        let Ok(comparison) = read_json(&comparison_path).and_then(|value| {
            serde_json::from_value::<LabRunComparison>(value).map_err(Into::into)
        }) else {
            return;
        };
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
    }

    fn add_expected_behavior(
        &mut self,
        entry: &LabRunIndexEntry,
        lab_run_dir: &Path,
        acceptance: &LabAcceptanceReport,
    ) {
        if let Some(expected_label) = acceptance.expected_label {
            self.add_expected_known(entry, lab_run_dir, acceptance, expected_label);
        } else {
            self.expected_ood_runs += 1;
            if acceptance.actual_diagnosis_status == DiagnosisStatus::Known {
                self.ood_false_negative_runs += 1;
            }
        }
    }

    fn add_expected_known(
        &mut self,
        entry: &LabRunIndexEntry,
        lab_run_dir: &Path,
        acceptance: &LabAcceptanceReport,
        expected_label: FaultLabel,
    ) {
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
        self.add_rule_threshold_samples(entry, lab_run_dir, expected_label, label_key);
    }

    fn add_rule_threshold_samples(
        &mut self,
        entry: &LabRunIndexEntry,
        lab_run_dir: &Path,
        expected_label: FaultLabel,
        label_key: String,
    ) {
        let events_path = run_dir(lab_run_dir, &entry.run_id).join("diagnosis_events.json");
        let Ok(events) = read_json(&events_path).and_then(|value| {
            serde_json::from_value::<Vec<DiagnosisEvent>>(value).map_err(Into::into)
        }) else {
            return;
        };
        self.rule_threshold_samples
            .entry(label_key)
            .or_default()
            .extend(
                events
                    .iter()
                    .filter(|event| event.evidence.symptom == expected_label)
                    .map(|event| event.evidence.confidence)
                    .filter(|value| value.is_finite()),
            );
    }

    fn add_accepted_status(&mut self, acceptance: &LabAcceptanceReport, ml: &MlResult) {
        match acceptance.actual_diagnosis_status {
            DiagnosisStatus::Known => self.add_accepted_known(ml),
            DiagnosisStatus::Uncertain => self.uncertain_runs += 1,
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

fn calibration_distribution(values: &[f64]) -> LabCalibrationDistribution {
    let finite = values
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .collect::<Vec<_>>();
    LabCalibrationDistribution {
        count: finite.len(),
        p50: round4(quantile(&finite, 0.50)),
        p95: round4(quantile(&finite, 0.95)),
        max: round4(finite.into_iter().fold(0.0, f64::max)),
    }
}

fn calibrated_feature_bounds(
    values: &BTreeMap<String, Vec<f64>>,
    previous: &ModelUncertaintyThresholds,
) -> BTreeMap<String, FeatureBounds> {
    let mut bounds = previous.feature_bounds.clone();
    for (name, samples) in values {
        let finite = samples
            .iter()
            .copied()
            .filter(|value| value.is_finite())
            .collect::<Vec<_>>();
        if finite.len() < 2 {
            continue;
        }
        let min = finite.iter().copied().fold(f64::INFINITY, f64::min);
        let max = finite.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let span = (max - min)
            .abs()
            .max(max.abs().max(min.abs()) * 0.05)
            .max(1e-6);
        bounds.insert(
            name.clone(),
            FeatureBounds {
                min: round4(min - span * 0.10),
                max: round4(max + span * 0.10),
            },
        );
    }
    bounds
}
