use super::*;

pub(super) struct CalibrationReportContext<'a> {
    pub(super) artifact_root: &'a Path,
    pub(super) model_manifest_path: &'a Path,
    pub(super) source_identity: &'a CalibrationModelIdentity,
    pub(super) current_manifest_hash_sha256: String,
    pub(super) previous_thresholds: Option<ModelUncertaintyThresholds>,
    pub(super) calibrated_thresholds: ModelUncertaintyThresholds,
    pub(super) applied: bool,
}

pub(super) fn build_report(
    context: CalibrationReportContext<'_>,
    inputs: LabCalibrationInputs,
) -> LabCalibrationReport {
    LabCalibrationReport {
        schema: "netdiag-lab-calibration/v2".to_string(),
        generated_at: Utc::now(),
        artifact_root: context.artifact_root.display().to_string(),
        model_manifest_path: context.model_manifest_path.display().to_string(),
        source_model_manifest_hash_sha256: context
            .source_identity
            .source_manifest_hash_sha256
            .clone(),
        model_manifest_hash_sha256: Some(context.current_manifest_hash_sha256),
        model_file_hash_sha256: Some(context.source_identity.model_file_hash_sha256.clone()),
        dataset_hash_sha256: Some(context.source_identity.dataset_hash_sha256.clone()),
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
    }
}
