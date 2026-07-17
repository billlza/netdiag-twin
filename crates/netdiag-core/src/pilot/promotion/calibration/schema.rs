use super::super::{ModelPromotionGate, gate};
use crate::lab::LabCalibrationReport;

const CALIBRATION_SCHEMA: &str = "netdiag-lab-calibration/v2";

pub(super) fn calibration_schema_gate(report: &LabCalibrationReport) -> ModelPromotionGate {
    let source_hash_valid = report.source_model_manifest_hash_sha256.len() == 64
        && report
            .source_model_manifest_hash_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    let passed = report.schema == CALIBRATION_SCHEMA && source_hash_valid;
    gate(
        "calibration_schema",
        passed,
        if passed {
            "calibration schema and source model identity are supported".to_string()
        } else {
            format!(
                "unsupported calibration schema or source model identity {}; expected {CALIBRATION_SCHEMA} with a lowercase SHA-256 source hash",
                report.schema
            )
        },
    )
}
