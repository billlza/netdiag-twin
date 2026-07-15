use super::model_identity::CalibrationModelIdentity;
use crate::error::Result;
use crate::lab::evidence_identity::{identity_error, require_equal};
pub(super) use crate::lab::evidence_identity::{
    validate_acceptance_identity, validate_comparison_identity,
};
use crate::lab::{LabAcceptanceReport, LabRunIndexEntry};
use crate::models::MlResult;

pub(super) fn validate_ml_identity(
    entry: &LabRunIndexEntry,
    acceptance: &LabAcceptanceReport,
    ml: &MlResult,
    source: &CalibrationModelIdentity,
) -> Result<()> {
    require_equal("ML run id", &ml.run_id, &entry.run_id)?;
    require_optional_hash(
        entry,
        "ML model manifest hash",
        ml.model_manifest_hash.as_deref(),
        &source.source_manifest_hash_sha256,
    )?;
    require_optional_hash(
        entry,
        "ML model file hash",
        ml.model_file_hash.as_deref(),
        &source.model_file_hash_sha256,
    )?;
    let top = ml
        .top_predictions
        .first()
        .ok_or_else(|| identity_error(entry, "ML result has no top prediction"))?;
    require_equal(
        "ML top label",
        top.label.as_str(),
        &acceptance.actual_ml_top,
    )?;
    if !top.prob.is_finite() || (top.prob - acceptance.actual_ml_probability).abs() > f64::EPSILON {
        return Err(identity_error(
            entry,
            "ML top probability does not match acceptance",
        ));
    }
    Ok(())
}

fn require_optional_hash(
    entry: &LabRunIndexEntry,
    name: &str,
    actual: Option<&str>,
    expected: &str,
) -> Result<()> {
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => Err(identity_error(entry, &format!("{name} mismatch"))),
        None => Err(identity_error(entry, &format!("{name} is missing"))),
    }
}
