use super::{LabAcceptanceReport, LabRunComparison, LabRunIndexEntry};
use crate::error::{NetdiagError, Result};

pub(in crate::lab) fn validate_acceptance_identity(
    entry: &LabRunIndexEntry,
    acceptance: &LabAcceptanceReport,
) -> Result<()> {
    require_equal(
        "acceptance schema",
        &acceptance.schema,
        "netdiag-lab-acceptance/v1",
    )?;
    require_equal("acceptance run id", &acceptance.run_id, &entry.run_id)?;
    require_equal(
        "acceptance scenario id",
        &acceptance.scenario_id,
        &entry.scenario_id,
    )?;
    if acceptance.passed != entry.passed {
        return Err(identity_error(
            entry,
            "acceptance passed flag does not match the lab index",
        ));
    }
    Ok(())
}

pub(in crate::lab) fn validate_comparison_identity(
    entry: &LabRunIndexEntry,
    acceptance: &LabAcceptanceReport,
    comparison: &LabRunComparison,
) -> Result<()> {
    require_equal(
        "comparison schema",
        &comparison.schema,
        "netdiag-lab-comparison/v1",
    )?;
    require_equal("comparison run id", &comparison.run_id, &entry.run_id)?;
    require_equal(
        "comparison scenario id",
        &comparison.scenario_id,
        &entry.scenario_id,
    )?;
    if comparison.expected_label != acceptance.expected_label
        || comparison.actual_rule_labels != acceptance.actual_rule_labels
        || comparison.actual_ml_top != acceptance.actual_ml_top
        || comparison.diagnosis_status != acceptance.actual_diagnosis_status
        || comparison.quality_status != acceptance.quality_status
    {
        return Err(identity_error(
            entry,
            "comparison diagnosis fields do not match acceptance",
        ));
    }
    Ok(())
}

pub(in crate::lab) fn require_equal(name: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "lab evidence {name} mismatch: actual={actual} expected={expected}"
        )))
    }
}

pub(in crate::lab) fn identity_error(entry: &LabRunIndexEntry, message: &str) -> NetdiagError {
    NetdiagError::InvalidTrace(format!("lab indexed run {} {message}", entry.run_id))
}
