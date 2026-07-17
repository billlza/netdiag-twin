use crate::error::{NetdiagError, Result};
use crate::models::{DiagnosisEvent, FaultLabel};
use std::path::Path;

pub(super) fn validate_rule_events(
    path: &Path,
    events: &[DiagnosisEvent],
    required: bool,
    expected_run_id: &str,
    expected_label: FaultLabel,
) -> Result<()> {
    if required && events.is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab calibration accepted known diagnosis_events.json {} is empty",
            path.display()
        )));
    }
    if events
        .iter()
        .any(|event| event.evidence.run_id != expected_run_id)
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab calibration diagnosis_events.json {} contains a mismatched run id",
            path.display()
        )));
    }
    if required
        && !events
            .iter()
            .any(|event| event.evidence.symptom == expected_label)
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab calibration accepted known diagnosis_events.json {} does not contain expected label {}",
            path.display(),
            expected_label.as_str()
        )));
    }
    Ok(())
}
