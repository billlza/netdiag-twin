use crate::error::Result;
use crate::models::FaultLabel;
use std::path::Path;

mod read;
#[cfg(test)]
use read::MAX_DIAGNOSIS_EVENTS_BYTES;
use read::read_rule_events;
mod validation;
use validation::validate_rule_events;

pub(super) fn read_rule_threshold_confidences(
    events_path: &Path,
    require_events: bool,
    expected_run_id: &str,
    expected_label: FaultLabel,
) -> Result<Option<Vec<f64>>> {
    let Some(events) = read_rule_events(events_path, require_events)? else {
        return Ok(None);
    };
    validate_rule_events(
        events_path,
        &events,
        require_events,
        expected_run_id,
        expected_label,
    )?;
    Ok(Some(
        events
            .into_iter()
            .filter(|event| event.evidence.symptom == expected_label)
            .map(|event| event.evidence.confidence)
            .filter(|value| value.is_finite())
            .collect(),
    ))
}

#[cfg(test)]
mod tests;
