use super::MAX_TRANSACTION_JSON_BYTES;
use crate::error::{NetdiagError, Result};
use crate::models::HilFeedbackRecord;
use crate::storage::read_stable_regular_file_bounded;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) fn read_optional_hil_feedback(
    path: &Path,
    expected_run_id: &str,
) -> Result<Option<BTreeMap<String, HilFeedbackRecord>>> {
    let Some(bytes) = read_stable_regular_file_bounded(path, MAX_TRANSACTION_JSON_BYTES)? else {
        return Ok(None);
    };
    let value = crate::strict_json::parse_unique_value(&bytes).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "invalid HIL feedback JSON at {}: {}",
            path.display(),
            crate::strict_json::error_summary(&source)
        ))
    })?;
    let feedback = serde_json::from_value::<BTreeMap<String, HilFeedbackRecord>>(value.clone())
        .map_err(|error| invalid_feedback_schema(path, &value, error))?;
    validate_feedback_records(path, expected_run_id, &feedback)?;
    Ok(Some(feedback))
}

fn validate_feedback_records(
    path: &Path,
    expected_run_id: &str,
    feedback: &BTreeMap<String, HilFeedbackRecord>,
) -> Result<()> {
    for (key, record) in feedback {
        if key != &record.recommendation_id {
            return Err(NetdiagError::InvalidTrace(format!(
                "HIL feedback key {key:?} does not match recommendation id {:?} in {}",
                record.recommendation_id,
                path.display()
            )));
        }
        if record.run_id != expected_run_id {
            return Err(NetdiagError::InvalidTrace(format!(
                "HIL feedback run id {} does not match {expected_run_id} in {}",
                record.run_id,
                path.display()
            )));
        }
    }
    Ok(())
}

fn invalid_feedback_schema(path: &Path, value: &Value, source: serde_json::Error) -> NetdiagError {
    if contains_legacy_feedback(value) {
        return NetdiagError::InvalidTrace(format!(
            "legacy HIL feedback schema at {} cannot be migrated safely because reviewer and review timestamp are missing; archive and remove the legacy file, then use review_recommendation",
            path.display()
        ));
    }
    NetdiagError::InvalidTrace(format!(
        "invalid HIL feedback schema at {}: {}",
        path.display(),
        crate::strict_json::error_summary(&source)
    ))
}

fn contains_legacy_feedback(value: &Value) -> bool {
    value.as_object().is_some_and(|feedback| {
        feedback.values().any(|record| {
            record.get("state").is_some()
                && record.get("notes").is_some()
                && record.get("review").is_none()
        })
    })
}
