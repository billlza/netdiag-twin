use crate::error::NetdiagError;
use std::path::Path;

pub(super) fn invalid_json(path: &Path, required: bool, source: serde_json::Error) -> NetdiagError {
    read_error(
        path,
        required,
        NetdiagError::InvalidTrace(format!(
            "invalid diagnosis event JSON: {}",
            crate::strict_json::error_summary(&source)
        )),
    )
}

pub(super) fn read_error(path: &Path, required: bool, error: NetdiagError) -> NetdiagError {
    let role = if required {
        "accepted known"
    } else {
        "optional"
    };
    NetdiagError::InvalidTrace(format!(
        "lab calibration could not read {role} diagnosis_events.json {}: {error}",
        path.display()
    ))
}
