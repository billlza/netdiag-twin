use crate::error::{NetdiagError, Result};
use std::path::Path;

pub(super) fn parse_unique_row(
    path: &Path,
    line_number: usize,
    line: &str,
) -> Result<serde_json::Value> {
    crate::strict_json::parse_unique_value(line.as_bytes()).map_err(|error| {
        NetdiagError::Ml(format!(
            "{} line {line_number} is not valid JSON: {}",
            path.display(),
            crate::strict_json::error_summary(&error)
        ))
    })
}
