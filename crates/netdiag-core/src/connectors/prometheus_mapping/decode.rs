use super::unique_object::parse_unique_string_map;
use crate::error::{NetdiagError, Result};
use std::collections::BTreeMap;
use std::path::Path;

pub(super) fn decode_mapping(bytes: &[u8], path: &Path) -> Result<BTreeMap<String, String>> {
    let input = std::str::from_utf8(bytes).map_err(|error| {
        NetdiagError::InvalidTrace(format!(
            "mapping file is not valid UTF-8 at {} near byte {}",
            path.display(),
            error.valid_up_to()
        ))
    })?;
    parse_unique_string_map(input).map_err(|error| mapping_json_error(path, error))
}

fn mapping_json_error(path: &Path, error: serde_json::Error) -> NetdiagError {
    let message = error.to_string();
    let reason = if message.contains("mapping object contains a duplicate canonical field") {
        "contains a duplicate canonical field"
    } else if error.is_syntax() || error.is_eof() {
        "is not valid JSON"
    } else {
        "does not match the required string-map JSON schema"
    };
    NetdiagError::InvalidTrace(format!(
        "mapping file {reason} at {} line {}, column {}",
        path.display(),
        error.line(),
        error.column()
    ))
}
