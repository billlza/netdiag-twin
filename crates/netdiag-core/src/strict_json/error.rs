use super::validation::DUPLICATE_KEY_ERROR;

/// Describes a JSON error without echoing input keys or values.
pub fn error_summary(error: &serde_json::Error) -> String {
    let reason = if error.to_string().starts_with(DUPLICATE_KEY_ERROR) {
        "contains a duplicate key"
    } else if error.is_syntax() || error.is_eof() {
        "is not syntactically valid JSON"
    } else {
        "does not match the required JSON schema"
    };
    format!(
        "{reason} at line {}, column {}",
        error.line(),
        error.column()
    )
}
