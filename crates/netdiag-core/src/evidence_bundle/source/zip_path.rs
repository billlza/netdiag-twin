use crate::error::{NetdiagError, Result};

pub(in crate::evidence_bundle) fn normalize_zip_path(raw: &str) -> Result<String> {
    if raw.is_empty() || raw.ends_with(['/', '\\']) || raw.chars().any(char::is_control) {
        return invalid_zip_path(raw);
    }
    let portable = raw.replace('\\', "/");
    if portable.starts_with('/') || has_windows_drive_prefix(&portable) {
        return invalid_zip_path(raw);
    }
    let mut components = Vec::new();
    for component in portable.split('/') {
        match component {
            "" | "." => {}
            ".." => return invalid_zip_path(raw),
            value if value.contains('\0') => return invalid_zip_path(raw),
            value => components.push(value),
        }
    }
    if components.is_empty() || portable.ends_with("/.") {
        return invalid_zip_path(raw);
    }
    Ok(components.join("/"))
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn invalid_zip_path<T>(raw: &str) -> Result<T> {
    Err(NetdiagError::InvalidTrace(format!(
        "evidence bundle zip path must name a normalized relative file: {raw:?}"
    )))
}
