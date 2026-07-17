use super::{ResolvedInterpreter, joined_runtime_path};
use crate::error::{NetdiagError, Result};
use crate::storage::{PathStatus, path_status};
use std::path::Path;

const MAX_CONFIGURED_INTERPRETER_PATH_BYTES: usize = 4 * 1024;

pub(super) fn resolve_configured_interpreter(value: &str) -> Result<ResolvedInterpreter> {
    if value.trim().is_empty() || value.len() > MAX_CONFIGURED_INTERPRETER_PATH_BYTES {
        return Err(NetdiagError::Connector(format!(
            "configured Python interpreter path must contain 1..={MAX_CONFIGURED_INTERPRETER_PATH_BYTES} bytes"
        )));
    }
    let requested = Path::new(value);
    if !requested.is_absolute() {
        return Err(NetdiagError::Connector(
            "configured Python interpreter must be an absolute path".to_string(),
        ));
    }
    let canonical = requested.canonicalize().map_err(|error| {
        NetdiagError::Connector(format!(
            "failed to canonicalize configured Python interpreter {}: {error}",
            requested.display()
        ))
    })?;
    let parent = canonical.parent().ok_or_else(|| {
        NetdiagError::Connector(format!(
            "configured Python interpreter has no parent directory: {}",
            canonical.display()
        ))
    })?;
    validate_interpreter(&canonical)?;
    let runtime_entry = parent.to_path_buf();
    Ok(ResolvedInterpreter {
        path: canonical,
        runtime_path: joined_runtime_path(std::iter::once(&runtime_entry))?,
    })
}

pub(super) fn validate_interpreter(path: &Path) -> Result<()> {
    if !path.is_absolute() || path_status(path)? != PathStatus::RegularFile {
        return Err(NetdiagError::Connector(format!(
            "Python interpreter must be an absolute regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    return super::path_entries::validate_trusted_interpreter(path);
    #[cfg(not(unix))]
    Err(NetdiagError::Connector(
        "Python adapter execution is disabled on this platform because interpreter and ancestor ACL trust cannot yet be proven"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests;
