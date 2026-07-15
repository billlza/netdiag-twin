use super::LabVerification;
use crate::error::{NetdiagError, Result};
use crate::storage::read_stable_regular_file_bounded;
use std::path::Path;

const MAX_VERIFICATION_OBJECTIVE_BYTES: u64 = 256 * 1024;

pub(super) fn read(path: &Path) -> Result<LabVerification> {
    let bytes = read_stable_regular_file_bounded(path, MAX_VERIFICATION_OBJECTIVE_BYTES)?
        .ok_or_else(|| NetdiagError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "verification objective file is missing",
            ),
        })?;
    let input = std::str::from_utf8(&bytes).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "verification objective is not valid UTF-8 at {}: {source}",
            path.display()
        ))
    })?;
    let value: serde_yaml::Value = serde_yaml::from_str(input).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "invalid objective YAML at {}: {source}",
            path.display()
        ))
    })?;
    if let Ok(policy) = serde_yaml::from_value::<LabVerification>(value.clone())
        && !policy.is_empty()
    {
        return Ok(policy);
    }
    if let Some(verification) = value.get("verification") {
        let policy: LabVerification =
            serde_yaml::from_value(verification.clone()).map_err(|source| {
                NetdiagError::InvalidTrace(format!(
                    "invalid verification YAML at {}: {source}",
                    path.display()
                ))
            })?;
        if !policy.is_empty() {
            return Ok(policy);
        }
    }
    Err(NetdiagError::InvalidTrace(format!(
        "verification objective {} must contain objective and/or fail_if",
        path.display()
    )))
}

#[cfg(test)]
mod tests;
