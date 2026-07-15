use super::super::{PilotManifest, validate_pilot_manifest};
use crate::error::{NetdiagError, Result};
use crate::storage::read_stable_regular_file_bounded;
use std::path::Path;

const MAX_PILOT_MANIFEST_BYTES: u64 = 1024 * 1024;

pub(in crate::pilot) fn read_manifest(path: &Path) -> Result<PilotManifest> {
    let bytes =
        read_stable_regular_file_bounded(path, MAX_PILOT_MANIFEST_BYTES)?.ok_or_else(|| {
            NetdiagError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "pilot manifest is missing",
                ),
            }
        })?;
    let manifest: PilotManifest = serde_yaml::from_slice(&bytes)
        .map_err(|err| NetdiagError::InvalidTrace(format!("invalid pilot YAML: {err}")))?;
    validate_pilot_manifest(&manifest)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests;
