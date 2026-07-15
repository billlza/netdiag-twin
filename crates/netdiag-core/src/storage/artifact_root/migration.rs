use super::ownership::OWNERSHIP_FILE_NAME;
use crate::error::{IoContext, NetdiagError, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const LEGACY_DIRECTORIES: [&str; 5] = ["datasets", "lab-runs", "model", "pilot-runs", "runs"];
const LEGACY_FILES: [&str; 3] = [
    "lab_calibration_report.json",
    "lab_run_index.json",
    "run_index.json",
];

pub(super) fn validate_layout(
    directory: &netdiag_platform::TrustedDirectory,
    marker_allowed: bool,
) -> Result<()> {
    directory
        .validate_identity()
        .map_err(|source| NetdiagError::FilesystemTrust {
            context: "legacy artifact root migration",
            source,
        })?;
    validate_top_level(directory.resolved_path(), marker_allowed)?;
    directory
        .validate_identity()
        .map_err(|source| NetdiagError::FilesystemTrust {
            context: "legacy artifact root migration",
            source,
        })
}

fn validate_top_level(root: &Path, marker_allowed: bool) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root).with_path(root)? {
        let entry = entry.with_path(root)?;
        let name = entry.file_name().into_string().map_err(|_| {
            NetdiagError::InvalidTrace(format!(
                "legacy artifact root contains a non-UTF-8 entry: {}",
                entry.path().display()
            ))
        })?;
        if marker_allowed && name == OWNERSHIP_FILE_NAME {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path()).with_path(entry.path())?;
        if metadata.file_type().is_symlink()
            || netdiag_platform::metadata_is_reparse_point(&metadata)
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "legacy artifact root entry is a link or reparse point: {}",
                entry.path().display()
            )));
        }
        let valid = if LEGACY_DIRECTORIES.contains(&name.as_str()) {
            metadata.is_dir()
        } else if LEGACY_FILES.contains(&name.as_str()) {
            metadata.is_file()
        } else {
            false
        };
        if !valid {
            return Err(NetdiagError::InvalidTrace(format!(
                "legacy artifact root contains an unsupported entry: {}",
                entry.path().display()
            )));
        }
        names.insert(name);
    }
    Ok(names)
}
