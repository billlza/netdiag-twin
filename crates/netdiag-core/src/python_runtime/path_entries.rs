use super::record_rejection;
use crate::error::{NetdiagError, Result};
use std::collections::BTreeSet;
use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

mod trust;
use trust::validate_trusted_directory_chain;
pub(super) use trust::validate_trusted_interpreter;

const MAX_PATH_BYTES: usize = 16 * 1024;

pub(super) struct TrustedPathSearch {
    pub(super) entries: Vec<PathBuf>,
    pub(super) rejections: Vec<String>,
}

pub(super) fn trusted_path_entries(path: &OsStr) -> Result<TrustedPathSearch> {
    if path.len() > MAX_PATH_BYTES {
        return Err(NetdiagError::Connector(format!(
            "cannot resolve Python interpreter because PATH exceeds {MAX_PATH_BYTES} bytes"
        )));
    }
    let (mut seen, mut entries, mut rejections) = (BTreeSet::new(), Vec::new(), Vec::new());
    for directory in env::split_paths(path) {
        if !directory.is_absolute() {
            record_rejection(
                &mut rejections,
                format!("path_entry_not_absolute(path={})", directory.display()),
            );
            continue;
        }
        let canonical = match directory.canonicalize() {
            Ok(canonical) => canonical,
            Err(error) => {
                record_rejection(
                    &mut rejections,
                    format!(
                        "path_canonicalize_error(path={}, cause={error})",
                        directory.display()
                    ),
                );
                continue;
            }
        };
        if let Err(error) = validate_trusted_directory_chain(&canonical) {
            record_rejection(&mut rejections, error.to_string());
            continue;
        }
        if seen.insert(canonical.clone()) {
            entries.push(canonical);
        }
    }
    Ok(TrustedPathSearch {
        entries,
        rejections,
    })
}

#[cfg(test)]
mod tests;
