#[cfg(not(any(unix, windows)))]
use crate::error::Result;
#[cfg(not(any(unix, windows)))]
use netdiag_platform::TrustedDirectory;
#[cfg(not(any(unix, windows)))]
use std::fs::File;
#[cfg(not(any(unix, windows)))]
use std::path::Path;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub(super) use unix::{open_coordination_file, validate_coordination_file, validate_namespace};
#[cfg(windows)]
pub(super) use windows::{open_coordination_file, validate_coordination_file, validate_namespace};

#[cfg(not(any(unix, windows)))]
pub(super) fn validate_namespace(_namespace: &TrustedDirectory) -> Result<()> {
    Err(unsupported("coordination lock namespaces"))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn open_coordination_file(_namespace: &TrustedDirectory, path: &Path) -> Result<File> {
    Err(unsupported(&format!(
        "coordination locks at {}",
        path.display()
    )))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn validate_coordination_file(
    _namespace: &TrustedDirectory,
    path: &Path,
    _file: &File,
) -> Result<()> {
    Err(unsupported(&format!(
        "coordination lock validation at {}",
        path.display()
    )))
}

#[cfg(not(any(unix, windows)))]
fn unsupported(boundary: &str) -> crate::error::NetdiagError {
    crate::error::NetdiagError::InvalidTrace(format!("{boundary} are unavailable on this platform"))
}
