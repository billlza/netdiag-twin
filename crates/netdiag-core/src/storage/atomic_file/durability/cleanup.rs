use super::super::target::BoundAtomicFileTarget;
use crate::error::NetdiagError;
use std::ffi::OsStr;
use std::path::Path;

pub(in crate::storage::atomic_file) fn cleanup_failed_write(
    target: &BoundAtomicFileTarget,
    temporary_name: &OsStr,
    temporary_path: &Path,
    error: NetdiagError,
) -> NetdiagError {
    match netdiag_platform::remove_file_at(target.directory(), temporary_name) {
        Ok(()) => error,
        Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => error,
        Err(source) => error.with_secondary_failure(
            "atomic file write failed",
            "temporary file cleanup also failed",
            NetdiagError::Io {
                path: temporary_path.to_path_buf(),
                source,
            },
        ),
    }
}
