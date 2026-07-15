use crate::error::NetdiagError;
use std::path::Path;

pub(super) fn after_capture_failure(path: &Path, operation: NetdiagError) -> NetdiagError {
    match std::fs::remove_file(path) {
        Ok(()) => operation,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => operation,
        Err(cleanup) => NetdiagError::EvidenceSnapshotOperationAndCleanup {
            path: path.to_path_buf(),
            operation: Box::new(operation),
            cleanup,
        },
    }
}
