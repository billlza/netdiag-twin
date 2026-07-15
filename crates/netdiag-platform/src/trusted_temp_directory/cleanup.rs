use super::TrustedTempDirectoryError;
use std::path::PathBuf;

pub(super) fn finish(path: PathBuf) -> Result<(), TrustedTempDirectoryError> {
    match std::fs::remove_dir_all(&path) {
        Ok(()) => Ok(()),
        Err(source) => Err(TrustedTempDirectoryError::Io {
            context: "trusted temporary directory cleanup",
            path,
            source,
        }),
    }
}

pub(super) fn after_creation_failure(
    path: PathBuf,
    validation: TrustedTempDirectoryError,
) -> TrustedTempDirectoryError {
    match std::fs::remove_dir(&path) {
        Ok(()) => validation,
        Err(cleanup) => TrustedTempDirectoryError::ValidationAndCleanup {
            path,
            validation: Box::new(validation),
            cleanup,
        },
    }
}
