use crate::PrivateFileCreationError;
use std::io;

pub(super) fn after_validation_failure(
    validation: io::Error,
    cleanup: io::Result<()>,
) -> PrivateFileCreationError {
    match cleanup {
        Ok(()) => validation.into(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => validation.into(),
        Err(cleanup) => PrivateFileCreationError::ValidationAndCleanup {
            validation,
            cleanup,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn successful_cleanup_returns_the_validation_error() {
        let error = after_validation_failure(io::Error::other("validation"), Ok(()));

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.cleanup_io_error().is_none());
        assert_eq!(
            error.source().expect("validation source").to_string(),
            "validation"
        );
    }

    #[test]
    fn missing_file_is_an_idempotent_cleanup_success() {
        let error = after_validation_failure(
            io::Error::new(io::ErrorKind::InvalidData, "validation"),
            Err(io::Error::new(io::ErrorKind::NotFound, "already removed")),
        );

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.cleanup_io_error().is_none());
    }

    #[test]
    fn validation_and_cleanup_failures_remain_typed() {
        let error = after_validation_failure(
            io::Error::new(io::ErrorKind::PermissionDenied, "validation"),
            Err(io::Error::new(io::ErrorKind::DirectoryNotEmpty, "cleanup")),
        );

        assert!(matches!(
            &error,
            PrivateFileCreationError::ValidationAndCleanup {
                validation,
                cleanup,
            } if validation.kind() == io::ErrorKind::PermissionDenied
                && cleanup.kind() == io::ErrorKind::DirectoryNotEmpty
        ));
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            error.cleanup_io_error().map(io::Error::kind),
            Some(io::ErrorKind::DirectoryNotEmpty)
        );
    }
}
