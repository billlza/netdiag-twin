use super::PrivateFileCreationError;
use std::error::Error;
use std::fmt;
use std::io;

#[derive(Debug)]
struct FixtureError(&'static str);

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for FixtureError {}

#[test]
fn ordinary_io_failure_preserves_kind_and_source_chain() {
    let error = PrivateFileCreationError::from(io::Error::new(
        io::ErrorKind::AlreadyExists,
        FixtureError("creation fixture"),
    ));

    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert!(error.cleanup_io_error().is_none());
    let source = error.source().expect("primary I/O source");
    let source = source.downcast_ref::<io::Error>().expect("I/O source type");
    assert_eq!(source.kind(), io::ErrorKind::AlreadyExists);
    assert!(matches!(
        source
            .get_ref()
            .and_then(|error| error.downcast_ref::<FixtureError>()),
        Some(FixtureError("creation fixture"))
    ));
}

#[test]
fn validation_and_cleanup_failure_preserves_both_io_errors() {
    let error = PrivateFileCreationError::ValidationAndCleanup {
        validation: io::Error::new(
            io::ErrorKind::PermissionDenied,
            FixtureError("validation fixture"),
        ),
        cleanup: io::Error::new(
            io::ErrorKind::DirectoryNotEmpty,
            FixtureError("cleanup fixture"),
        ),
    };

    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    let source = error.source().expect("validation I/O source");
    let source = source.downcast_ref::<io::Error>().expect("I/O source type");
    assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(
        error.cleanup_io_error().map(io::Error::kind),
        Some(io::ErrorKind::DirectoryNotEmpty)
    );
    assert!(matches!(
        source
            .get_ref()
            .and_then(|error| error.downcast_ref::<FixtureError>()),
        Some(FixtureError("validation fixture"))
    ));
    assert!(matches!(
        error
            .cleanup_io_error()
            .and_then(io::Error::get_ref)
            .and_then(|error| error.downcast_ref::<FixtureError>()),
        Some(FixtureError("cleanup fixture"))
    ));
}

#[test]
fn io_conversion_preserves_kind_and_structured_error() {
    let error = PrivateFileCreationError::ValidationAndCleanup {
        validation: io::Error::new(io::ErrorKind::InvalidData, FixtureError("validation")),
        cleanup: io::Error::other(FixtureError("cleanup")),
    };
    let error = io::Error::from(error);

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    let structured = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<PrivateFileCreationError>())
        .expect("structured private-file error");
    assert_eq!(
        structured.cleanup_io_error().map(io::Error::kind),
        Some(io::ErrorKind::Other)
    );
}
