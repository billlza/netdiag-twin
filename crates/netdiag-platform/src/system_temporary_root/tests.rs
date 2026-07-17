use super::*;
use std::error::Error;

#[cfg(any(unix, windows))]
#[test]
fn resolves_an_absolute_canonical_platform_root() {
    let root = system_temporary_root_path().expect("system temporary root");
    assert!(root.is_absolute());
    assert_eq!(root.canonicalize().expect("canonical root"), root);
    #[cfg(unix)]
    assert_eq!(
        root,
        std::path::Path::new("/tmp")
            .canonicalize()
            .expect("canonical /tmp")
    );
}

#[cfg(any(unix, windows))]
#[test]
fn resolution_failure_preserves_path_and_io_source() {
    let parent = tempfile::tempdir().expect("missing-root parent");
    let missing = parent.path().join("missing");
    let error = resolve(&missing).expect_err("missing root must fail explicitly");
    assert!(matches!(
        &error,
        SystemTemporaryRootError::Resolution { path, .. } if path == &missing
    ));
    assert!(matches!(
        error.source(),
        Some(source) if source.downcast_ref::<std::io::Error>().is_some()
    ));
    assert!(error.to_string().contains("failed to resolve"));
}

#[test]
fn query_contract_errors_remain_distinct_and_preserve_sources() {
    let query = SystemTemporaryRootError::Query {
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "query denied"),
    };
    assert!(query.to_string().contains("failed to query"));
    assert!(query.source().is_some());

    let invalid_length = SystemTemporaryRootError::InvalidLength { units: 32_768 };
    assert!(invalid_length.to_string().contains("32768"));
    assert!(invalid_length.source().is_none());

    let invalid_path = SystemTemporaryRootError::InvalidPath {
        path: PathBuf::from("relative"),
        detail: "the path must be absolute",
    };
    assert!(invalid_path.to_string().contains("relative"));

    let unterminated = SystemTemporaryRootError::MissingTerminator { units: 261 };
    assert!(unterminated.to_string().contains("261-code-unit"));
}
