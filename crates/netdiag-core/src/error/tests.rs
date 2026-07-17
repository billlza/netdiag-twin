use super::*;
use std::error::Error;
use std::ffi::OsStr;
use std::io;
use std::path::Path;

fn io_error(path: &str, message: &'static str) -> NetdiagError {
    NetdiagError::Io {
        path: Path::new(path).to_path_buf(),
        source: std::io::Error::other(message),
    }
}

#[test]
fn secondary_failure_keeps_both_typed_causes() {
    let error = io_error("primary", "primary failure").with_secondary_failure(
        "primary context",
        "secondary context",
        io_error("secondary", "secondary failure"),
    );

    let NetdiagError::CombinedFailure {
        primary_context,
        primary,
        secondary_context,
        secondary,
    } = &error
    else {
        panic!("expected combined failure: {error}");
    };
    assert_eq!(*primary_context, "primary context");
    assert_eq!(*secondary_context, "secondary context");
    assert!(matches!(
        primary.as_ref(),
        NetdiagError::Io { path, source }
            if path == Path::new("primary") && source.to_string() == "primary failure"
    ));
    assert!(matches!(
        secondary.as_ref(),
        NetdiagError::Io { path, source }
            if path == Path::new("secondary") && source.to_string() == "secondary failure"
    ));
    assert!(error.source().is_some());
}

#[test]
fn secondary_failure_preserves_atomic_publication_state() {
    let target = Path::new("state.json").to_path_buf();
    let error = NetdiagError::AtomicPublish {
        path: target.clone(),
        phase: AtomicPublishPhase::Published,
        source: Box::new(io_error("state.json", "post-publication failure")),
    }
    .with_secondary_failure(
        "publication failed",
        "unlock also failed",
        io_error("state.lock", "unlock failure"),
    );

    let NetdiagError::AtomicPublish {
        path,
        phase,
        source,
    } = error
    else {
        panic!("expected atomic publication failure");
    };
    assert_eq!(path, target);
    assert_eq!(phase, AtomicPublishPhase::Published);
    assert!(matches!(
        source.as_ref(),
        NetdiagError::CombinedFailure { .. }
    ));
}

#[test]
fn platform_atomic_publication_keeps_the_complete_source_chain() {
    let root = tempfile::tempdir().expect("temporary root");
    let directory =
        netdiag_platform::open_trusted_directory_chain(root.path()).expect("trusted directory");
    let platform = netdiag_platform::publish_file_replace_at(
        &directory,
        OsStr::new("../invalid"),
        OsStr::new("state.json"),
    )
    .expect_err("invalid leaf must fail");
    let target = root.path().join("state.json");
    let error = NetdiagError::atomic_publish(
        target.clone(),
        AtomicPublishPhase::NotPublished,
        NetdiagError::PlatformAtomicPublication {
            path: target.clone(),
            source: platform,
        },
    );

    let NetdiagError::AtomicPublish {
        source: platform_variant,
        ..
    } = &error
    else {
        panic!("expected outer atomic publication variant");
    };
    let NetdiagError::PlatformAtomicPublication { path, source } = platform_variant.as_ref() else {
        panic!("expected platform atomic publication variant");
    };
    assert_eq!(path, &target);
    assert_eq!(source.kind(), io::ErrorKind::InvalidInput);

    let platform_error = Error::source(platform_variant.as_ref())
        .and_then(|error| error.downcast_ref::<netdiag_platform::AtomicPublicationError>())
        .expect("typed platform error source");
    assert!(std::ptr::eq(platform_error, source));
    let platform_error_from_standard_chain = error
        .source()
        .and_then(Error::source)
        .and_then(|error| error.downcast_ref::<netdiag_platform::AtomicPublicationError>())
        .expect("typed platform error in standard source chain");
    assert!(std::ptr::eq(platform_error_from_standard_chain, source));
    let primary_io = Error::source(platform_error)
        .and_then(|error| error.downcast_ref::<io::Error>())
        .expect("typed primary I/O");
    assert_eq!(primary_io.kind(), io::ErrorKind::InvalidInput);
    assert!(std::ptr::eq(primary_io, source.primary_io_error()));
}
