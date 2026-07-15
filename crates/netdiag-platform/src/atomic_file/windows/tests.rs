use super::classification::classify_failure_with;
use super::*;
use crate::{
    AtomicPublicationClassification, AtomicPublicationLocationObservation, OpenedFileIdentity,
    create_new_private_file_at, open_trusted_directory_chain, opened_file_identity,
};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::io;

const TEMPORARY_NAME: &str = "state.tmp";
const TARGET_NAME: &str = "state.json";

#[derive(Debug)]
struct InjectedPublishFailure;

impl fmt::Display for InjectedPublishFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected publish failure")
    }
}

impl Error for InjectedPublishFailure {}

#[derive(Clone, Copy)]
enum TestLocation {
    SourceFile,
    Missing,
    DifferentIdentity,
}

#[test]
fn failed_publish_with_source_at_target_is_conservatively_uncertain() {
    let root = tempfile::tempdir().expect("temporary root");
    let directory = open_trusted_directory_chain(root.path()).expect("trusted parent");
    drop(
        create_new_private_file_at(&directory, OsStr::new(TEMPORARY_NAME))
            .expect("private temporary"),
    );
    let source = crate::open_file_read_only_no_follow(&root.path().join(TEMPORARY_NAME))
        .expect("temporary handle");
    let expected = opened_file_identity(&source).expect("temporary identity");
    std::fs::rename(
        root.path().join(TEMPORARY_NAME),
        root.path().join(TARGET_NAME),
    )
    .expect("simulate rename before durability failure");

    let failure = classify_failure(
        &directory,
        OsStr::new(TEMPORARY_NAME),
        OsStr::new(TARGET_NAME),
        &source,
        expected,
        primary_error(),
    );

    assert_eq!(
        failure.state(),
        crate::AtomicPublicationState::PublishedButDurabilityUncertain
    );
    let (temporary, target) = source_locations(&failure);
    assert!(matches!(
        temporary,
        AtomicPublicationLocationObservation::Missing
    ));
    assert!(matches!(
        target,
        AtomicPublicationLocationObservation::SourceFile
    ));
    assert_primary_error(&failure);
}

#[test]
fn failed_publish_with_original_source_is_not_published() {
    let root = tempfile::tempdir().expect("temporary root");
    let directory = open_trusted_directory_chain(root.path()).expect("trusted parent");
    drop(
        create_new_private_file_at(&directory, OsStr::new(TEMPORARY_NAME))
            .expect("private temporary"),
    );
    let source = crate::open_file_read_only_no_follow(&root.path().join(TEMPORARY_NAME))
        .expect("temporary handle");
    let expected = opened_file_identity(&source).expect("temporary identity");

    let failure = classify_failure(
        &directory,
        OsStr::new(TEMPORARY_NAME),
        OsStr::new(TARGET_NAME),
        &source,
        expected,
        primary_error(),
    );

    assert_eq!(failure.state(), crate::AtomicPublicationState::NotPublished);
    let (temporary, target) = source_locations(&failure);
    assert!(matches!(
        temporary,
        AtomicPublicationLocationObservation::SourceFile
    ));
    assert!(matches!(
        target,
        AtomicPublicationLocationObservation::Missing
    ));
    assert_primary_error(&failure);
}

#[test]
fn held_source_identity_mismatch_is_structured_and_uncertain() {
    let (expected, different) = distinct_identities();
    let failure = classify_observations(expected, Ok(different), Ok(Some(expected)), Ok(None));

    assert_eq!(
        failure.state(),
        crate::AtomicPublicationState::PublishedButDurabilityUncertain
    );
    assert!(matches!(
        failure.classification(),
        Some(AtomicPublicationClassification::HeldSourceIdentityMismatch)
    ));
    assert_primary_error(&failure);
}

#[test]
fn held_source_identity_inspection_failure_preserves_both_io_errors() {
    let (expected, _) = distinct_identities();
    let failure = classify_observations(
        expected,
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "held identity denied",
        )),
        Ok(Some(expected)),
        Ok(None),
    );

    assert_eq!(
        failure.state(),
        crate::AtomicPublicationState::PublishedButDurabilityUncertain
    );
    let classification = failure.classification().expect("held classification");
    let held_error = classification
        .held_source_inspection_io_error()
        .expect("held inspection error");
    assert_eq!(held_error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(held_error.to_string(), "held identity denied");
    assert_primary_error(&failure);
}

#[test]
fn location_matrix_only_classifies_an_unchanged_temporary_as_not_published() {
    let (expected, different) = distinct_identities();
    let locations = [
        TestLocation::SourceFile,
        TestLocation::Missing,
        TestLocation::DifferentIdentity,
    ];

    for temporary in locations {
        for target in locations {
            let failure = classify_observations(
                expected,
                Ok(expected),
                location_result(temporary, expected, different),
                location_result(target, expected, different),
            );
            let not_published = matches!(temporary, TestLocation::SourceFile)
                && matches!(
                    target,
                    TestLocation::Missing | TestLocation::DifferentIdentity
                );
            let expected_state = if not_published {
                crate::AtomicPublicationState::NotPublished
            } else {
                crate::AtomicPublicationState::PublishedButDurabilityUncertain
            };
            assert_eq!(failure.state(), expected_state);
            let (observed_temporary, observed_target) = source_locations(&failure);
            assert_location(observed_temporary, temporary);
            assert_location(observed_target, target);
            assert_primary_error(&failure);
        }
    }
}

#[test]
fn either_location_inspection_failure_is_structured_and_uncertain() {
    let (expected, different) = distinct_identities();
    let locations = [
        TestLocation::SourceFile,
        TestLocation::Missing,
        TestLocation::DifferentIdentity,
    ];

    for target in locations {
        let failure = classify_observations(
            expected,
            Ok(expected),
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "temporary inspection denied",
            )),
            location_result(target, expected, different),
        );
        assert_eq!(
            failure.state(),
            crate::AtomicPublicationState::PublishedButDurabilityUncertain
        );
        let (temporary, observed_target) = source_locations(&failure);
        assert_eq!(
            temporary
                .inspection_io_error()
                .expect("temporary inspection error")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_location(observed_target, target);
    }

    for temporary in locations {
        let failure = classify_observations(
            expected,
            Ok(expected),
            location_result(temporary, expected, different),
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "target inspection timed out",
            )),
        );
        assert_eq!(
            failure.state(),
            crate::AtomicPublicationState::PublishedButDurabilityUncertain
        );
        let (observed_temporary, target) = source_locations(&failure);
        assert_location(observed_temporary, temporary);
        assert_eq!(
            target
                .inspection_io_error()
                .expect("target inspection error")
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}

#[test]
fn both_location_inspection_failures_remain_independently_accessible() {
    let (expected, _) = distinct_identities();
    let failure = classify_observations(
        expected,
        Ok(expected),
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "temporary inspection denied",
        )),
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "target inspection timed out",
        )),
    );

    assert_eq!(
        failure.state(),
        crate::AtomicPublicationState::PublishedButDurabilityUncertain
    );
    let (temporary, target) = source_locations(&failure);
    let temporary_error = temporary
        .inspection_io_error()
        .expect("temporary inspection error");
    let target_error = target
        .inspection_io_error()
        .expect("target inspection error");
    assert_eq!(temporary_error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(temporary_error.to_string(), "temporary inspection denied");
    assert_eq!(target_error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(target_error.to_string(), "target inspection timed out");
    assert_primary_error(&failure);
}

#[test]
fn publication_error_formatting_never_contains_file_identity_bytes() {
    let (expected, different) = distinct_identities();
    let expected_debug = format!("{expected:?}");
    let different_debug = format!("{different:?}");
    let expected_bytes = expected_debug
        .strip_prefix("OpenedFileIdentity(")
        .and_then(|value| value.strip_suffix(')'))
        .expect("identity debug shape");
    let different_bytes = different_debug
        .strip_prefix("OpenedFileIdentity(")
        .and_then(|value| value.strip_suffix(')'))
        .expect("identity debug shape");
    let failure = classify_observations(expected, Ok(expected), Ok(Some(different)), Ok(None));

    let display = failure.to_string();
    assert!(display.contains("temporary=different file, target=missing"));
    for rendered in [display, format!("{failure:?}")] {
        assert!(!rendered.contains("OpenedFileIdentity"));
        assert!(!rendered.contains(&expected_debug));
        assert!(!rendered.contains(&different_debug));
        assert!(!rendered.contains(expected_bytes));
        assert!(!rendered.contains(different_bytes));
    }
}

fn primary_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, InjectedPublishFailure)
}

fn assert_primary_error(failure: &AtomicPublicationError) {
    assert_eq!(failure.kind(), io::ErrorKind::ConnectionAborted);
    assert!(
        failure
            .primary_io_error()
            .get_ref()
            .is_some_and(|source| source.is::<InjectedPublishFailure>())
    );
    let chained = Error::source(failure)
        .and_then(|source| source.downcast_ref::<io::Error>())
        .expect("primary I/O source");
    assert!(std::ptr::eq(chained, failure.primary_io_error()));
}

fn distinct_identities() -> (OpenedFileIdentity, OpenedFileIdentity) {
    let root = tempfile::tempdir().expect("identity root");
    let first_path = root.path().join("first");
    let second_path = root.path().join("second");
    std::fs::write(&first_path, b"first").expect("first identity fixture");
    std::fs::write(&second_path, b"second").expect("second identity fixture");
    let first = crate::open_file_read_only_no_follow(&first_path).expect("first handle");
    let second = crate::open_file_read_only_no_follow(&second_path).expect("second handle");
    let first = opened_file_identity(&first).expect("first identity");
    let second = opened_file_identity(&second).expect("second identity");
    assert_ne!(first, second);
    (first, second)
}

fn classify_observations(
    expected: OpenedFileIdentity,
    held: io::Result<OpenedFileIdentity>,
    temporary: io::Result<Option<OpenedFileIdentity>>,
    target: io::Result<Option<OpenedFileIdentity>>,
) -> AtomicPublicationError {
    let mut temporary = Some(temporary);
    let mut target = Some(target);
    classify_failure_with(
        OsStr::new(TEMPORARY_NAME),
        OsStr::new(TARGET_NAME),
        expected,
        primary_error(),
        || held,
        |name| {
            if name == OsStr::new(TEMPORARY_NAME) {
                temporary.take().expect("single temporary inspection")
            } else {
                assert_eq!(name, OsStr::new(TARGET_NAME));
                target.take().expect("single target inspection")
            }
        },
    )
}

fn location_result(
    location: TestLocation,
    expected: OpenedFileIdentity,
    different: OpenedFileIdentity,
) -> io::Result<Option<OpenedFileIdentity>> {
    Ok(match location {
        TestLocation::SourceFile => Some(expected),
        TestLocation::Missing => None,
        TestLocation::DifferentIdentity => Some(different),
    })
}

fn source_locations(
    failure: &AtomicPublicationError,
) -> (
    &AtomicPublicationLocationObservation,
    &AtomicPublicationLocationObservation,
) {
    failure
        .classification()
        .and_then(AtomicPublicationClassification::source_location_observations)
        .expect("source location observations")
}

fn assert_location(actual: &AtomicPublicationLocationObservation, expected: TestLocation) {
    assert!(match expected {
        TestLocation::SourceFile => {
            matches!(actual, AtomicPublicationLocationObservation::SourceFile)
        }
        TestLocation::Missing => {
            matches!(actual, AtomicPublicationLocationObservation::Missing)
        }
        TestLocation::DifferentIdentity => matches!(
            actual,
            AtomicPublicationLocationObservation::DifferentIdentity
        ),
    });
}
