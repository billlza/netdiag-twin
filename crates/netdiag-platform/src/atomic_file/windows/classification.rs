use super::super::error::{
    AtomicPublicationClassification, AtomicPublicationError, AtomicPublicationLocationObservation,
    AtomicPublicationState, classified_publication_error,
};
use crate::{OpenedFileIdentity, TrustedDirectory, opened_file_identity};
use std::ffi::OsStr;
use std::fs::File;
use std::io;

mod observation;
use observation::observe_location;

pub(super) fn classify_failure(
    directory: &TrustedDirectory,
    temporary: &OsStr,
    target: &OsStr,
    source_file: &File,
    expected: OpenedFileIdentity,
    primary: io::Error,
) -> AtomicPublicationError {
    classify_failure_with(
        temporary,
        target,
        expected,
        primary,
        || opened_file_identity(source_file),
        |name| observation::identity_at(directory, name),
    )
}

pub(super) fn classify_failure_with<H, L>(
    temporary: &OsStr,
    target: &OsStr,
    expected: OpenedFileIdentity,
    primary: io::Error,
    inspect_held_source: H,
    mut inspect_location: L,
) -> AtomicPublicationError
where
    H: FnOnce() -> io::Result<OpenedFileIdentity>,
    L: FnMut(&OsStr) -> io::Result<Option<OpenedFileIdentity>>,
{
    match inspect_held_source() {
        Ok(current) if current == expected => {}
        Ok(_) => {
            return classified_publication_error(
                AtomicPublicationState::PublishedButDurabilityUncertain,
                primary,
                AtomicPublicationClassification::HeldSourceIdentityMismatch,
            );
        }
        Err(source) => {
            return classified_publication_error(
                AtomicPublicationState::PublishedButDurabilityUncertain,
                primary,
                AtomicPublicationClassification::HeldSourceIdentityInspectionFailed { source },
            );
        }
    }

    let temporary = observe_location(inspect_location(temporary), expected);
    let target = observe_location(inspect_location(target), expected);
    let state = if matches!(temporary, AtomicPublicationLocationObservation::SourceFile)
        && matches!(
            target,
            AtomicPublicationLocationObservation::Missing
                | AtomicPublicationLocationObservation::DifferentIdentity
        ) {
        AtomicPublicationState::NotPublished
    } else {
        AtomicPublicationState::PublishedButDurabilityUncertain
    };
    classified_publication_error(
        state,
        primary,
        AtomicPublicationClassification::SourceLocationObservations { temporary, target },
    )
}
