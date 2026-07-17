use super::{AtomicPublicationClassification, AtomicPublicationError, AtomicPublicationState};
use std::io;

pub(crate) fn not_published(primary: io::Error) -> AtomicPublicationError {
    publication_error(AtomicPublicationState::NotPublished, primary, None)
}

#[cfg(unix)]
pub(crate) fn published_uncertain(primary: io::Error) -> AtomicPublicationError {
    publication_error(
        AtomicPublicationState::PublishedButDurabilityUncertain,
        primary,
        None,
    )
}

#[cfg(windows)]
pub(in crate::atomic_file) fn classified_publication_error(
    state: AtomicPublicationState,
    primary: io::Error,
    classification: AtomicPublicationClassification,
) -> AtomicPublicationError {
    publication_error(state, primary, Some(classification))
}

fn publication_error(
    state: AtomicPublicationState,
    primary: io::Error,
    classification: Option<AtomicPublicationClassification>,
) -> AtomicPublicationError {
    AtomicPublicationError {
        state,
        primary,
        classification,
    }
}
