use std::io;

mod classification;
mod construction;
mod display;
#[cfg(test)]
mod tests;
pub use classification::{AtomicPublicationClassification, AtomicPublicationLocationObservation};
#[cfg(windows)]
pub(super) use construction::classified_publication_error;
pub(crate) use construction::not_published;
#[cfg(unix)]
pub(crate) use construction::published_uncertain;

/// Observable publication state after an atomic filesystem operation fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtomicPublicationState {
    /// The source file is conclusively still unpublished.
    NotPublished,
    /// The target may be visible, but its durable state cannot be proven.
    PublishedButDurabilityUncertain,
}

/// Atomic publication failure with its primary I/O error and typed classification evidence.
#[derive(Debug)]
pub struct AtomicPublicationError {
    state: AtomicPublicationState,
    primary: io::Error,
    classification: Option<AtomicPublicationClassification>,
}

impl AtomicPublicationError {
    /// Returns the conservative publication state.
    pub fn state(&self) -> AtomicPublicationState {
        self.state
    }

    /// Returns the [`io::ErrorKind`] of the primary publish operation.
    pub fn kind(&self) -> io::ErrorKind {
        self.primary.kind()
    }

    /// Returns the primary publish operation error used by [`std::error::Error::source`].
    pub fn primary_io_error(&self) -> &io::Error {
        &self.primary
    }

    /// Returns typed evidence collected while classifying the failed operation.
    pub fn classification(&self) -> Option<&AtomicPublicationClassification> {
        self.classification.as_ref()
    }
}
