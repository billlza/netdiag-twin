use std::io;

mod display;

/// Typed evidence used to classify a failed Windows atomic publication.
#[derive(Debug)]
#[non_exhaustive]
pub enum AtomicPublicationClassification {
    /// The retained source handle no longer identified the expected source file.
    HeldSourceIdentityMismatch,
    /// Inspecting the retained source handle failed.
    HeldSourceIdentityInspectionFailed { source: io::Error },
    /// Semantic observations for the temporary and target names.
    SourceLocationObservations {
        temporary: AtomicPublicationLocationObservation,
        target: AtomicPublicationLocationObservation,
    },
}

impl AtomicPublicationClassification {
    /// Returns the retained-handle inspection error when that inspection failed.
    pub fn held_source_inspection_io_error(&self) -> Option<&io::Error> {
        match self {
            Self::HeldSourceIdentityInspectionFailed { source } => Some(source),
            _ => None,
        }
    }

    /// Returns the temporary and target observations when both names were inspected.
    pub fn source_location_observations(
        &self,
    ) -> Option<(
        &AtomicPublicationLocationObservation,
        &AtomicPublicationLocationObservation,
    )> {
        match self {
            Self::SourceLocationObservations { temporary, target } => Some((temporary, target)),
            _ => None,
        }
    }
}

/// Identity-free observation made while locating the expected source file.
#[derive(Debug)]
#[non_exhaustive]
pub enum AtomicPublicationLocationObservation {
    /// The name resolves to the expected source file.
    SourceFile,
    /// The name does not exist.
    Missing,
    /// The name resolves to another file; its identity value is intentionally discarded.
    DifferentIdentity,
    /// Inspecting the name failed.
    InspectionFailed { source: io::Error },
}

impl AtomicPublicationLocationObservation {
    /// Returns the location inspection error when inspection failed.
    pub fn inspection_io_error(&self) -> Option<&io::Error> {
        match self {
            Self::InspectionFailed { source } => Some(source),
            _ => None,
        }
    }
}
