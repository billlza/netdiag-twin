use super::{AtomicPublicationClassification, AtomicPublicationLocationObservation};
use std::fmt;

impl fmt::Display for AtomicPublicationClassification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeldSourceIdentityMismatch => {
                formatter.write_str("the retained source identity no longer matched")
            }
            Self::HeldSourceIdentityInspectionFailed { source } => {
                write!(
                    formatter,
                    "retained source identity inspection failed: {source}"
                )
            }
            Self::SourceLocationObservations { temporary, target } => write!(
                formatter,
                "source locations were temporary={temporary}, target={target}"
            ),
        }
    }
}

impl fmt::Display for AtomicPublicationLocationObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceFile => formatter.write_str("source file"),
            Self::Missing => formatter.write_str("missing"),
            Self::DifferentIdentity => formatter.write_str("different file"),
            Self::InspectionFailed { source } => write!(formatter, "inspection failed: {source}"),
        }
    }
}
