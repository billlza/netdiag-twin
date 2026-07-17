use netdiag_platform::{
    AtomicPublicationClassification, AtomicPublicationError, AtomicPublicationLocationObservation,
    AtomicPublicationState,
};

pub(super) fn is_existing_target(failure: &AtomicPublicationError) -> bool {
    failure.state() == AtomicPublicationState::NotPublished
        && failure.kind() == std::io::ErrorKind::AlreadyExists
        && classification_confirms_existing(failure.classification())
}

fn classification_confirms_existing(
    classification: Option<&AtomicPublicationClassification>,
) -> bool {
    let Some(classification) = classification else {
        return true;
    };
    let Some((temporary, target)) = classification.source_location_observations() else {
        return false;
    };
    existing_location_evidence(location(temporary), location(target))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Location {
    Source,
    Missing,
    Different,
    InspectionFailed,
}

fn location(observation: &AtomicPublicationLocationObservation) -> Location {
    match observation {
        AtomicPublicationLocationObservation::SourceFile => Location::Source,
        AtomicPublicationLocationObservation::Missing => Location::Missing,
        AtomicPublicationLocationObservation::DifferentIdentity => Location::Different,
        AtomicPublicationLocationObservation::InspectionFailed { .. } => Location::InspectionFailed,
        _ => Location::InspectionFailed,
    }
}

fn existing_location_evidence(temporary: Location, target: Location) -> bool {
    temporary == Location::Source && target == Location::Different
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_distinct_target_with_the_source_still_staged_confirms_a_collision() {
        assert!(classification_confirms_existing(None));
        assert!(existing_location_evidence(
            Location::Source,
            Location::Different
        ));
        assert!(!existing_location_evidence(
            Location::Source,
            Location::Missing
        ));
        assert!(!existing_location_evidence(
            Location::Source,
            Location::InspectionFailed
        ));
        assert!(!existing_location_evidence(
            Location::Different,
            Location::Different
        ));
    }
}
