#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtomicPublishPhase {
    NotPublished,
    PublishedButDurabilityUncertain,
    Published,
}

impl std::fmt::Display for AtomicPublishPhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPublished => formatter.write_str("not published"),
            Self::PublishedButDurabilityUncertain => {
                formatter.write_str("published but durability is uncertain")
            }
            Self::Published => formatter.write_str("published"),
        }
    }
}

impl From<netdiag_platform::AtomicPublicationState> for AtomicPublishPhase {
    fn from(state: netdiag_platform::AtomicPublicationState) -> Self {
        match state {
            netdiag_platform::AtomicPublicationState::NotPublished => Self::NotPublished,
            netdiag_platform::AtomicPublicationState::PublishedButDurabilityUncertain => {
                Self::PublishedButDurabilityUncertain
            }
        }
    }
}
