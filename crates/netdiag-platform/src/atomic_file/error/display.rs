use super::AtomicPublicationError;

impl std::fmt::Display for AtomicPublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.classification {
            Some(classification) => write!(
                formatter,
                "{}; publication classification: {classification}",
                self.primary
            ),
            None => self.primary.fmt(formatter),
        }
    }
}

impl std::error::Error for AtomicPublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
