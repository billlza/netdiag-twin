use super::PrivateFileCreationError;
use std::error::Error;
use std::fmt;

impl fmt::Display for PrivateFileCreationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { source } => write!(formatter, "private file creation failed: {source}"),
            Self::ValidationAndCleanup {
                validation,
                cleanup,
            } => write!(
                formatter,
                "private file validation failed: {validation}; cleanup also failed: {cleanup}"
            ),
        }
    }
}

impl Error for PrivateFileCreationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.primary_io_error())
    }
}
