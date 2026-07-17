use std::io;

mod display;
#[cfg(test)]
mod tests;

/// A failure to create and validate a private file.
#[derive(Debug)]
pub enum PrivateFileCreationError {
    /// File creation or security validation failed.
    Io { source: io::Error },
    /// Security validation failed and the invalid file could not be removed.
    ValidationAndCleanup {
        validation: io::Error,
        cleanup: io::Error,
    },
}

impl PrivateFileCreationError {
    /// Returns the primary I/O error kind.
    pub fn kind(&self) -> io::ErrorKind {
        self.primary_io_error().kind()
    }

    /// Returns the primary creation or validation error.
    pub fn primary_io_error(&self) -> &io::Error {
        match self {
            Self::Io { source } => source,
            Self::ValidationAndCleanup { validation, .. } => validation,
        }
    }

    /// Returns the cleanup error when validation and cleanup both failed.
    pub fn cleanup_io_error(&self) -> Option<&io::Error> {
        match self {
            Self::Io { .. } => None,
            Self::ValidationAndCleanup { cleanup, .. } => Some(cleanup),
        }
    }
}

impl From<io::Error> for PrivateFileCreationError {
    fn from(source: io::Error) -> Self {
        Self::Io { source }
    }
}

impl From<PrivateFileCreationError> for io::Error {
    fn from(source: PrivateFileCreationError) -> Self {
        Self::new(source.kind(), source)
    }
}
