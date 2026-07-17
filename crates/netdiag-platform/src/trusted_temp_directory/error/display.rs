use super::TrustedTempDirectoryError;
use std::error::Error;
use std::fmt;

impl fmt::Display for TrustedTempDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => formatter
                .write_str("trusted temporary directory prefix must be 1-64 safe ASCII characters"),
            Self::InvalidGeneratedName => {
                formatter.write_str("generated trusted temporary directory name is invalid")
            }
            Self::Random { source } => write!(
                formatter,
                "failed to generate a trusted temporary directory name: {source}"
            ),
            Self::SystemTemporaryRoot { source } => write!(
                formatter,
                "failed to select the trusted temporary directory root: {source}"
            ),
            Self::Trust {
                context,
                path,
                source,
            } => write!(
                formatter,
                "{context} failed for {}: {source}",
                path.display()
            ),
            Self::Io {
                context,
                path,
                source,
            } => write!(
                formatter,
                "{context} failed for {}: {source}",
                path.display()
            ),
            Self::RootPolicy { path, detail } => write!(
                formatter,
                "trusted temporary root policy failed for {}: {detail}",
                path.display()
            ),
            Self::ChildPolicy { path, detail } => write!(
                formatter,
                "trusted temporary child policy failed for {}: {detail}",
                path.display()
            ),
            Self::IdentityChanged { path } => write!(
                formatter,
                "trusted temporary directory identity changed: {}",
                path.display()
            ),
            Self::StateUnavailable { path } => write!(
                formatter,
                "trusted temporary directory state is unavailable: {}",
                path.display()
            ),
            Self::NameCollisionLimit { root } => write!(
                formatter,
                "trusted temporary directory name collision limit reached under {}",
                root.display()
            ),
            Self::CleanupSkipped { path, validation } => write!(
                formatter,
                "trusted temporary directory cleanup was skipped because identity validation failed at {}: {validation}",
                path.display()
            ),
            Self::ValidationAndCleanup {
                path,
                validation,
                cleanup,
            } => write!(
                formatter,
                "trusted temporary directory validation failed at {}: {validation}; cleanup also failed: {cleanup}",
                path.display()
            ),
            Self::UnsupportedPlatform => formatter
                .write_str("trusted temporary directories are unavailable on this platform"),
        }
    }
}

impl Error for TrustedTempDirectoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Random { source } => Some(source),
            Self::SystemTemporaryRoot { source } => Some(source),
            Self::Trust { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::CleanupSkipped { validation, .. } => Some(validation.as_ref()),
            Self::ValidationAndCleanup { validation, .. } => Some(validation.as_ref()),
            _ => None,
        }
    }
}
