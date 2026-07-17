use std::error::Error;
use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum SystemTemporaryRootError {
    Query { source: io::Error },
    InvalidLength { units: usize },
    InvalidPath { path: PathBuf, detail: &'static str },
    MissingTerminator { units: usize },
    Resolution { path: PathBuf, source: io::Error },
    UnsupportedPlatform,
}

impl fmt::Display for SystemTemporaryRootError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query { source } => {
                write!(
                    formatter,
                    "failed to query the system temporary root: {source}"
                )
            }
            Self::InvalidLength { units } => write!(
                formatter,
                "system temporary root query returned an invalid UTF-16 length of {units} code units"
            ),
            Self::InvalidPath { path, detail } => write!(
                formatter,
                "system temporary root query returned an invalid path {}: {detail}",
                path.display()
            ),
            Self::MissingTerminator { units } => write!(
                formatter,
                "system temporary root query did not terminate within its {units}-code-unit buffer"
            ),
            Self::Resolution { path, source } => write!(
                formatter,
                "failed to resolve the system temporary root at {}: {source}",
                path.display()
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("the system temporary root is unavailable on this platform")
            }
        }
    }
}

impl Error for SystemTemporaryRootError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Query { source } => Some(source),
            Self::Resolution { source, .. } => Some(source),
            Self::InvalidLength { .. }
            | Self::InvalidPath { .. }
            | Self::MissingTerminator { .. }
            | Self::UnsupportedPlatform => None,
        }
    }
}
