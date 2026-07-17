use super::{CurrentUserLocalAppDataError, WindowsHresultError};
use std::error::Error;
use std::fmt;

impl fmt::Display for WindowsHresultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Windows HRESULT 0x{:08X}", self.code() as u32)
    }
}

impl Error for WindowsHresultError {}

impl fmt::Display for CurrentUserLocalAppDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Query { source } => {
                write!(
                    formatter,
                    "failed to query current-user LocalAppData: {source}"
                )
            }
            Self::MissingPath => {
                formatter.write_str("current-user LocalAppData query returned no path")
            }
            Self::PathTooLong { max_units } => write!(
                formatter,
                "current-user LocalAppData path exceeds {max_units} UTF-16 code units"
            ),
            Self::NotAbsolute { path } => write!(
                formatter,
                "current-user LocalAppData path is not absolute: {}",
                path.display()
            ),
        }
    }
}

impl Error for CurrentUserLocalAppDataError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Query { source } => Some(source),
            Self::MissingPath | Self::PathTooLong { .. } | Self::NotAbsolute { .. } => None,
        }
    }
}
