use super::{TrustedTempDirectory, TrustedTempDirectoryError};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum TrustedTempDirectoryFinishError<E> {
    Operation(E),
    Cleanup(TrustedTempDirectoryError),
    OperationAndCleanup {
        operation: E,
        cleanup: TrustedTempDirectoryError,
    },
}

impl<E: fmt::Display> fmt::Display for TrustedTempDirectoryFinishError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Operation(operation) => operation.fmt(formatter),
            Self::Cleanup(cleanup) => write!(formatter, "{cleanup}"),
            Self::OperationAndCleanup { operation, cleanup } => write!(
                formatter,
                "operation failed: {operation}; trusted temporary directory cleanup also failed: {cleanup}"
            ),
        }
    }
}

impl<E: Error + 'static> Error for TrustedTempDirectoryFinishError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Operation(operation) | Self::OperationAndCleanup { operation, .. } => {
                Some(operation)
            }
            Self::Cleanup(cleanup) => Some(cleanup),
        }
    }
}

pub(super) fn finish<T, E>(
    directory: TrustedTempDirectory,
    operation: Result<T, E>,
) -> Result<T, TrustedTempDirectoryFinishError<E>> {
    let cleanup = directory.close();
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(TrustedTempDirectoryFinishError::Operation(operation)),
        (Ok(_), Err(cleanup)) => Err(TrustedTempDirectoryFinishError::Cleanup(cleanup)),
        (Err(operation), Err(cleanup)) => {
            Err(TrustedTempDirectoryFinishError::OperationAndCleanup { operation, cleanup })
        }
    }
}
