use crate::error::{NetdiagError, Result};
use netdiag_platform::{TrustedTempDirectory, TrustedTempDirectoryFinishError};
use std::path::Path;

#[must_use = "managed temporary directories must be finished explicitly"]
#[derive(Debug)]
pub(crate) struct ManagedTempDirectory {
    context: &'static str,
    directory: TrustedTempDirectory,
}

impl ManagedTempDirectory {
    pub(crate) fn create(context: &'static str, prefix: &str) -> Result<Self> {
        let directory = TrustedTempDirectory::create(prefix).map_err(|source| {
            NetdiagError::TrustedTemporaryDirectory {
                context,
                source: Box::new(source),
            }
        })?;
        Ok(Self { context, directory })
    }

    pub(crate) fn path(&self) -> &Path {
        self.directory.path()
    }

    pub(crate) fn validate_identity(&self) -> Result<()> {
        self.directory.validate_identity().map_err(|source| {
            NetdiagError::TrustedTemporaryDirectory {
                context: self.context,
                source: Box::new(source),
            }
        })
    }

    pub(crate) fn finish<T>(self, operation: Result<T>) -> Result<T> {
        match self.directory.finish(operation) {
            Ok(value) => Ok(value),
            Err(TrustedTempDirectoryFinishError::Operation(operation)) => Err(operation),
            Err(TrustedTempDirectoryFinishError::Cleanup(source)) => {
                Err(NetdiagError::TrustedTemporaryDirectoryCleanupAfterSuccess {
                    context: self.context,
                    source: Box::new(source),
                })
            }
            Err(TrustedTempDirectoryFinishError::OperationAndCleanup { operation, cleanup }) => {
                Err(NetdiagError::TrustedTemporaryDirectoryOperationAndCleanup {
                    context: self.context,
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests;
