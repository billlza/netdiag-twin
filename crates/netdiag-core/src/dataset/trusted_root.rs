use crate::error::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod errors;
mod open;
mod publication;
mod rollback;
mod target;

#[cfg(any(unix, windows))]
use errors::trust_error;

pub(super) struct TrustedDatasetRoot {
    path: PathBuf,
    #[cfg(any(unix, windows))]
    directory: Arc<netdiag_platform::TrustedDirectory>,
}

impl TrustedDatasetRoot {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn validate(&self) -> Result<()> {
        #[cfg(any(unix, windows))]
        {
            self.directory.validate_identity().map_err(trust_error)?;
            self.directory
                .validate_private_security()
                .map_err(trust_error)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(crate::error::NetdiagError::InvalidTrace(
                "dataset directory trust validation is unavailable on this platform".to_string(),
            ))
        }
    }
}

#[cfg(all(test, unix))]
mod tests;
