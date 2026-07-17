use super::super::TrustedDatasetRoot;
#[cfg(any(unix, windows))]
use super::super::errors::trust_error;
use super::path;
use crate::error::Result;
use std::path::Path;
#[cfg(any(unix, windows))]
use std::sync::Arc;

pub(super) fn open(path: &Path, durable: bool) -> Result<TrustedDatasetRoot> {
    let absolute = path::absolute(path)?;
    #[cfg(any(unix, windows))]
    {
        let directory = if durable {
            netdiag_platform::open_or_create_durable_trusted_directory_chain(&absolute)
        } else {
            netdiag_platform::open_or_create_trusted_directory_chain(&absolute)
        }
        .map_err(trust_error)?;
        directory.validate_private_security().map_err(trust_error)?;
        let path = directory.resolved_path().to_path_buf();
        Ok(TrustedDatasetRoot {
            path,
            directory: Arc::new(directory),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (absolute, durable);
        Err(crate::error::NetdiagError::InvalidTrace(
            "dataset directory trust validation is unavailable on this platform".to_string(),
        ))
    }
}
