use super::super::TrustedDatasetRoot;
#[cfg(any(unix, windows))]
use super::super::errors::trust_error;
use crate::error::Result;
use crate::storage::BoundAtomicFileTarget;
use std::ffi::OsStr;
use std::sync::Arc;

impl TrustedDatasetRoot {
    pub(in crate::dataset) fn open_child(
        parent: &BoundAtomicFileTarget,
        name: &str,
    ) -> Result<Self> {
        #[cfg(any(unix, windows))]
        {
            let directory = netdiag_platform::open_or_create_durable_trusted_subdirectory(
                parent.directory(),
                OsStr::new(name),
            )
            .map_err(trust_error)?;
            directory.validate_private_security().map_err(trust_error)?;
            let path = directory.resolved_path().to_path_buf();
            Ok(Self {
                path,
                directory: Arc::new(directory),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (parent, name);
            Err(crate::error::NetdiagError::InvalidTrace(
                "dataset directory trust validation is unavailable on this platform".to_string(),
            ))
        }
    }
}
