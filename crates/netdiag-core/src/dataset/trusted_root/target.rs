use super::TrustedDatasetRoot;
use crate::error::Result;
use crate::storage::BoundAtomicFileTarget;
use std::ffi::OsStr;
use std::sync::Arc;

impl TrustedDatasetRoot {
    pub(in crate::dataset) fn immutable_targets(
        &self,
        hash: &str,
    ) -> Result<(BoundAtomicFileTarget, BoundAtomicFileTarget)> {
        let prefix = hash.chars().take(12).collect::<String>();
        Ok((
            self.target(&format!("{prefix}.jsonl"))?,
            self.target(&format!("{prefix}-manifest.json"))?,
        ))
    }

    pub(in crate::dataset) fn target(&self, name: &str) -> Result<BoundAtomicFileTarget> {
        #[cfg(any(unix, windows))]
        {
            BoundAtomicFileTarget::from_directory(Arc::clone(&self.directory), OsStr::new(name))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = name;
            Err(crate::error::NetdiagError::InvalidTrace(
                "dataset directory targets are unavailable on this platform".to_string(),
            ))
        }
    }

    #[cfg(any(unix, windows))]
    pub(in crate::dataset) fn directory_arc(&self) -> Arc<netdiag_platform::TrustedDirectory> {
        Arc::clone(&self.directory)
    }

    pub(in crate::dataset) fn owns_target(&self, target: &BoundAtomicFileTarget) -> bool {
        #[cfg(any(unix, windows))]
        {
            target.shares_directory_arc(&self.directory)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = target;
            false
        }
    }
}
