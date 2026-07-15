use super::TrustedDatasetRoot;
use crate::error::{NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;

mod confirmation;
mod finish;

impl TrustedDatasetRoot {
    fn ensure_owned(&self, target: &BoundAtomicFileTarget) -> Result<()> {
        if self.owns_target(target) {
            return Ok(());
        }
        Err(NetdiagError::InvalidTrace(format!(
            "dataset publication target does not belong to the retained root handle: {}",
            target.resolved_path().display()
        )))
    }
}
