use super::super::TrustedDatasetRoot;
use super::super::errors::{combine_operation_and_identity_failure, published};
use crate::error::Result;
use crate::storage::BoundAtomicFileTarget;

impl TrustedDatasetRoot {
    pub(in crate::dataset) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        self.finish_with(result, || self.validate())
    }

    pub(in crate::dataset) fn finish_published<T>(
        &self,
        target: &BoundAtomicFileTarget,
        result: Result<T>,
    ) -> Result<T> {
        self.ensure_owned(target)?;
        self.finish_with(result, || self.validate())
            .map_err(|error| {
                if matches!(
                    &error,
                    crate::error::NetdiagError::AtomicPublish {
                        path,
                        phase: crate::error::AtomicPublishPhase::Published
                            | crate::error::AtomicPublishPhase::PublishedButDurabilityUncertain,
                        ..
                    } if path == target.resolved_path()
                ) {
                    error
                } else {
                    published(target.resolved_path(), error)
                }
            })
    }

    pub(in crate::dataset::trusted_root) fn finish_with<T>(
        &self,
        result: Result<T>,
        validate_after: impl FnOnce() -> Result<()>,
    ) -> Result<T> {
        match (result, validate_after()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(primary), Err(identity)) => {
                Err(combine_operation_and_identity_failure(primary, identity))
            }
        }
    }
}
