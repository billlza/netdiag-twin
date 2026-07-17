use super::super::TrustedDatasetRoot;
#[cfg(unix)]
use super::super::errors::published;
use super::super::errors::published_but_durability_uncertain;
#[cfg(unix)]
use crate::error::IoContext;
#[cfg(not(unix))]
use crate::error::NetdiagError;
use crate::error::Result;
use crate::storage::BoundAtomicFileTarget;

impl TrustedDatasetRoot {
    pub(in crate::dataset) fn confirm_publication_durability(
        &self,
        target: &BoundAtomicFileTarget,
    ) -> Result<()> {
        self.ensure_owned(target)?;
        #[cfg(unix)]
        {
            self.confirm_publication_durability_with(
                target,
                |directory| {
                    directory
                        .as_file()
                        .sync_all()
                        .with_path(directory.resolved_path())
                },
                || self.validate(),
            )
        }
        #[cfg(not(unix))]
        {
            Err(published_but_durability_uncertain(
                target.resolved_path(),
                NetdiagError::InvalidTrace(
                    "dataset publication durability confirmation is unavailable on this platform"
                        .to_string(),
                ),
            ))
        }
    }

    #[cfg(unix)]
    pub(in crate::dataset::trusted_root) fn confirm_publication_durability_with(
        &self,
        target: &BoundAtomicFileTarget,
        sync: impl FnOnce(&netdiag_platform::TrustedDirectory) -> Result<()>,
        validate_after: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        self.ensure_owned(target)?;
        self.validate()
            .map_err(|source| published_but_durability_uncertain(target.resolved_path(), source))?;
        sync(&self.directory)
            .map_err(|source| published_but_durability_uncertain(target.resolved_path(), source))?;
        validate_after().map_err(|source| published(target.resolved_path(), source))
    }
}
