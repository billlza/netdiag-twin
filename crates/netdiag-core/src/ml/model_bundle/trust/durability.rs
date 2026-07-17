use super::{TrustedModelDirectory, combine_validation, validate_opened};
use crate::error::{IoContext, NetdiagError, Result};

impl TrustedModelDirectory {
    pub(in crate::ml::model_bundle) fn sync(&self) -> Result<()> {
        self.validate()?;
        let result = self.directory.as_file().sync_all().with_path(&self.path);
        self.finish(result)
    }

    pub(in crate::ml::model_bundle) fn sync_parent(&self) -> Result<()> {
        let parent = self.parent_directory.as_ref().ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "model bundle directory has no retained parent handle: {}",
                self.path.display()
            ))
        })?;
        let parent_path = parent.resolved_path();
        validate_opened(parent, parent_path)?;
        let result = parent.as_file().sync_all().with_path(parent_path);
        combine_validation(result, validate_opened(parent, parent_path))
    }
}
