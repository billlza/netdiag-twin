use super::BoundAtomicFileTarget;
use super::path::{invalid_target, lexical_absolute};
use crate::error::{NetdiagError, Result};
use netdiag_platform::{open_or_create_trusted_directory_chain, open_trusted_directory_chain};
use std::path::Path;
use std::sync::Arc;

impl BoundAtomicFileTarget {
    pub(crate) fn bind(target: &Path) -> Result<Self> {
        Self::bind_with(target, true)
    }

    pub(crate) fn bind_existing_parent(target: &Path) -> Result<Self> {
        Self::bind_with(target, false)
    }

    fn bind_with(target: &Path, create_parent: bool) -> Result<Self> {
        let absolute = lexical_absolute(target)?;
        let target_name = absolute.file_name().ok_or_else(|| invalid_target(target))?;
        let parent = absolute.parent().ok_or_else(|| invalid_target(target))?;
        let directory = if create_parent {
            open_or_create_trusted_directory_chain(parent)
        } else {
            open_trusted_directory_chain(parent)
        }
        .map_err(trust_error)?;
        directory.validate_private_security().map_err(trust_error)?;
        let resolved = directory.resolved_path().join(target_name);
        Ok(Self {
            target_name: target_name.to_os_string(),
            directory: Arc::new(directory),
            resolved,
        })
    }
}

pub(super) fn trust_error(source: netdiag_platform::DirectoryTrustError) -> NetdiagError {
    NetdiagError::FilesystemTrust {
        context: "atomic file target parent",
        source,
    }
}
