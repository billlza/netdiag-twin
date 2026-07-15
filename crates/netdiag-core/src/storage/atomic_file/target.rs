use crate::error::Result;
use netdiag_platform::TrustedDirectory;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

mod binding;
mod path;
use path::invalid_target;

#[derive(Clone)]
pub(crate) struct BoundAtomicFileTarget {
    directory: Arc<TrustedDirectory>,
    target_name: std::ffi::OsString,
    resolved: PathBuf,
}

impl BoundAtomicFileTarget {
    pub(crate) fn from_directory(
        directory: Arc<TrustedDirectory>,
        target_name: &OsStr,
    ) -> Result<Self> {
        let mut components = Path::new(target_name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(invalid_target(&directory.resolved_path().join(target_name)));
        }
        Ok(Self {
            resolved: directory.resolved_path().join(target_name),
            target_name: target_name.to_os_string(),
            directory,
        })
    }

    pub(crate) fn directory(&self) -> &TrustedDirectory {
        &self.directory
    }

    pub(crate) fn directory_arc(&self) -> Arc<TrustedDirectory> {
        Arc::clone(&self.directory)
    }

    pub(crate) fn shares_directory_arc(&self, directory: &Arc<TrustedDirectory>) -> bool {
        Arc::ptr_eq(&self.directory, directory)
    }

    pub(crate) fn target_name(&self) -> &OsStr {
        &self.target_name
    }

    pub(crate) fn resolved_path(&self) -> &Path {
        &self.resolved
    }

    pub(crate) fn parent_identity(&self) -> Result<[u8; 32]> {
        self.directory
            .coordination_identity()
            .map_err(binding::trust_error)
    }
}
