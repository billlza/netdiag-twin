use crate::TrustedDirectory;
use std::path::{Path, PathBuf};

mod cleanup;
mod create;
mod error;
mod finish;
mod identity;

pub use error::TrustedTempDirectoryError;
pub use finish::TrustedTempDirectoryFinishError;

#[cfg(test)]
mod tests;

/// A private temporary directory bound to validated root and child handles.
///
/// The private mode or DACL trusts the current Unix UID or Windows SID and platform
/// administrators. It is not an isolation boundary between same-principal processes.
///
/// Call [`TrustedTempDirectory::close`] on every success and failure path so
/// cleanup errors remain observable.
#[must_use = "trusted temporary directories must be closed explicitly"]
#[derive(Debug)]
pub struct TrustedTempDirectory {
    path: PathBuf,
    root: Option<TrustedDirectory>,
    child: Option<identity::ChildDirectory>,
}

impl TrustedTempDirectory {
    pub fn create(prefix: &str) -> Result<Self, TrustedTempDirectoryError> {
        create::create(prefix)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn validate_identity(&self) -> Result<(), TrustedTempDirectoryError> {
        match (self.root.as_ref(), self.child.as_ref()) {
            (Some(root), Some(child)) => identity::validate(root, child, &self.path),
            _ => Err(TrustedTempDirectoryError::StateUnavailable {
                path: self.path.clone(),
            }),
        }
    }

    pub fn close(mut self) -> Result<(), TrustedTempDirectoryError> {
        let validation = self.validate_identity();
        self.release_handles();
        match validation {
            Ok(()) => cleanup::finish(self.path.clone()),
            Err(validation) => Err(TrustedTempDirectoryError::CleanupSkipped {
                path: self.path.clone(),
                validation: Box::new(validation),
            }),
        }
    }

    pub fn finish<T, E>(
        self,
        operation: Result<T, E>,
    ) -> Result<T, TrustedTempDirectoryFinishError<E>> {
        finish::finish(self, operation)
    }

    fn release_handles(&mut self) {
        let _ = self.child.take();
        let _ = self.root.take();
    }
}

impl Drop for TrustedTempDirectory {
    fn drop(&mut self) {
        let trusted = self.validate_identity().is_ok();
        self.release_handles();
        if trusted {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
