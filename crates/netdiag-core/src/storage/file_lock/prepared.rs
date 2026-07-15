use super::errors::trust_error;
use super::key::{absolute_target, namespace_path, stripe_key};
use crate::error::{NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;
use netdiag_platform::{TrustedDirectory, open_or_create_trusted_directory_chain};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod namespace;
mod target_boundary;
mod validation;
mod view;

pub(super) struct PreparedLock {
    key: String,
    target: PathBuf,
    target_parent: Arc<TrustedDirectory>,
    namespace: TrustedDirectory,
    lock_path: PathBuf,
}

impl PreparedLock {
    pub(super) fn open(target: &Path) -> Result<Self> {
        Self::open_with_namespace(target, &namespace_path()?)
    }

    #[cfg(test)]
    pub(super) fn open_in_namespace(target: &Path, namespace: &Path) -> Result<Self> {
        Self::open_with_namespace(target, namespace)
    }

    fn open_with_namespace(target: &Path, namespace_path: &Path) -> Result<Self> {
        let target = absolute_target(target)?;
        let file_name = target.file_name().ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "coordination lock target has no final component: {}",
                target.display()
            ))
        })?;
        let parent = target.parent().ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "coordination lock target has no parent: {}",
                target.display()
            ))
        })?;
        let namespace = namespace::open(namespace_path)?;
        target_boundary::ensure_outside_namespace(parent, &namespace)?;
        let target_parent = open_or_create_trusted_directory_chain(parent).map_err(trust_error)?;
        target_parent
            .validate_private_security()
            .map_err(trust_error)?;
        let target = target_parent.resolved_path().join(file_name);
        Self::open_with_parent(target, Arc::new(target_parent), namespace)
    }

    pub(super) fn open_bound(target: &BoundAtomicFileTarget) -> Result<Self> {
        let namespace = namespace::open(&namespace_path()?)?;
        target_boundary::ensure_outside_namespace(target.directory().resolved_path(), &namespace)?;
        Self::open_with_parent(
            target.resolved_path().to_path_buf(),
            target.directory_arc(),
            namespace,
        )
    }

    fn open_with_parent(
        target: PathBuf,
        target_parent: Arc<TrustedDirectory>,
        namespace: TrustedDirectory,
    ) -> Result<Self> {
        let target_parent_identity = target_parent.coordination_identity().map_err(trust_error)?;
        let namespace_identity = namespace.coordination_identity().map_err(trust_error)?;
        if target_parent_identity == namespace_identity
            || target.starts_with(namespace.resolved_path())
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "coordination lock targets must not be inside the private lock namespace: {}",
                target.display()
            )));
        }
        let key = stripe_key(&target_parent_identity);
        let lock_path = namespace.resolved_path().join(format!("{key}.lock"));
        Ok(Self {
            key,
            target,
            target_parent,
            namespace,
            lock_path,
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        validation::validate(self)
    }

    pub(super) fn validate_lock_file(&self, file: &File) -> Result<()> {
        validation::validate_lock_file(self, file)
    }
}
