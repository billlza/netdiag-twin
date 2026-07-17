use super::target_path::resolve_target_path;
use crate::error::{NetdiagError, Result};
use crate::storage::{BoundAtomicFileTarget, RunLocation};
use std::path::{Path, PathBuf};

mod protected;
mod reserved;
mod transaction;
pub(super) use protected::protected_target_set;

/// Lexically normalized output target validated independently from per-run input locks.
#[derive(Debug)]
pub(crate) struct SnapshotOutputTarget {
    artifact_root: PathBuf,
    resolved: PathBuf,
    protected: super::output_validation::ProtectedOutputScopes,
}

impl SnapshotOutputTarget {
    pub(crate) fn prepare(artifact_root: &Path, output: &Path) -> Result<Self> {
        let resolved = resolve_target_path(output)?;
        let anchor = resolve_target_path(&artifact_root.join(".netdiag-root-anchor"))?;
        let artifact_root = anchor
            .parent()
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(format!(
                    "artifact root has no parent boundary: {}",
                    artifact_root.display()
                ))
            })?
            .to_path_buf();
        reserved::ensure_outside_reserved_subtrees(&artifact_root, &resolved, output)?;
        let protected = [
            resolve_target_path(&artifact_root.join("run_index.json"))?,
            resolve_target_path(&artifact_root.join("lab_run_index.json"))?,
        ];
        super::output_validation::ensure_not_protected(&resolved, output, &protected, &[], None)?;
        let protected =
            super::output_validation::ProtectedOutputScopes::capture(&protected, &[], output)?;
        Ok(Self {
            artifact_root,
            resolved,
            protected,
        })
    }

    pub(crate) fn validate_for_run(&mut self, location: &RunLocation, run_id: &str) -> Result<()> {
        let targets = protected_target_set(location, run_id)?;
        super::output_validation::ensure_not_protected(
            &self.resolved,
            &self.resolved,
            &targets.files,
            &targets.directories,
            None,
        )?;
        self.protected
            .extend(super::output_validation::ProtectedOutputScopes::capture(
                &targets.files,
                &targets.directories,
                &self.resolved,
            )?);
        Ok(())
    }

    pub(crate) fn bind_for_publication(&self) -> Result<BoundAtomicFileTarget> {
        let bound = BoundAtomicFileTarget::bind(&self.resolved)?;
        reserved::ensure_outside_reserved_subtrees(
            &self.artifact_root,
            bound.resolved_path(),
            &self.resolved,
        )?;
        self.protected.validate_bound(&bound, &self.resolved)?;
        Ok(bound)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.resolved
    }
}
