use super::super::ownership::{ArtifactRootCapability, OwnedArtifactRoot};
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::{StagedAtomicDirectory, with_artifact_root_capability};
use std::path::{Path, PathBuf};

pub(crate) fn finish<T>(
    capability: &ArtifactRootCapability,
    staged: StagedAtomicDirectory,
    operation: Result<T>,
    after_publish: impl FnOnce(&OwnedArtifactRoot, &T, &Path) -> Result<()>,
) -> Result<(T, PathBuf)> {
    let mut staged = Some(staged);
    let mut published_path = None;
    let result = with_artifact_root_capability(capability, |owned| {
        let staged = take_stage(&mut staged)?;
        let (value, path) = staged.finish(operation)?;
        published_path = Some(path.clone());
        after_publish(owned, &value, &path).map_err(|source| {
            NetdiagError::atomic_publish(&path, AtomicPublishPhase::Published, source)
        })?;
        Ok((value, path))
    });
    match result {
        Ok(result) => Ok(result),
        Err(error) => match staged {
            Some(staged) => Err(staged.abort(error)),
            None if error.atomic_publish_phase().is_none() => match published_path {
                Some(path) => Err(NetdiagError::atomic_publish(
                    path,
                    AtomicPublishPhase::Published,
                    error,
                )),
                None => Err(error),
            },
            None => Err(error),
        },
    }
}

pub(crate) fn discard<T>(
    capability: &ArtifactRootCapability,
    staged: StagedAtomicDirectory,
    operation: Result<T>,
) -> Result<T> {
    let mut staged = Some(staged);
    let mut operation = Some(operation);
    let result = with_artifact_root_capability(capability, |_| {
        take_stage(&mut staged)?.discard(operation.take().ok_or_else(consumed)?)
    });
    match (result, staged) {
        (Ok(value), _) => Ok(value),
        (Err(error), Some(staged)) => Err(staged.abort(error)),
        (Err(error), None) => Err(error),
    }
}

fn take_stage(staged: &mut Option<StagedAtomicDirectory>) -> Result<StagedAtomicDirectory> {
    staged.take().ok_or_else(consumed)
}

fn consumed() -> NetdiagError {
    NetdiagError::InvalidTrace("root-bound staged directory was already consumed".to_string())
}
