#[cfg(test)]
use super::DatasetRegistry;
use super::{DatasetRegisterOptions, DatasetRegistration};
#[cfg(test)]
use crate::error::NetdiagError;
use crate::error::Result;
#[cfg(test)]
use crate::storage::BoundAtomicFileTarget;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

mod artifact_root;
mod manifest;
mod registry_publish;
mod transaction;

pub(super) fn register(
    dataset: &Path,
    options: DatasetRegisterOptions,
) -> Result<DatasetRegistration> {
    transaction::run(dataset, options, || {}, || {}, registry_publish::publish)
}

#[cfg(test)]
pub(super) fn register_with_source_hooks(
    dataset: &Path,
    options: DatasetRegisterOptions,
    source_opened: impl FnOnce(),
    copy_completed: impl FnOnce(),
) -> Result<DatasetRegistration> {
    transaction::run(
        dataset,
        options,
        source_opened,
        copy_completed,
        registry_publish::publish,
    )
}

#[cfg(test)]
pub(super) fn register_with_registry_publisher<P>(
    dataset: &Path,
    options: DatasetRegisterOptions,
    publish_registry: P,
) -> Result<DatasetRegistration>
where
    P: FnOnce(&Path, &DatasetRegistry) -> Result<PathBuf>,
{
    transaction::run(
        dataset,
        options,
        || {},
        || {},
        move |target: &BoundAtomicFileTarget, registry, _prepared| {
            let published_path = publish_registry(target.resolved_path(), registry)?;
            if published_path != target.resolved_path() {
                return Err(NetdiagError::InvalidTrace(format!(
                    "dataset registry publisher reported an unexpected target: expected {}, got {}",
                    target.resolved_path().display(),
                    published_path.display()
                )));
            }
            Ok(())
        },
    )
}
