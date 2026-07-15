use super::DatasetRegistry;
use super::preparation::PreparedRegistry;
use crate::error::Result;
use crate::storage::{BoundAtomicFileTarget, typed_json::save_prepared_json_atomic_to_bound};

pub(in crate::dataset::registration) fn publish(
    target: &BoundAtomicFileTarget,
    _registry: &DatasetRegistry,
    prepared: PreparedRegistry,
) -> Result<()> {
    save_prepared_json_atomic_to_bound(target, prepared.into_json())
}
