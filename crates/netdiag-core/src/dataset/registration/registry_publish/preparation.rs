use super::{DATASET_REGISTRY_SCHEMA, DatasetRegistry};
use crate::error::{NetdiagError, Result};
use crate::storage::typed_json::{
    MAX_DATASET_REGISTRY_BYTES, MAX_DATASET_REGISTRY_ENTRIES, PreparedJson,
    ensure_collection_limit, prepare_json_bounded,
};

pub(in crate::dataset::registration) struct PreparedRegistry(PreparedJson);

impl PreparedRegistry {
    pub(super) fn into_json(self) -> PreparedJson {
        self.0
    }
}

pub(in crate::dataset::registration) fn prepare(
    registry: &DatasetRegistry,
) -> Result<PreparedRegistry> {
    if registry.schema != DATASET_REGISTRY_SCHEMA {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported dataset registry schema: {}",
            registry.schema
        )));
    }
    ensure_collection_limit(
        "dataset registry",
        registry.datasets.len(),
        MAX_DATASET_REGISTRY_ENTRIES,
    )?;
    prepare_json_bounded(registry, MAX_DATASET_REGISTRY_BYTES, "dataset registry")
        .map(PreparedRegistry)
}
