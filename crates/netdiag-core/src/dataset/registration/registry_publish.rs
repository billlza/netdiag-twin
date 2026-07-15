use super::super::{DatasetManifest, DatasetRegistry, DatasetRegistryEntry};
use crate::storage::typed_json::MAX_DATASET_REGISTRY_ENTRIES;
use chrono::{DateTime, Utc};
use std::path::Path;

mod io;
mod preparation;
mod validation;
pub(super) use io::publish;
pub(super) use preparation::{PreparedRegistry, prepare};
pub(super) use validation::ensure_dataset_id_available;

const DATASET_REGISTRY_SCHEMA: &str = "netdiag-dataset-registry/v1";

pub(super) fn upsert(
    registry: &mut DatasetRegistry,
    manifest: &DatasetManifest,
    dataset_path: &Path,
    manifest_path: &Path,
    registered_at: DateTime<Utc>,
) {
    registry.schema = DATASET_REGISTRY_SCHEMA.to_string();
    registry.generated_at = registered_at;
    registry
        .datasets
        .retain(|entry| entry.hash_sha256 != manifest.hash_sha256);
    registry.datasets.insert(
        0,
        DatasetRegistryEntry {
            dataset_id: manifest.dataset_id.clone(),
            hash_sha256: manifest.hash_sha256.clone(),
            rows: manifest.rows,
            label_distribution: manifest.label_distribution.clone(),
            dataset_path: dataset_path.display().to_string(),
            manifest_path: manifest_path.display().to_string(),
            registered_at,
            source_runs: manifest.source_runs.clone(),
            scenario_ids: manifest.scenario_ids.clone(),
            operator: manifest.operator.clone(),
            label_policy: manifest.label_policy.clone(),
            min_rows_per_label: manifest.min_rows_per_label,
        },
    );
    registry.datasets.truncate(MAX_DATASET_REGISTRY_ENTRIES);
}
