mod limits;
mod preparation;
mod read;
mod write;

pub(crate) use limits::{
    MAX_CONNECTOR_HEALTH_BYTES, MAX_DATASET_MANIFEST_BYTES, MAX_DATASET_REGISTRY_BYTES,
    MAX_DATASET_REGISTRY_ENTRIES, MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES, MAX_GENERIC_JSON_BYTES,
    MAX_LAB_ACCEPTANCE_BYTES, MAX_LAB_COMPARISON_BYTES, MAX_LAB_CONNECTOR_HEALTH_BYTES,
    MAX_LAB_RUN_INDEX_BYTES, MAX_LAB_RUN_INDEX_ENTRIES, MAX_ML_RESULT_BYTES, MAX_RUN_INDEX_BYTES,
    MAX_RUN_INDEX_ENTRIES, MAX_RUN_MANIFEST_ARTIFACTS, MAX_RUN_MANIFEST_BYTES,
    MAX_RUN_REPORT_BYTES, ensure_collection_limit, ensure_manifest_artifact_limit,
};
pub(crate) use preparation::{PreparedJson, prepare_json_bounded};
pub(crate) use read::{
    read_optional_stable_json_bounded, read_optional_stable_json_bounded_at,
    read_required_stable_json_bounded, read_required_stable_json_bounded_at,
};
pub(crate) use write::{save_json_atomic_bounded, save_prepared_json_atomic_to_bound};

#[cfg(test)]
mod tests;
