use crate::dataset::DatasetManifest;
use crate::error::Result;
use crate::storage::typed_json::{MAX_DATASET_MANIFEST_BYTES, PreparedJson, prepare_json_bounded};

pub(in crate::dataset::registration) fn prepare(
    manifest: &DatasetManifest,
) -> Result<PreparedJson> {
    prepare_json_bounded(manifest, MAX_DATASET_MANIFEST_BYTES, "dataset manifest")
}
