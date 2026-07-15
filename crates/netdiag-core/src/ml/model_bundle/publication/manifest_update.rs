use super::super::ModelBundleSnapshot;
use super::super::loading::{read_model, sha256_bytes};
use super::publish_locked_with_bytes;
use crate::error::{NetdiagError, Result};
use crate::ml::{MODEL_FILE_NAME, ModelManifest};
use crate::storage::save_json_atomic;
use std::path::Path;

pub(in crate::ml::model_bundle) fn publish_locked(
    model_dir: &Path,
    current: &ModelBundleSnapshot,
    manifest: &ModelManifest,
) -> Result<ModelManifest> {
    let model_bytes = current.model_file_bytes.as_ref();
    let model_hash = sha256_bytes(model_bytes);
    if model_hash != current.model_file_hash_sha256 {
        return Err(NetdiagError::Ml(
            "validated model snapshot bytes no longer match its model hash".to_string(),
        ));
    }
    let model_path = current.manifest_path.with_file_name(MODEL_FILE_NAME);
    let model = read_model(&model_path, model_bytes)?;
    publish_locked_with_bytes(
        model_dir,
        &model,
        Some(model_bytes),
        manifest,
        |path, descriptor| save_json_atomic(path, descriptor).map(drop),
    )
}
