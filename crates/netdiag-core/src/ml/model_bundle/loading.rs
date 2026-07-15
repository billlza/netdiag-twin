use super::layout::BundlePaths;
use super::{MAX_MODEL_FILE_BYTES, MAX_MODEL_MANIFEST_BYTES, ModelBundleSnapshot};
use crate::error::{NetdiagError, Result};
use crate::ml::{ModelManifest, RustMlModel, validate_model_manifest, validate_model_structure};
use crate::storage::read_stable_regular_file_bounded;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

pub(super) fn load_snapshot_from_paths(paths: &BundlePaths) -> Result<ModelBundleSnapshot> {
    paths.validate()?;
    let result = (|| {
        let model_bytes = read_required_file(
            &paths.model_path,
            MAX_MODEL_FILE_BYTES,
            "model generation file",
        )?;
        let manifest_bytes = read_required_file(
            &paths.manifest_path,
            MAX_MODEL_MANIFEST_BYTES,
            "model generation manifest",
        )?;
        let model_file_hash_sha256 = sha256_bytes(&model_bytes);
        let model_manifest_hash_sha256 = sha256_bytes(&manifest_bytes);
        let model = read_model(&paths.model_path, &model_bytes)?;
        let manifest = read_model_manifest_bytes(&paths.manifest_path, &manifest_bytes)?;
        validate_model_manifest(&manifest, &model, &model_file_hash_sha256)?;
        Ok(ModelBundleSnapshot {
            model,
            manifest,
            model_file_hash_sha256,
            model_manifest_hash_sha256,
            manifest_path: paths.manifest_path.clone(),
            generation: paths.generation.clone(),
            model_file_bytes: Arc::from(model_bytes),
        })
    })();
    paths.finish(result)
}

pub(super) fn read_model(path: &Path, bytes: &[u8]) -> Result<RustMlModel> {
    let model = crate::strict_json::from_slice::<RustMlModel>(bytes).map_err(|error| {
        NetdiagError::Ml(format!(
            "stored model {} is not a valid Rust ML model: {}",
            path.display(),
            crate::strict_json::error_summary(&error)
        ))
    })?;
    validate_model_structure(&model)?;
    Ok(model)
}

pub(super) fn read_model_manifest_bytes(path: &Path, bytes: &[u8]) -> Result<ModelManifest> {
    crate::strict_json::from_slice(bytes).map_err(|error| {
        NetdiagError::Ml(format!(
            "model manifest {} is invalid: {}",
            path.display(),
            crate::strict_json::error_summary(&error)
        ))
    })
}

pub(super) fn read_required_file(path: &Path, max_bytes: u64, kind: &str) -> Result<Vec<u8>> {
    read_stable_regular_file_bounded(path, max_bytes)?
        .ok_or_else(|| NetdiagError::Ml(format!("{kind} is missing: {}", path.display())))
}

pub(super) fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
