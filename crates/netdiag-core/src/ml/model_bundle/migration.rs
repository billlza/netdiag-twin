use super::layout::{BundlePaths, resolve_bundle_paths, validate_generation_name};
use super::loading::{
    load_snapshot_from_paths, read_model, read_model_manifest_bytes, read_required_file,
    sha256_bytes,
};
use super::publication::MAX_GENERATION_ENTRIES;
use super::{MAX_MODEL_FILE_BYTES, MAX_MODEL_MANIFEST_BYTES, with_model_bundle_lock};
use crate::error::{IoContext, NetdiagError, Result};
use crate::ml::{
    MODEL_FILE_NAME, MODEL_GENERATIONS_DIR_NAME, MODEL_MANIFEST_FILE_NAME, MODEL_MANIFEST_SCHEMA,
    MODEL_PROMOTION_GATE_FILE_NAME, ModelManifest, RustMlModel, validate_model_manifest,
    validate_model_manifest_payload,
};
use crate::storage::{PathStatus, path_status, typed_json};
use std::fs;
use std::path::Path;
use std::sync::Arc;

const LEGACY_MODEL_MANIFEST_SCHEMA: &str = "netdiag-model-manifest/v1";

pub(super) struct PublicationSource {
    pub(super) model: RustMlModel,
    pub(super) manifest: ModelManifest,
    pub(super) model_file_bytes: Arc<[u8]>,
    pub(super) generation: Option<String>,
}

pub(in crate::ml) fn validate_for_artifact_root_migration(model_dir: &Path) -> Result<bool> {
    with_model_bundle_lock(model_dir, || {
        let Some(paths) = resolve_bundle_paths(model_dir)? else {
            return validate_empty_model_directory(model_dir).map(|()| false);
        };
        load_for_writer(&paths).map(|_| true)
    })
}

pub(super) fn load_for_writer(paths: &BundlePaths) -> Result<PublicationSource> {
    if paths.generation.is_some() {
        return load_snapshot_from_paths(paths).map(PublicationSource::from);
    }
    load_flat_snapshot_for_writer(paths)
}

impl From<super::ModelBundleSnapshot> for PublicationSource {
    fn from(snapshot: super::ModelBundleSnapshot) -> Self {
        Self {
            model: snapshot.model,
            manifest: snapshot.manifest,
            model_file_bytes: snapshot.model_file_bytes,
            generation: snapshot.generation,
        }
    }
}

fn load_flat_snapshot_for_writer(paths: &BundlePaths) -> Result<PublicationSource> {
    paths.validate()?;
    let result = (|| {
        let model_bytes =
            read_required_file(&paths.model_path, MAX_MODEL_FILE_BYTES, "legacy model file")?;
        let manifest_bytes = read_required_file(
            &paths.manifest_path,
            MAX_MODEL_MANIFEST_BYTES,
            "legacy model manifest",
        )?;
        let model = read_model(&paths.model_path, &model_bytes)?;
        let mut manifest = read_model_manifest_bytes(&paths.manifest_path, &manifest_bytes)?;
        let model_hash = sha256_bytes(&model_bytes);
        match manifest.schema_version.as_str() {
            MODEL_MANIFEST_SCHEMA => {
                validate_model_manifest(&manifest, &model, &model_hash)?;
            }
            LEGACY_MODEL_MANIFEST_SCHEMA => {
                validate_exact_v1_layout(paths.root_path())?;
                if !manifest.model_file_hash_sha256.is_empty() {
                    return Err(NetdiagError::Ml(
                        "legacy v1 model manifest unexpectedly contains a model hash".to_string(),
                    ));
                }
                validate_model_manifest_payload(&manifest, &model)?;
                manifest.schema_version = MODEL_MANIFEST_SCHEMA.to_string();
                manifest.model_file_hash_sha256 = model_hash.clone();
                validate_model_manifest(&manifest, &model, &model_hash)?;
            }
            _ => {
                return Err(NetdiagError::Ml(format!(
                    "unsupported model manifest schema {}; expected {MODEL_MANIFEST_SCHEMA} or an exact {LEGACY_MODEL_MANIFEST_SCHEMA} writer-migration source",
                    manifest.schema_version
                )));
            }
        }
        Ok(PublicationSource {
            model,
            manifest,
            model_file_bytes: Arc::from(model_bytes),
            generation: None,
        })
    })();
    paths.finish(result)
}

fn validate_exact_v1_layout(model_dir: &Path) -> Result<()> {
    for entry in fs::read_dir(model_dir).with_path(model_dir)? {
        let entry = entry.with_path(model_dir)?;
        let name = entry.file_name().into_string().map_err(|_| {
            NetdiagError::Ml(format!(
                "legacy v1 model bundle contains a non-UTF-8 entry: {}",
                entry.path().display()
            ))
        })?;
        match name.as_str() {
            MODEL_FILE_NAME | MODEL_MANIFEST_FILE_NAME => require_status(
                &entry.path(),
                PathStatus::RegularFile,
                "legacy v1 model file",
            )?,
            MODEL_PROMOTION_GATE_FILE_NAME => validate_promotion_gate(&entry.path())?,
            MODEL_GENERATIONS_DIR_NAME => validate_recovery_generations(&entry.path())?,
            _ => {
                return Err(NetdiagError::Ml(format!(
                    "legacy v1 model bundle contains an unsupported entry: {}",
                    entry.path().display()
                )));
            }
        }
    }
    Ok(())
}

fn validate_promotion_gate(path: &Path) -> Result<()> {
    require_status(path, PathStatus::RegularFile, "legacy model promotion gate")?;
    typed_json::read_required_stable_json_bounded::<serde_json::Value>(
        path,
        typed_json::MAX_GENERIC_JSON_BYTES,
        "legacy model promotion gate",
    )
    .map(drop)
}

fn validate_recovery_generations(path: &Path) -> Result<()> {
    require_status(
        path,
        PathStatus::Directory,
        "legacy model migration recovery directory",
    )?;
    for (entries, entry) in fs::read_dir(path).with_path(path)?.enumerate() {
        if entries == MAX_GENERATION_ENTRIES {
            return Err(NetdiagError::Ml(format!(
                "legacy model migration recovery directory exceeds the strict {MAX_GENERATION_ENTRIES} entry bound"
            )));
        }
        let entry = entry.with_path(path)?;
        let name = entry.file_name().into_string().map_err(|_| {
            NetdiagError::Ml(format!(
                "legacy model migration recovery entry is not valid UTF-8: {}",
                entry.path().display()
            ))
        })?;
        validate_generation_name(&name)?;
        require_status(
            &entry.path(),
            PathStatus::Directory,
            "legacy model migration recovery generation",
        )?;
    }
    Ok(())
}

fn validate_empty_model_directory(model_dir: &Path) -> Result<()> {
    let mut entries = fs::read_dir(model_dir).with_path(model_dir)?;
    if let Some(entry) = entries.next() {
        let entry = entry.with_path(model_dir)?;
        return Err(NetdiagError::Ml(format!(
            "model directory has no complete bundle but contains an unsupported entry: {}",
            entry.path().display()
        )));
    }
    Ok(())
}

fn require_status(path: &Path, expected: PathStatus, description: &str) -> Result<()> {
    if path_status(path)? != expected {
        return Err(NetdiagError::Ml(format!(
            "{description} has an invalid filesystem type at {}",
            path.display()
        )));
    }
    Ok(())
}
