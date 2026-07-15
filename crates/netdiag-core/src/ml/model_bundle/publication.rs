use super::layout::{CurrentDescriptor, new_generation_name, resolve_bundle_paths_in};
use super::loading::{read_model_manifest_bytes, read_required_file, sha256_bytes};
use super::migration::load_for_writer;
use super::trust::TrustedModelDirectory;
use super::{
    MAX_MODEL_FILE_BYTES, MAX_MODEL_MANIFEST_BYTES, invalidate_model_promotion_gate_locked,
};
use crate::error::{AtomicPublishPhase, IoContext, NetdiagError, Result};
use crate::ml::{
    MODEL_CURRENT_FILE_NAME, MODEL_FILE_NAME, MODEL_MANIFEST_FILE_NAME, ModelManifest, RustMlModel,
    validate_model_manifest, validate_model_manifest_metadata, validate_model_structure,
};
use crate::storage::typed_json::save_json_atomic_bounded;
use crate::storage::{save_json_atomic, write_file_atomically};
use std::ffi::OsStr;
use std::io::Write;
use std::path::Path;

pub(super) const MAX_GENERATION_ENTRIES: usize = 16;

pub(super) fn ensure_publication_durability(model_dir: &Path) -> Result<()> {
    durability::ensure_publication_durability(model_dir)
}

pub(super) fn publish_locked(
    model_dir: &Path,
    model: &RustMlModel,
    manifest: &ModelManifest,
) -> Result<ModelManifest> {
    publish_locked_with_bytes(model_dir, model, None, manifest, |path, descriptor| {
        save_json_atomic(path, descriptor).map(drop)
    })
}

pub(super) fn prepare_parent_for_publication(model_dir: &Path) -> Result<()> {
    ensure_publication_durability(model_dir)?;
    let parent = model_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    prepare_parent_directory_durably(parent)
}

#[cfg(test)]
pub(super) fn publish_locked_with(
    model_dir: &Path,
    model: &RustMlModel,
    manifest: &ModelManifest,
    publish_current: impl FnOnce(&Path, &CurrentDescriptor) -> Result<()>,
) -> Result<ModelManifest> {
    publish_locked_with_bytes(model_dir, model, None, manifest, publish_current)
}

fn publish_locked_with_bytes(
    model_dir: &Path,
    model: &RustMlModel,
    model_bytes: Option<&[u8]>,
    manifest: &ModelManifest,
    publish_current: impl FnOnce(&Path, &CurrentDescriptor) -> Result<()>,
) -> Result<ModelManifest> {
    ensure_publication_durability(model_dir)?;
    validate_model_structure(model)?;
    validate_model_manifest_metadata(manifest, model)?;
    let bundle_root = create_directory_durably(model_dir)?;
    bundle_root.validate()?;
    let current_path = bundle_root.path().join(MODEL_CURRENT_FILE_NAME);
    let mut current_published = false;
    let result = (|| {
        let existing_paths = resolve_bundle_paths_in(bundle_root.clone())?;
        let existing = existing_paths.as_ref().map(load_for_writer).transpose()?;
        let preserve_flat_source_until_commit = existing_paths
            .as_ref()
            .is_some_and(|paths| paths.generation.is_none());
        let generations = create_child_directory_durably(
            &bundle_root,
            OsStr::new(super::super::MODEL_GENERATIONS_DIR_NAME),
        )?;
        cleanup::noncurrent_generations(
            &generations,
            existing_paths
                .as_ref()
                .and_then(|paths| paths.generation.as_deref()),
        )?;
        if existing_paths
            .as_ref()
            .is_some_and(|paths| paths.generation.is_some())
        {
            cleanup::legacy_files(&bundle_root)?;
        }
        if let Some(legacy) = existing.filter(|snapshot| snapshot.generation.is_none()) {
            write_generation(
                &generations,
                &legacy.model,
                Some(legacy.model_file_bytes.as_ref()),
                &legacy.manifest,
            )?;
        }
        let (generation, bound_manifest) =
            write_generation(&generations, model, model_bytes, manifest)?;
        let descriptor = CurrentDescriptor::new(generation);
        if !preserve_flat_source_until_commit {
            invalidate_model_promotion_gate_locked(bundle_root.path())?;
        }
        bundle_root.validate()?;
        publish_current(&current_path, &descriptor)?;
        current_published = true;
        bundle_root.validate()?;
        if preserve_flat_source_until_commit {
            invalidate_model_promotion_gate_locked(bundle_root.path())?;
        }
        cleanup::legacy_files(&bundle_root)?;
        Ok(bound_manifest)
    })();
    let result = bundle_root.finish(result);
    if current_published {
        result.map_err(|source| NetdiagError::AtomicPublish {
            path: current_path,
            phase: AtomicPublishPhase::Published,
            source: Box::new(source),
        })
    } else {
        result
    }
}

fn write_generation(
    generations: &TrustedModelDirectory,
    model: &RustMlModel,
    model_bytes: Option<&[u8]>,
    manifest: &ModelManifest,
) -> Result<(String, ModelManifest)> {
    let generation = new_generation_name();
    let generation_dir = create_child_directory_durably(generations, OsStr::new(&generation))?;
    let write_result = write_generation_files(&generation_dir, model, model_bytes, manifest);
    generation_dir
        .finish(write_result)
        .map(|manifest| (generation, manifest))
        .map_err(|error| cleanup::failed_generation(&generation_dir, error))
}

fn write_generation_files(
    generation_dir: &TrustedModelDirectory,
    model: &RustMlModel,
    model_bytes: Option<&[u8]>,
    manifest: &ModelManifest,
) -> Result<ModelManifest> {
    generation_dir.validate()?;
    let result = (|| {
        let model_path = generation_dir.path().join(MODEL_FILE_NAME);
        if let Some(model_bytes) = model_bytes {
            write_exact_model_bytes(&model_path, model_bytes)?;
        } else {
            save_json_atomic_bounded(
                &model_path,
                model,
                MAX_MODEL_FILE_BYTES,
                "model generation file",
            )?;
        }
        let model_bytes = read_required_file(
            &model_path,
            MAX_MODEL_FILE_BYTES,
            "published model generation file",
        )?;
        let model_hash = sha256_bytes(&model_bytes);
        let mut bound_manifest = manifest.clone();
        bound_manifest.model_file_hash_sha256 = model_hash.clone();
        validate_model_manifest(&bound_manifest, model, &model_hash)?;
        let manifest_path = generation_dir.path().join(MODEL_MANIFEST_FILE_NAME);
        save_json_atomic_bounded(
            &manifest_path,
            &bound_manifest,
            MAX_MODEL_MANIFEST_BYTES,
            "model generation manifest",
        )?;
        let manifest_bytes = read_required_file(
            &manifest_path,
            MAX_MODEL_MANIFEST_BYTES,
            "published model generation manifest",
        )?;
        let persisted = read_model_manifest_bytes(&manifest_path, &manifest_bytes)?;
        validate_model_manifest(&persisted, model, &model_hash)?;
        Ok(bound_manifest)
    })();
    generation_dir.finish(result)
}

fn write_exact_model_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let byte_count = u64::try_from(bytes.len())
        .map_err(|_| NetdiagError::Ml("model generation file size overflow".to_string()))?;
    if byte_count > MAX_MODEL_FILE_BYTES {
        return Err(NetdiagError::Ml(format!(
            "model generation file exceeds the {MAX_MODEL_FILE_BYTES}-byte limit"
        )));
    }
    write_file_atomically(path, "json", |file| file.write_all(bytes).with_path(path)).map(drop)
}

mod cleanup;
mod durability;
mod manifest_update;

use self::durability::{
    create_child_directory_durably, create_directory_durably, prepare_parent_directory_durably,
};
pub(super) use manifest_update::publish_locked as publish_manifest_update_locked;
