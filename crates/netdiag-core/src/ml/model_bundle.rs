mod layout;
mod loading;
mod migration;
mod publication;
mod trust;

#[cfg(test)]
mod tests;

use self::layout::resolve_bundle_paths;
use self::loading::load_snapshot_from_paths;
use self::trust::TrustedModelDirectory;
use super::{
    MODEL_PROMOTION_GATE_FILE_NAME, ModelBundleIdentity, ModelLoadPolicy, ModelManifest,
    RustMlModel, synthetic_model_bundle,
};
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::{remove_file_durably, with_exclusive_file_lock};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(super) use migration::validate_for_artifact_root_migration;

const MAX_CURRENT_DESCRIPTOR_BYTES: u64 = 4 * 1024;
const MAX_MODEL_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MODEL_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;

/// Immutable model and manifest bytes resolved from one `current.json`
/// descriptor (or, during migration only, one complete legacy v2 bundle).
#[derive(Debug, Clone)]
pub(crate) struct ModelBundleSnapshot {
    pub(crate) model: RustMlModel,
    pub(crate) manifest: ModelManifest,
    pub(crate) model_file_hash_sha256: String,
    pub(crate) model_manifest_hash_sha256: String,
    pub(crate) manifest_path: PathBuf,
    pub(crate) generation: Option<String>,
    model_file_bytes: Arc<[u8]>,
}

impl ModelBundleSnapshot {
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.model_file_hash_sha256 == other.model_file_hash_sha256
            && self.model_manifest_hash_sha256 == other.model_manifest_hash_sha256
    }

    pub(crate) fn identity(&self) -> ModelBundleIdentity {
        ModelBundleIdentity {
            manifest: self.manifest.clone(),
            model_file_hash_sha256: self.model_file_hash_sha256.clone(),
            model_manifest_hash_sha256: self.model_manifest_hash_sha256.clone(),
            generation: self.generation.clone(),
        }
    }
}

thread_local! {
    static HELD_MODEL_BUNDLE_LOCKS: RefCell<BTreeMap<PathBuf, usize>> =
        const { RefCell::new(BTreeMap::new()) };
}

struct ModelBundleLockGuard {
    canonical_model_dir: PathBuf,
}

impl Drop for ModelBundleLockGuard {
    fn drop(&mut self) {
        HELD_MODEL_BUNDLE_LOCKS.with(|held| {
            let mut held = held.borrow_mut();
            if let Some(depth) = held.get_mut(&self.canonical_model_dir) {
                if *depth == 1 {
                    held.remove(&self.canonical_model_dir);
                } else {
                    *depth -= 1;
                }
            }
        });
    }
}

pub(crate) fn with_model_bundle_lock<T>(
    model_dir: &Path,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let canonical_model_dir = canonical_model_dir_for_lock(model_dir)?;
    let reentrant = HELD_MODEL_BUNDLE_LOCKS.with(|held| {
        let mut held = held.borrow_mut();
        let depth = held.entry(canonical_model_dir.clone()).or_default();
        let reentrant = *depth > 0;
        *depth += 1;
        reentrant
    });
    let _guard = ModelBundleLockGuard {
        canonical_model_dir: canonical_model_dir.clone(),
    };
    if reentrant {
        action()
    } else {
        let file_name = canonical_model_dir.file_name().ok_or_else(|| {
            NetdiagError::Ml(format!(
                "model directory has no lockable final component: {}",
                canonical_model_dir.display()
            ))
        })?;
        let mut lock_name = std::ffi::OsString::from(".");
        lock_name.push(file_name);
        lock_name.push(".bundle");
        with_exclusive_file_lock(&canonical_model_dir.with_file_name(lock_name), action)
    }
}

fn canonical_model_dir_for_lock(model_dir: &Path) -> Result<PathBuf> {
    if model_dir.try_exists().with_path(model_dir)? {
        return model_dir.canonicalize().with_path(model_dir);
    }
    let parent = model_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = parent.canonicalize().with_path(parent)?;
    let file_name = model_dir.file_name().ok_or_else(|| {
        NetdiagError::Ml(format!(
            "model directory has no final component: {}",
            model_dir.display()
        ))
    })?;
    Ok(canonical_parent.join(file_name))
}

pub(crate) fn load_existing_model_bundle_snapshot(model_dir: &Path) -> Result<ModelBundleSnapshot> {
    load_model_bundle_snapshot_with_policy(model_dir, ModelLoadPolicy::ExistingOnly)
}

/// Invalidates promotion evidence while the caller holds the model bundle lock.
pub(crate) fn invalidate_model_promotion_gate_locked(model_dir: &Path) -> Result<()> {
    let bundle_root = TrustedModelDirectory::open(model_dir)?;
    bundle_root.validate()?;
    let result = remove_file_durably(&bundle_root.path().join(MODEL_PROMOTION_GATE_FILE_NAME));
    bundle_root.finish(result)
}

pub(crate) fn load_existing_model_bundle_snapshot_if_present(
    model_dir: &Path,
) -> Result<Option<ModelBundleSnapshot>> {
    with_model_bundle_lock(model_dir, || {
        resolve_bundle_paths(model_dir)?
            .map(|paths| load_snapshot_from_paths(&paths))
            .transpose()
    })
}

pub(crate) fn load_model_bundle_snapshot_with_policy(
    model_dir: &Path,
    load_policy: ModelLoadPolicy,
) -> Result<ModelBundleSnapshot> {
    if load_policy == ModelLoadPolicy::AllowSyntheticFallback
        && matches!(
            std::fs::symlink_metadata(model_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    {
        publication::prepare_parent_for_publication(model_dir)?;
    }
    with_model_bundle_lock(model_dir, || {
        load_model_bundle_snapshot_locked(model_dir, load_policy)
    })
}

fn load_model_bundle_snapshot_locked(
    model_dir: &Path,
    load_policy: ModelLoadPolicy,
) -> Result<ModelBundleSnapshot> {
    if let Some(paths) = resolve_bundle_paths(model_dir)? {
        return load_snapshot_from_paths(&paths);
    }
    if load_policy == ModelLoadPolicy::AllowSyntheticFallback {
        ensure_publication_supported(model_dir)?;
        let (model, manifest) = synthetic_model_bundle()?;
        publication::publish_locked(model_dir, &model, &manifest)?;
        let paths = resolve_bundle_paths(model_dir)?.ok_or_else(|| {
            NetdiagError::Ml(
                "published synthetic model bundle has no current descriptor".to_string(),
            )
        })?;
        return load_snapshot_from_paths(&paths);
    }
    Err(missing_existing_model_bundle(model_dir))
}

fn missing_existing_model_bundle(model_dir: &Path) -> NetdiagError {
    NetdiagError::Ml(format!(
        "model bundle is missing {} and the complete legacy pair {}/{}; train or explicitly rebuild the bundle",
        model_dir.join(super::MODEL_CURRENT_FILE_NAME).display(),
        super::MODEL_FILE_NAME,
        super::MODEL_MANIFEST_FILE_NAME,
    ))
}

pub(super) fn write_model_bundle(
    model_dir: &Path,
    model: &RustMlModel,
    manifest: &ModelManifest,
) -> Result<ModelManifest> {
    publication::prepare_parent_for_publication(model_dir)?;
    with_model_bundle_lock(model_dir, || {
        publication::publish_locked(model_dir, model, manifest)
    })
}

pub(super) fn ensure_publication_supported(model_dir: &Path) -> Result<()> {
    publication::ensure_publication_durability(model_dir)
}

pub(crate) fn replace_manifest_if_current(
    model_dir: &Path,
    expected_manifest_hash_sha256: &str,
    updated_manifest: &ModelManifest,
) -> Result<ModelBundleSnapshot> {
    with_model_bundle_lock(model_dir, || {
        let current = load_model_bundle_snapshot_locked(model_dir, ModelLoadPolicy::ExistingOnly)?;
        if current.model_manifest_hash_sha256 != expected_manifest_hash_sha256 {
            return Err(NetdiagError::Ml(
                "model bundle changed before the manifest update could be published; reload and retry"
                    .to_string(),
            ));
        }
        publication::publish_manifest_update_locked(model_dir, &current, updated_manifest)?;
        load_model_bundle_snapshot_locked(model_dir, ModelLoadPolicy::ExistingOnly)
    })
}
