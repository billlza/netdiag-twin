use super::super::layout::resolve_bundle_paths;
use super::super::loading::load_snapshot_from_paths;
use super::super::publication::publish_locked_with_bytes;
use super::super::{ensure_publication_supported, with_model_bundle_lock};
use super::load_for_writer;
use crate::error::{NetdiagError, Result};
use crate::ml::ModelBundleIdentity;
use crate::storage::save_json_atomic;
use std::path::Path;

/// Explicitly adopts a complete legacy model without retraining or changing its bytes.
///
/// The existing serialized publication protocol validates the legacy bundle,
/// preserves it until the new current descriptor is durable, and invalidates
/// promotion evidence bound to the old manifest. Training metadata is retained.
/// An already published, valid generation is returned without republishing it.
pub fn migrate_legacy_model_bundle(model_dir: &Path) -> Result<ModelBundleIdentity> {
    ensure_publication_supported(model_dir)?;
    with_model_bundle_lock(model_dir, || {
        let paths = resolve_bundle_paths(model_dir)?.ok_or_else(|| {
            NetdiagError::Ml("model migration requires an existing complete bundle".to_string())
        })?;
        if paths.generation.is_some() {
            return load_snapshot_from_paths(&paths).map(|snapshot| snapshot.identity());
        }
        let source = load_for_writer(&paths)?;
        publish_locked_with_bytes(
            model_dir,
            &source.model,
            Some(source.model_file_bytes.as_ref()),
            &source.manifest,
            |path, descriptor| save_json_atomic(path, descriptor).map(drop),
        )?;
        super::super::load_existing_model_bundle_snapshot(model_dir)
            .map(|snapshot| snapshot.identity())
    })
}
