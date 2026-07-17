use crate::error::{NetdiagError, Result};
use crate::ml::{
    ModelBundleSnapshot, invalidate_model_promotion_gate_locked,
    load_existing_model_bundle_snapshot, with_model_bundle_lock,
};
use std::path::Path;

pub(super) fn load_promotion_snapshot(model_dir: &Path) -> Result<ModelBundleSnapshot> {
    with_model_bundle_lock(model_dir, || {
        load_existing_model_bundle_snapshot(model_dir)
            .map_err(|error| invalidate_after_current_failure(model_dir, error))
    })
}

pub(super) fn ensure_promotion_snapshot_current(
    model_dir: &Path,
    evaluated: &ModelBundleSnapshot,
) -> Result<()> {
    let current = load_promotion_snapshot(model_dir)?;
    if evaluated.same_identity(&current) {
        return Ok(());
    }
    Err(invalidate_after_current_failure(
        model_dir,
        NetdiagError::Ml(
            "model bundle changed while promotion gates were being evaluated; rerun benchmark and promotion"
                .to_string(),
        ),
    ))
}

fn invalidate_after_current_failure(model_dir: &Path, error: NetdiagError) -> NetdiagError {
    match invalidate_model_promotion_gate_locked(model_dir) {
        Ok(()) => error,
        Err(invalidation) => error.with_secondary_failure(
            "promotion model state failed",
            "durable invalidation of the stale promotion gate also failed",
            invalidation,
        ),
    }
}
