use super::{ModelPromotionReport, model_state::ensure_promotion_snapshot_current};
use crate::error::Result;
use crate::ml::{MODEL_PROMOTION_GATE_FILE_NAME, ModelBundleSnapshot, with_model_bundle_lock};
use crate::storage::save_json_atomic;
use std::path::Path;

pub(super) fn persist_if_current(
    model_dir: &Path,
    evaluated_snapshot: &ModelBundleSnapshot,
    report: &ModelPromotionReport,
) -> Result<()> {
    with_model_bundle_lock(model_dir, || {
        ensure_promotion_snapshot_current(model_dir, evaluated_snapshot)?;
        save_json_atomic(model_dir.join(MODEL_PROMOTION_GATE_FILE_NAME), report)?;
        Ok(())
    })
}
