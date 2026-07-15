use crate::error::{NetdiagError, Result};
use crate::pilot::{PilotManifest, PilotSourceKind};
use crate::resource_limits::MAX_TOTAL_SOURCE_EXECUTION_SECS as MAX_TOTAL_ADAPTER_EXECUTION_SECS;

pub(super) fn validate_total_execution_budget(manifest: &PilotManifest) -> Result<()> {
    let total_execution_secs = manifest
        .sources
        .iter()
        .filter(|source| source.kind == PilotSourceKind::AdapterSample)
        .try_fold(0_u64, |total, source| {
            source
                .collection
                .timeout_secs
                .checked_mul(2)
                .and_then(|source_budget| total.checked_add(source_budget))
        })
        .ok_or_else(|| {
            NetdiagError::InvalidTrace("pilot adapter execution budget overflowed".to_string())
        })?;
    if total_execution_secs > MAX_TOTAL_ADAPTER_EXECUTION_SECS {
        return Err(NetdiagError::InvalidTrace(format!(
            "pilot adapter preflight and collection budget {total_execution_secs}s exceeds {MAX_TOTAL_ADAPTER_EXECUTION_SECS}s"
        )));
    }
    Ok(())
}
