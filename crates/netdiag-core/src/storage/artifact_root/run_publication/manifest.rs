use crate::error::{NetdiagError, Result};
use crate::models::RunManifest;

pub(super) fn parse(bytes: &[u8], kind: &str) -> Result<RunManifest> {
    crate::strict_json::from_slice(bytes).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "{kind} is invalid: {}",
            crate::strict_json::error_summary(&source)
        ))
    })
}
