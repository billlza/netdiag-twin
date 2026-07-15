use crate::error::{NetdiagError, Result};

pub(super) fn ensure_representable_limit(max_bytes: u64) -> Result<u64> {
    max_bytes.checked_add(1).ok_or_else(|| {
        NetdiagError::InvalidTrace("stable file read limit must be less than u64::MAX".to_string())
    })
}
