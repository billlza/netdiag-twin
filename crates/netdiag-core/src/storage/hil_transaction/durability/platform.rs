use crate::error::{NetdiagError, Result};

pub(crate) fn ensure_transaction_durability() -> Result<()> {
    validate_transaction_durability(cfg!(unix))
}

fn validate_transaction_durability(supported: bool) -> Result<()> {
    if supported {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(
            "HIL review is disabled on platforms such as Windows where this build cannot guarantee atomic overwrite rename plus parent-directory fsync; no transaction was started"
                .to_string(),
        ))
    }
}

#[cfg(test)]
pub(crate) fn reject_unsupported_durability_for_test() -> Result<()> {
    validate_transaction_durability(false)
}
