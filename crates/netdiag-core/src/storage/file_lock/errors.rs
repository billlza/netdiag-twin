use crate::error::{NetdiagError, Result};

mod publication;
pub(super) use publication::combine_publication_completion;

pub(super) fn trust_error(source: netdiag_platform::DirectoryTrustError) -> NetdiagError {
    NetdiagError::FilesystemTrust {
        context: "coordination directory",
        source,
    }
}

pub(super) fn combine_action_and_identity<T>(action: Result<T>, identity: Result<()>) -> Result<T> {
    match (action, identity) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(action_error), Err(identity_error)) => Err(action_error.with_secondary_failure(
            "locked update failed",
            "coordination lock identity validation also failed",
            identity_error,
        )),
    }
}

pub(super) fn combine_with_unlock<T>(result: Result<T>, unlock: Result<()>) -> Result<T> {
    match (result, unlock) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(unlock_error)) => Err(primary.with_secondary_failure(
            "locked update failed",
            "lock release also failed",
            unlock_error,
        )),
    }
}
