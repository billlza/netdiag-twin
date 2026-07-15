use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use std::path::Path;

pub(in crate::storage::file_lock) fn combine_publication_completion<T>(
    result: Result<T>,
    completion: Result<()>,
    target: &Path,
    completion_context: &'static str,
) -> Result<T> {
    match (result, completion) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(NetdiagError::AtomicPublish {
            path: target.to_path_buf(),
            phase: AtomicPublishPhase::Published,
            source: Box::new(error),
        }),
        (Err(primary), Err(secondary)) => Err(append_publication_error(
            primary,
            completion_context,
            secondary,
        )),
    }
}

fn append_publication_error(
    primary: NetdiagError,
    context: &'static str,
    secondary: NetdiagError,
) -> NetdiagError {
    primary.with_secondary_failure("locked update failed", context, secondary)
}
