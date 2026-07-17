use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::storage::atomic_file::target::BoundAtomicFileTarget;
use crate::storage::atomic_file::temporary::{NoClobberDisposition, StagedAtomicFile};
use std::fs::File;

pub(crate) fn write_file_atomically_noclobber_or_existing_to_bound<T>(
    target: &BoundAtomicFileTarget,
    default_extension: &str,
    write: impl FnOnce(&mut File) -> Result<T>,
) -> Result<(NoClobberDisposition, T)> {
    let mut staged = StagedAtomicFile::reserve_in(
        target.directory_arc(),
        target.target_name(),
        default_extension,
    )
    .map_err(|source| {
        NetdiagError::atomic_publish(
            target.resolved_path().to_path_buf(),
            AtomicPublishPhase::NotPublished,
            source,
        )
    })?;
    let value = match write(staged.file_mut()) {
        Ok(value) => value,
        Err(source) => {
            let source = staged.abort(source);
            return Err(NetdiagError::atomic_publish(
                target.resolved_path().to_path_buf(),
                AtomicPublishPhase::NotPublished,
                source,
            ));
        }
    };
    staged
        .publish_noclobber(target)
        .map(|disposition| (disposition, value))
}
