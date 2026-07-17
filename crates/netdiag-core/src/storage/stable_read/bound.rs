use super::{read_pass, read_stable_opened_with};
use crate::error::{NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;
use std::fs::File;
use std::path::Path;

pub(crate) fn read_stable_regular_file_bounded_at(
    target: &BoundAtomicFileTarget,
    max_bytes: u64,
) -> Result<Option<Vec<u8>>> {
    read_stable_regular_file_bounded_at_with(target, max_bytes, read_pass)
}

pub(crate) fn read_stable_regular_file_bounded_at_with<T: Eq>(
    target: &BoundAtomicFileTarget,
    max_bytes: u64,
    pass: impl FnMut(&mut File, &Path, u64, u64, u64) -> Result<T>,
) -> Result<Option<T>> {
    read_with_hook(target, max_bytes, || {}, pass)
}

pub(super) fn read_with_hook<T: Eq>(
    target: &BoundAtomicFileTarget,
    max_bytes: u64,
    between_reads: impl FnOnce(),
    pass: impl FnMut(&mut File, &Path, u64, u64, u64) -> Result<T>,
) -> Result<Option<T>> {
    let path = target.resolved_path();
    read_stable_opened_with(
        path,
        max_bytes,
        between_reads,
        || match netdiag_platform::open_file_read_only_at(target.directory(), target.target_name())
        {
            Ok(file) => Ok(Some(file)),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(NetdiagError::Io {
                path: path.to_path_buf(),
                source,
            }),
        },
        pass,
    )
}
