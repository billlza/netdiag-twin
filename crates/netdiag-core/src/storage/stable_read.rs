use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::{identity, open_file};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub(crate) mod bound;
pub(crate) mod checkpoint;
mod digest;
mod limit;
mod validation;
use limit::ensure_representable_limit;
use validation::{changed, metadata_is_reparse_point, oversized, validate_regular};

pub(crate) use digest::{
    sha256_stable_regular_file_bounded, sha256_stable_regular_file_bounded_at,
};

/// Reads a small regular file twice from one no-follow handle.
///
/// Missing files are reported as `Ok(None)`. Every other inspection, identity,
/// size, or stability failure is explicit. The returned bytes are independent
/// of later path replacement.
pub fn read_stable_regular_file_bounded(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>> {
    read_with_hook(path, max_bytes, || {})
}

fn read_with_hook(
    path: &Path,
    max_bytes: u64,
    between_reads: impl FnOnce(),
) -> Result<Option<Vec<u8>>> {
    read_stable_with(path, max_bytes, between_reads, read_pass)
}

pub(super) fn read_stable_with<T: Eq>(
    path: &Path,
    max_bytes: u64,
    between_reads: impl FnOnce(),
    pass: impl FnMut(&mut File, &Path, u64, u64, u64) -> Result<T>,
) -> Result<Option<T>> {
    ensure_representable_limit(max_bytes)?;
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(NetdiagError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    validate_regular(path, &before, max_bytes)?;

    read_stable_opened_with(
        path,
        max_bytes,
        between_reads,
        || open_file(path).map(Some),
        pass,
    )
}

pub(super) fn read_stable_opened_with<T: Eq>(
    path: &Path,
    max_bytes: u64,
    between_reads: impl FnOnce(),
    mut open: impl FnMut() -> Result<Option<File>>,
    mut pass: impl FnMut(&mut File, &Path, u64, u64, u64) -> Result<T>,
) -> Result<Option<T>> {
    let read_limit = ensure_representable_limit(max_bytes)?;

    let Some(mut file) = open()? else {
        return Ok(None);
    };
    let opened = file.metadata().with_path(path)?;
    validate_regular(path, &opened, max_bytes)?;
    let opened_identity = identity(&file, path)?;
    let current_after_open = open()?.ok_or_else(|| changed(path))?;
    let current_after_open_metadata = current_after_open.metadata().with_path(path)?;
    validate_regular(path, &current_after_open_metadata, max_bytes)?;
    if identity(&current_after_open, path)? != opened_identity {
        return Err(changed(path));
    }
    let modified = opened.modified().with_path(path)?;

    let first = pass(&mut file, path, max_bytes, read_limit, opened.len())?;
    between_reads();
    file.seek(SeekFrom::Start(0)).with_path(path)?;
    let second = pass(&mut file, path, max_bytes, read_limit, opened.len())?;
    let final_opened = file.metadata().with_path(path)?;
    let final_path_file = open()?.ok_or_else(|| changed(path))?;
    let final_path = final_path_file.metadata().with_path(path)?;
    if first != second
        || final_opened.file_type().is_symlink()
        || metadata_is_reparse_point(&final_opened)
        || !final_opened.is_file()
        || validate_regular(path, &final_path, max_bytes).is_err()
        || identity(&final_path_file, path)? != opened_identity
        || opened.len() != final_opened.len()
        || opened.len() != final_path.len()
        || final_opened.modified().with_path(path)? != modified
        || final_path.modified().with_path(path)? != modified
    {
        return Err(changed(path));
    }
    Ok(Some(second))
}

pub(super) fn read_pass(
    file: &mut File,
    path: &Path,
    max_bytes: u64,
    read_limit: u64,
    declared_bytes: u64,
) -> Result<Vec<u8>> {
    let capacity = declared_bytes.min(max_bytes).min(64 * 1024) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .with_path(path)?;
    if bytes.len() as u64 > max_bytes {
        return Err(oversized(path, max_bytes));
    }
    if bytes.len() as u64 != declared_bytes {
        return Err(changed(path));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
