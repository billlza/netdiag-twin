use super::validation::{changed, oversized};
use crate::error::{IoContext, Result};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub(crate) fn read_stable_regular_file_bounded_with_checkpoint(
    path: &Path,
    max_bytes: u64,
    mut checkpoint: impl FnMut() -> Result<()>,
) -> Result<Option<Vec<u8>>> {
    super::read_stable_with(
        path,
        max_bytes,
        || {},
        |file, path, max_bytes, read_limit, declared_bytes| {
            read_pass(
                file,
                path,
                max_bytes,
                read_limit,
                declared_bytes,
                &mut checkpoint,
            )
        },
    )
}

fn read_pass(
    file: &mut File,
    path: &Path,
    max_bytes: u64,
    read_limit: u64,
    declared_bytes: u64,
    checkpoint: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let capacity = declared_bytes.min(max_bytes).min(64 * 1024) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    let mut reader = file.take(read_limit);
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        checkpoint()?;
        let read = reader.read(&mut chunk).with_path(path)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    if bytes.len() as u64 > max_bytes {
        return Err(oversized(path, max_bytes));
    }
    if bytes.len() as u64 != declared_bytes {
        return Err(changed(path));
    }
    Ok(bytes)
}
