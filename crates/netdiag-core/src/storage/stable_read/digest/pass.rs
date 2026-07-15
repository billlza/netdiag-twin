use super::super::validation::{changed, oversized};
use crate::error::{IoContext, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub(super) fn hash_pass(
    file: &mut File,
    path: &Path,
    max_bytes: u64,
    read_limit: u64,
    declared_bytes: u64,
) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    let mut reader = file.take(read_limit);
    loop {
        let read = reader.read(&mut buffer).with_path(path)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| oversized(path, max_bytes))?;
        if bytes > max_bytes {
            return Err(oversized(path, max_bytes));
        }
        hasher.update(&buffer[..read]);
    }
    if bytes != declared_bytes {
        return Err(changed(path));
    }
    Ok(format!("{:x}", hasher.finalize()))
}
