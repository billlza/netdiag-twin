use super::digest::hex_digest;
use crate::error::{IoContext, NetdiagError, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[cfg(test)]
mod tests;

pub(super) const MAX_REGISTRATION_DATASET_BYTES: u64 = crate::dataset::limits::MAX_INPUT_BYTES;

pub(super) fn read_and_hash(
    source_path: &Path,
    input: &mut File,
    consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<String> {
    read_and_hash_with_limit(source_path, input, MAX_REGISTRATION_DATASET_BYTES, consume)
}

fn read_and_hash_with_limit(
    source_path: &Path,
    input: &mut File,
    max_bytes: u64,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = max_bytes
            .checked_add(1)
            .and_then(|limit| limit.checked_sub(bytes))
            .ok_or_else(byte_count_overflow)?;
        let read_limit = usize::try_from(remaining.min(buffer.len() as u64)).map_err(|_| {
            NetdiagError::InvalidTrace(
                "dataset registration read limit could not be represented".to_string(),
            )
        })?;
        let read = input
            .read(&mut buffer[..read_limit])
            .with_path(source_path)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(byte_count_overflow)?;
        ensure_size_with_limit(source_path, bytes, max_bytes)?;
        consume(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    Ok(hex_digest(hasher.finalize()))
}

pub(super) fn ensure_size_within_limit(path: &Path, bytes: u64) -> Result<()> {
    ensure_size_with_limit(path, bytes, MAX_REGISTRATION_DATASET_BYTES)
}

fn ensure_size_with_limit(path: &Path, bytes: u64, max_bytes: u64) -> Result<()> {
    if bytes > max_bytes {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset registration source exceeds {max_bytes} bytes: {}",
            path.display()
        )));
    }
    Ok(())
}

fn byte_count_overflow() -> NetdiagError {
    NetdiagError::InvalidTrace("dataset registration byte count overflowed".to_string())
}
