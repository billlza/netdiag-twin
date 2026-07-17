use crate::error::{IoContext, NetdiagError, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use super::super::MAX_ADAPTER_FILE_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct BoundedDigest {
    pub(super) bytes: u64,
    sha256: [u8; 32],
}

pub(super) fn copy_and_hash_bounded(
    source: &mut File,
    source_path: &Path,
    target: &mut File,
    target_path: &Path,
) -> Result<BoundedDigest> {
    read_and_hash_bounded(source, source_path, |chunk| {
        target.write_all(chunk).with_path(target_path)
    })
}

pub(super) fn hash_bounded(source: &mut File, source_path: &Path) -> Result<BoundedDigest> {
    read_and_hash_bounded(source, source_path, |_| Ok(()))
}

fn read_and_hash_bounded(
    source: &mut File,
    source_path: &Path,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<BoundedDigest> {
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    while bytes <= MAX_ADAPTER_FILE_BYTES {
        let remaining = (MAX_ADAPTER_FILE_BYTES + 1 - bytes) as usize;
        let read_capacity = buffer.len().min(remaining);
        let read = source
            .read(&mut buffer[..read_capacity])
            .with_path(source_path)?;
        if read == 0 {
            break;
        }
        consume(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    if bytes > MAX_ADAPTER_FILE_BYTES {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter endpoint exceeded {MAX_ADAPTER_FILE_BYTES} bytes while it was being prepared: {}",
            source_path.display()
        )));
    }
    Ok(BoundedDigest {
        bytes,
        sha256: hasher.finalize().into(),
    })
}
