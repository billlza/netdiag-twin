use crate::error::{IoContext, NetdiagError, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::evidence_bundle) struct BoundedDigest {
    pub(in crate::evidence_bundle) bytes: u64,
    pub(in crate::evidence_bundle) sha256: [u8; 32],
}

impl BoundedDigest {
    pub(in crate::evidence_bundle) fn sha256_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(self.sha256.len() * 2);
        for byte in self.sha256 {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }
}

pub(super) fn copy_and_hash(
    source: &mut File,
    source_path: &Path,
    target: &mut File,
    target_path: &Path,
    max_file_bytes: u64,
    max_remaining_bytes: u64,
) -> Result<BoundedDigest> {
    read_and_hash(
        source,
        source_path,
        max_file_bytes,
        max_remaining_bytes,
        |chunk| target.write_all(chunk).with_path(target_path),
    )
}

pub(super) fn hash(
    source: &mut File,
    source_path: &Path,
    max_file_bytes: u64,
) -> Result<BoundedDigest> {
    read_and_hash(source, source_path, max_file_bytes, max_file_bytes, |_| {
        Ok(())
    })
}

fn read_and_hash(
    source: &mut File,
    source_path: &Path,
    max_file_bytes: u64,
    max_remaining_bytes: u64,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<BoundedDigest> {
    let effective_limit = max_file_bytes.min(max_remaining_bytes);
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; BUFFER_BYTES];
    while bytes <= effective_limit {
        let remaining = effective_limit + 1 - bytes;
        let capacity = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = source
            .read(&mut buffer[..capacity])
            .with_path(source_path)?;
        if read == 0 {
            break;
        }
        consume(&buffer[..read])?;
        hasher.update(&buffer[..read]);
        bytes += read as u64;
    }
    if bytes > max_file_bytes {
        return Err(limit_error(
            source_path,
            "single source file",
            bytes,
            max_file_bytes,
        ));
    }
    if bytes > max_remaining_bytes {
        return Err(limit_error(
            source_path,
            "total source snapshot",
            bytes,
            max_remaining_bytes,
        ));
    }
    Ok(BoundedDigest {
        bytes,
        sha256: hasher.finalize().into(),
    })
}

fn limit_error(source: &Path, kind: &str, actual: u64, limit: u64) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "evidence bundle {kind} byte limit exceeded for {}: {actual} > {limit}",
        source.display()
    ))
}
