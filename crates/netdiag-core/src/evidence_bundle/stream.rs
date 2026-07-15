use crate::error::{IoContext, NetdiagError, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;

pub(super) const MAX_SOURCE_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

pub(super) struct StreamDigest {
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

pub(super) struct BundleBudget {
    bytes: u64,
}

impl BundleBudget {
    pub(super) fn new() -> Self {
        Self { bytes: 0 }
    }

    pub(super) fn validate_declared_source(&self, source: &Path, bytes: u64) -> Result<()> {
        Self::validate_single_source(source, bytes)?;
        let projected = self.bytes.checked_add(bytes).ok_or_else(|| {
            NetdiagError::InvalidTrace("evidence bundle byte count overflowed".to_string())
        })?;
        if projected > MAX_BUNDLE_BYTES {
            return Err(limit_error(
                source,
                "total uncompressed bundle",
                projected,
                MAX_BUNDLE_BYTES,
            ));
        }
        Ok(())
    }

    pub(super) fn validate_single_source(source: &Path, bytes: u64) -> Result<()> {
        if bytes > MAX_SOURCE_FILE_BYTES {
            return Err(limit_error(
                source,
                "single source file",
                bytes,
                MAX_SOURCE_FILE_BYTES,
            ));
        }
        Ok(())
    }

    pub(super) fn copy_source(
        &mut self,
        source: &mut impl Read,
        source_path: &Path,
        destination: &mut impl Write,
    ) -> Result<StreamDigest> {
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        let mut entry_bytes = 0_u64;
        let mut hasher = Sha256::new();
        loop {
            let read = source.read(&mut buffer).with_path(source_path)?;
            if read == 0 {
                break;
            }
            let read = read as u64;
            entry_bytes = entry_bytes.checked_add(read).ok_or_else(|| {
                NetdiagError::InvalidTrace("evidence source byte count overflowed".to_string())
            })?;
            self.validate_streamed_chunk(source_path, entry_bytes, read)?;
            destination
                .write_all(&buffer[..read as usize])
                .with_path(source_path)?;
            hasher.update(&buffer[..read as usize]);
            self.bytes += read;
        }
        Ok(StreamDigest {
            bytes: entry_bytes,
            sha256: finish_hash(hasher),
        })
    }

    pub(super) fn write_bytes(
        &mut self,
        bytes: &[u8],
        source_path: &Path,
        destination: &mut impl Write,
    ) -> Result<StreamDigest> {
        self.validate_declared_source(source_path, bytes.len() as u64)?;
        destination.write_all(bytes).with_path(source_path)?;
        self.bytes += bytes.len() as u64;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(StreamDigest {
            bytes: bytes.len() as u64,
            sha256: finish_hash(hasher),
        })
    }

    fn validate_streamed_chunk(
        &self,
        source: &Path,
        entry_bytes: u64,
        next_bytes: u64,
    ) -> Result<()> {
        if entry_bytes > MAX_SOURCE_FILE_BYTES {
            return Err(limit_error(
                source,
                "single source file",
                entry_bytes,
                MAX_SOURCE_FILE_BYTES,
            ));
        }
        let projected = self.bytes.checked_add(next_bytes).ok_or_else(|| {
            NetdiagError::InvalidTrace("evidence bundle byte count overflowed".to_string())
        })?;
        if projected > MAX_BUNDLE_BYTES {
            return Err(limit_error(
                source,
                "total uncompressed bundle",
                projected,
                MAX_BUNDLE_BYTES,
            ));
        }
        Ok(())
    }
}

fn finish_hash(hasher: Sha256) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn limit_error(source: &Path, kind: &str, actual: u64, limit: u64) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "evidence bundle {kind} byte limit exceeded for {}: {actual} > {limit}",
        source.display()
    ))
}

#[cfg(test)]
mod tests;
