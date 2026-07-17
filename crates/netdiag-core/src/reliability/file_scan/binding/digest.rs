use crate::reliability::file_scan::{FileScanIssue, file_too_large};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const DIGEST_BUFFER_BYTES: usize = 64 * 1024;

pub(super) fn hash_opened_file(
    file: &mut File,
    path: &Path,
    root: &Path,
    expected_bytes: u64,
    max_bytes: u64,
) -> Result<[u8; 32], FileScanIssue> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| FileScanIssue::io(path, "seek before content digest", error))?;
    let read_limit = expected_bytes.checked_add(1).ok_or_else(|| {
        FileScanIssue::malformed(path, "content digest length must be less than u64::MAX")
    })?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; DIGEST_BUFFER_BYTES];
    while bytes < read_limit {
        let remaining = (read_limit - bytes).min(buffer.len() as u64);
        let capacity = usize::try_from(remaining).map_err(|_| {
            FileScanIssue::malformed(path, "content digest buffer size is unsupported")
        })?;
        let read = file
            .read(&mut buffer[..capacity])
            .map_err(|error| FileScanIssue::io(path, "read content digest", error))?;
        if read == 0 {
            break;
        }
        bytes = bytes.checked_add(read as u64).ok_or_else(|| {
            FileScanIssue::malformed(path, "file content digest byte count overflowed")
        })?;
        if bytes > max_bytes {
            return Err(file_too_large(path, bytes, max_bytes));
        }
        hasher.update(&buffer[..read]);
    }
    if bytes != expected_bytes {
        return Err(FileScanIssue::changed(path, root));
    }
    Ok(hasher.finalize().into())
}
