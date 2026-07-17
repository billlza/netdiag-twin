use super::binding::{capture_confined_file, read_confined_modified_time};
use super::{FileScanIssue, MAX_SCANNED_FILE_BYTES, ScannedFile, file_too_large};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

impl ScannedFile {
    pub fn read_text(self) -> std::result::Result<String, FileScanIssue> {
        read_binding_text(&self.binding)
    }
}

pub(in crate::reliability) fn read_confined_text(
    root: &Path,
    path: &Path,
) -> std::result::Result<String, FileScanIssue> {
    let binding = capture_confined_file(root, path, MAX_SCANNED_FILE_BYTES)?;
    read_binding_text(&binding)
}

/// Reads one confined object's mtime through a verified no-follow handle.
///
/// The returned timestamp is only an ordering hint and is never content identity.
pub(in crate::reliability) fn confined_modified_time(
    root: &Path,
    path: &Path,
) -> std::result::Result<SystemTime, FileScanIssue> {
    read_confined_modified_time(root, path)
}

fn read_binding_text(
    binding: &super::binding::FileBinding,
) -> std::result::Result<String, FileScanIssue> {
    let (mut file, metadata) = binding.open_current()?;
    let max_bytes = binding.max_bytes();
    let read_limit = metadata.len().checked_add(1).ok_or_else(|| {
        FileScanIssue::malformed(
            binding.path(),
            "bound file length must be less than u64::MAX",
        )
    })?;
    let capacity = metadata.len().min(max_bytes).min(64 * 1024) as usize;
    let mut bytes = Vec::with_capacity(capacity);
    let mut hasher = Sha256::new();
    let mut reader = (&mut file).take(read_limit);
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| FileScanIssue::io(binding.path(), "read", error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        bytes.extend_from_slice(&buffer[..read]);
    }
    if bytes.len() as u64 > max_bytes {
        return Err(file_too_large(
            binding.path(),
            bytes.len() as u64,
            max_bytes,
        ));
    }
    if bytes.len() as u64 != metadata.len() {
        return Err(FileScanIssue::changed(binding.path(), binding.root_path()));
    }
    binding.verify_content_digest(hasher.finalize().into())?;
    binding.verify_opened(&file)?;
    String::from_utf8(bytes).map_err(|error| {
        FileScanIssue::malformed(
            binding.path(),
            format!("{} is not valid UTF-8: {error}", binding.path().display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reliability::ReliabilityReasonCode;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn opened_handle_never_reads_a_same_path_replacement() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("report.json");
        fs::write(&path, "{\"trusted\":true}").expect("trusted file");
        let binding = capture_confined_file(temp.path(), &path, MAX_SCANNED_FILE_BYTES)
            .expect("capture file");
        let (mut opened, _) = binding.open_current().expect("open captured file");

        fs::rename(&path, temp.path().join("original.json")).expect("move original");
        fs::write(&path, "{\"secret\":\"replacement\"}").expect("replacement");

        let mut body = String::new();
        opened
            .read_to_string(&mut body)
            .expect("read opened handle");
        assert_eq!(body, "{\"trusted\":true}");
        let issue = binding
            .verify_opened(&opened)
            .expect_err("path replacement must be reported");
        assert_eq!(issue.reason, ReliabilityReasonCode::PathEscapesArtifactRoot);
    }
}
