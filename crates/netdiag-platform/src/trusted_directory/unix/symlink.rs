use super::{DirectoryTrustError, inspect};
use rustix::fs::readlinkat;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(super) fn read_trusted_system_symlink(
    parent: &File,
    parent_path: &Path,
    candidate: &Path,
    name: &OsStr,
    owner_uid: u32,
) -> Result<PathBuf, DirectoryTrustError> {
    if owner_uid != 0 {
        return Err(DirectoryTrustError::UntrustedSymlink {
            path: candidate.to_path_buf(),
            detail: format!("owner uid {owner_uid} is not root"),
        });
    }
    let parent_metadata = parent
        .metadata()
        .map_err(|source| inspect(parent_path, source))?;
    if parent_metadata.uid() != 0 || parent_metadata.mode() & 0o022 != 0 {
        return Err(DirectoryTrustError::UntrustedSymlink {
            path: candidate.to_path_buf(),
            detail: "root-owned symlink is not under a root-owned non-writable parent".to_string(),
        });
    }
    let target =
        readlinkat(parent, name, Vec::new()).map_err(|source| DirectoryTrustError::Inspect {
            path: candidate.to_path_buf(),
            source: source.into(),
        })?;
    Ok(PathBuf::from(OsString::from_vec(target.into_bytes())))
}
