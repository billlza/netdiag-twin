use super::super::{TrustedDirectory, TrustedTempDirectoryError};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug)]
pub(in crate::trusted_temp_directory) struct ChildDirectory {
    directory: std::fs::File,
    device: u64,
    inode: u64,
}

pub(in crate::trusted_temp_directory) fn open(
    root: &TrustedDirectory,
    path: &Path,
) -> Result<ChildDirectory, TrustedTempDirectoryError> {
    let name = child_name(path)?;
    let (directory, metadata) = crate::open_strict_directory_at(root.as_file(), name, path)
        .map_err(|source| TrustedTempDirectoryError::Trust {
            context: "trusted temporary child open",
            path: path.to_path_buf(),
            source,
        })?;
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err(TrustedTempDirectoryError::ChildPolicy {
            path: path.to_path_buf(),
            detail: "Unix temporary child must be owned by the effective user with mode 0700",
        });
    }
    Ok(ChildDirectory {
        directory,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(in crate::trusted_temp_directory) fn validate(
    root: &TrustedDirectory,
    child: &ChildDirectory,
    path: &Path,
) -> Result<(), TrustedTempDirectoryError> {
    validate_root(root)?;
    crate::validate_opened_strict_directory(path, &child.directory).map_err(|source| {
        TrustedTempDirectoryError::Trust {
            context: "trusted temporary child handle validation",
            path: path.to_path_buf(),
            source,
        }
    })?;
    let (_, current) = crate::open_strict_directory_at(root.as_file(), child_name(path)?, path)
        .map_err(|source| TrustedTempDirectoryError::Trust {
            context: "trusted temporary child identity validation",
            path: path.to_path_buf(),
            source,
        })?;
    if current.dev() != child.device || current.ino() != child.inode {
        return Err(TrustedTempDirectoryError::IdentityChanged {
            path: path.to_path_buf(),
        });
    }
    validate_root(root)
}

fn child_name(path: &Path) -> Result<&std::ffi::OsStr, TrustedTempDirectoryError> {
    path.file_name()
        .ok_or_else(|| TrustedTempDirectoryError::ChildPolicy {
            path: path.to_path_buf(),
            detail: "temporary child path has no final component",
        })
}

fn validate_root(root: &TrustedDirectory) -> Result<(), TrustedTempDirectoryError> {
    root.validate_identity()
        .and_then(|()| root.validate_private_security())
        .map_err(|source| TrustedTempDirectoryError::Trust {
            context: "trusted temporary root identity validation",
            path: root.resolved_path().to_path_buf(),
            source,
        })
}
