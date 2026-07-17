use super::{DirectoryTrustError, inspect, open_directory_at};
use rustix::fs::{AtFlags, FileType, statat};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

pub(super) fn open_nofollow_directory(
    parent: &File,
    name: &OsStr,
    candidate: &Path,
    symlink_detail: &'static str,
) -> Result<File, DirectoryTrustError> {
    open_directory_at(parent, name).map_err(|source| {
        classify_nofollow_directory_error(parent, name, candidate, source, symlink_detail)
    })
}

pub(super) fn classify_nofollow_directory_error(
    parent: &File,
    name: &OsStr,
    candidate: &Path,
    source: Errno,
    symlink_detail: &'static str,
) -> DirectoryTrustError {
    if !matches!(source, Errno::LOOP | Errno::NOTDIR) {
        return inspect(candidate, source);
    }
    let stat = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(source) => return inspect(candidate, source),
    };
    if FileType::from_raw_mode(stat.st_mode).is_symlink() {
        return DirectoryTrustError::UntrustedSymlink {
            path: candidate.to_path_buf(),
            detail: symlink_detail.to_string(),
        };
    }
    if source == Errno::NOTDIR {
        DirectoryTrustError::NotDirectory {
            path: candidate.to_path_buf(),
        }
    } else {
        inspect(candidate, source)
    }
}
