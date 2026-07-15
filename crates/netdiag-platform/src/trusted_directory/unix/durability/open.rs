use super::super::{DirectoryTrustError, open_nofollow_directory};
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

pub(in crate::trusted_directory::unix) fn open_created_directory(
    parent: &File,
    name: &OsStr,
    candidate: &Path,
) -> Result<File, DirectoryTrustError> {
    open_nofollow_directory(
        parent,
        name,
        candidate,
        "newly created trusted directories cannot be symbolic links",
    )
}
