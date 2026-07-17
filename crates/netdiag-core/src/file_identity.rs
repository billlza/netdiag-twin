use crate::error::{IoContext, Result};
use std::fs::File;
use std::path::Path;

pub(crate) use netdiag_platform::OpenedFileIdentity;

pub(crate) fn identity(file: &File, path: &Path) -> Result<OpenedFileIdentity> {
    netdiag_platform::opened_file_identity(file).with_path(path)
}

#[cfg(any(unix, test))]
pub(crate) fn same_file(left: &File, right: &File, path: &Path) -> Result<bool> {
    netdiag_platform::same_open_file(left, right).with_path(path)
}

pub(crate) fn open_file(path: &Path) -> Result<File> {
    netdiag_platform::open_file_read_only_no_follow(path).with_path(path)
}

pub(crate) fn open_directory(path: &Path) -> Result<File> {
    netdiag_platform::open_directory_read_only_no_follow(path).with_path(path)
}

#[cfg(test)]
mod tests;
