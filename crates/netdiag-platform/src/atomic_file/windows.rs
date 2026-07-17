use super::error::{AtomicPublicationError, not_published};
use crate::TrustedDirectory;
use crate::opened_file_identity;
use std::ffi::OsStr;
use std::io;

mod classification;
mod open;
#[cfg(test)]
mod tests;
use classification::classify_failure;
pub(super) use open::{create, read_only as open_read_only};

pub(super) fn publish_replace(
    directory: &TrustedDirectory,
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    publish(directory, temporary, target, true)
}

pub(super) fn publish_noclobber(
    directory: &TrustedDirectory,
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    publish(directory, temporary, target, false)
}

pub(super) fn remove(directory: &TrustedDirectory, name: &OsStr) -> io::Result<()> {
    std::fs::remove_file(directory.resolved_path().join(name))
}

fn publish(
    directory: &TrustedDirectory,
    temporary: &OsStr,
    target: &OsStr,
    replace: bool,
) -> Result<(), AtomicPublicationError> {
    let temporary_path = directory.resolved_path().join(temporary);
    let target_path = directory.resolved_path().join(target);
    let source_file =
        crate::open_file_read_only_no_follow(&temporary_path).map_err(not_published)?;
    let expected = opened_file_identity(&source_file).map_err(not_published)?;
    let result = if replace {
        crate::replace_file_write_through(&temporary_path, &target_path)
    } else {
        crate::move_file_noreplace_write_through(&temporary_path, &target_path)
    };
    match result {
        Ok(()) => Ok(()),
        Err(source) => Err(classify_failure(
            directory,
            temporary,
            target,
            &source_file,
            expected,
            source,
        )),
    }
}
