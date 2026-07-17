use super::error::{AtomicPublicationError, not_published, published_uncertain};
use crate::TrustedDirectory;
use rustix::fs::{AtFlags, linkat, renameat, unlinkat};
use std::ffi::OsStr;
use std::io;

mod durability;
mod open;
use durability::sync_parent;
pub(super) use open::{create, read_only as open_read_only};

pub(super) fn publish_replace(
    directory: &TrustedDirectory,
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    renameat(directory.as_file(), temporary, directory.as_file(), target)
        .map_err(io::Error::from)
        .map_err(not_published)?;
    sync_parent(directory)
}

pub(super) fn publish_noclobber(
    directory: &TrustedDirectory,
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    linkat(
        directory.as_file(),
        temporary,
        directory.as_file(),
        target,
        AtFlags::empty(),
    )
    .map_err(io::Error::from)
    .map_err(not_published)?;
    unlinkat(directory.as_file(), temporary, AtFlags::empty())
        .map_err(io::Error::from)
        .map_err(published_uncertain)?;
    sync_parent(directory)
}

pub(super) fn remove(directory: &TrustedDirectory, name: &OsStr) -> io::Result<()> {
    unlinkat(directory.as_file(), name, AtFlags::empty()).map_err(Into::into)
}
