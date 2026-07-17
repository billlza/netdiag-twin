use crate::atomic_file::error::not_published;
use crate::{AtomicPublicationError, TrustedDirectory};
use std::ffi::OsStr;

pub(in crate::atomic_directory) fn ensure_supported() -> Result<(), AtomicPublicationError> {
    Err(not_published(super::unsupported()))
}

pub(in crate::atomic_directory) fn publish_noclobber(
    _parent: &TrustedDirectory,
    _staged: &TrustedDirectory,
    _source: &OsStr,
    _target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    Err(not_published(super::unsupported()))
}
