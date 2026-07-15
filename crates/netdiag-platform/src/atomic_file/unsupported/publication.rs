use super::super::error::{AtomicPublicationError, not_published};
use crate::TrustedDirectory;
use std::ffi::OsStr;

pub(in crate::atomic_file) fn publish_replace(
    _directory: &TrustedDirectory,
    _temporary: &OsStr,
    _target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    Err(not_published(super::unsupported()))
}

pub(in crate::atomic_file) fn publish_noclobber(
    _directory: &TrustedDirectory,
    _temporary: &OsStr,
    _target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    Err(not_published(super::unsupported()))
}
