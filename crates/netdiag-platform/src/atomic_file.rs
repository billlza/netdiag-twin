use crate::{PrivateFileCreationError, TrustedDirectory};
use std::ffi::OsStr;
use std::fs::File;
use std::io;

pub(crate) mod error;
pub(crate) mod leaf;
#[cfg(test)]
mod tests;
#[cfg(unix)]
mod unix;
#[cfg(not(any(unix, windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

pub use error::{
    AtomicPublicationClassification, AtomicPublicationError, AtomicPublicationLocationObservation,
    AtomicPublicationState,
};
use leaf::{validate_leaf, validate_publication_names};

pub fn create_new_private_file_at(
    directory: &TrustedDirectory,
    name: &OsStr,
) -> Result<File, PrivateFileCreationError> {
    validate_leaf(name).map_err(PrivateFileCreationError::from)?;
    platform::create(directory, name)
}

pub fn open_file_read_only_at(directory: &TrustedDirectory, name: &OsStr) -> io::Result<File> {
    validate_leaf(name)?;
    platform::open_read_only(directory, name)
}

pub fn publish_file_replace_at(
    directory: &TrustedDirectory,
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    validate_publication_names(temporary, target)?;
    platform::publish_replace(directory, temporary, target)
}

pub fn publish_file_noclobber_at(
    directory: &TrustedDirectory,
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    validate_publication_names(temporary, target)?;
    platform::publish_noclobber(directory, temporary, target)
}

pub fn remove_file_at(directory: &TrustedDirectory, name: &OsStr) -> io::Result<()> {
    validate_leaf(name)?;
    platform::remove(directory, name)
}

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

#[cfg(not(any(unix, windows)))]
use unsupported as platform;
