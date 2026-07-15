use crate::{PrivateFileCreationError, TrustedDirectory};
use std::ffi::OsStr;
use std::fs::File;
use std::io;

mod publication;
pub(super) use publication::{publish_noclobber, publish_replace};

pub(super) fn create(
    _directory: &TrustedDirectory,
    _name: &OsStr,
) -> Result<File, PrivateFileCreationError> {
    Err(unsupported().into())
}

pub(super) fn open_read_only(_: &TrustedDirectory, _: &OsStr) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "handle-relative file opening is unsupported on this platform",
    ))
}

pub(super) fn remove(_directory: &TrustedDirectory, _name: &OsStr) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "handle-bound atomic files are unsupported on this platform",
    )
}
