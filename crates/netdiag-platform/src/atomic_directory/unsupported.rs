use crate::TrustedDirectory;
use std::ffi::OsStr;
use std::io;

mod publication;
pub(super) use publication::{ensure_supported, publish_noclobber};

pub(super) fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-clobber directory publication with durable parent synchronization is unavailable on this platform",
    )
}

pub(super) fn remove(_parent: &TrustedDirectory, _name: &OsStr) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn remove_tree(
    _parent: &TrustedDirectory,
    _staged: &TrustedDirectory,
    _name: &OsStr,
) -> io::Result<()> {
    Err(unsupported())
}
