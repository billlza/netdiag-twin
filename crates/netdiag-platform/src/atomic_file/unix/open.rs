use crate::{PrivateFileCreationError, TrustedDirectory};
use rustix::fs::{Mode, OFlags, openat};
use rustix::io::Errno;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io;

const PRIVATE_FILE_MODE: Mode = Mode::RUSR.union(Mode::WUSR);
const PRIVATE_FILE_FLAGS: OFlags = OFlags::RDWR
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(in crate::atomic_file) fn create(
    directory: &TrustedDirectory,
    name: &OsStr,
) -> Result<File, PrivateFileCreationError> {
    openat(
        directory.as_file(),
        name,
        PRIVATE_FILE_FLAGS,
        PRIVATE_FILE_MODE,
    )
    .map(File::from)
    .map_err(io::Error::from)
    .map_err(PrivateFileCreationError::from)
}

pub(in crate::atomic_file) fn read_only(
    directory: &TrustedDirectory,
    name: &OsStr,
) -> io::Result<File> {
    let file = match openat(
        directory.as_file(),
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(Errno::LOOP) => return Err(symlink_error()),
        Err(source) => return Err(source.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic file leaf is not a regular file",
        ));
    }
    Ok(file)
}

fn symlink_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        SymlinkLeafOpenError {
            source: Errno::LOOP.into(),
        },
    )
}

#[derive(Debug)]
struct SymlinkLeafOpenError {
    source: io::Error,
}

impl fmt::Display for SymlinkLeafOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "atomic file leaf is a symlink/reparse point: {}",
            self.source
        )
    }
}

impl Error for SymlinkLeafOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
