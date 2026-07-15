use std::fs::{File, Metadata};
use std::io;
use std::path::Path;

/// Stable identity of one opened filesystem object.
///
/// The value is derived from the handle, never from a pathname. On Windows it
/// contains the volume serial number and the complete 128-bit `FILE_ID_INFO`
/// identifier; on Unix it contains the device and inode numbers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OpenedFileIdentity([u8; 32]);

pub fn opened_file_identity(file: &File) -> io::Result<OpenedFileIdentity> {
    platform_identity(file).map(OpenedFileIdentity)
}

pub fn same_open_file(left: &File, right: &File) -> io::Result<bool> {
    Ok(opened_file_identity(left)? == opened_file_identity(right)?)
}

pub fn open_file_read_only_no_follow(path: &Path) -> io::Result<File> {
    platform_open_file(path)
}

pub fn open_directory_read_only_no_follow(path: &Path) -> io::Result<File> {
    platform_open_directory(path)
}

#[cfg(windows)]
pub fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub fn metadata_is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn platform_identity(file: &File) -> io::Result<[u8; 32]> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    let mut identity = [0_u8; 32];
    identity[..8].copy_from_slice(b"unix-v1\0");
    identity[8..16].copy_from_slice(&metadata.dev().to_le_bytes());
    identity[16..24].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(identity)
}

#[cfg(windows)]
fn platform_identity(file: &File) -> io::Result<[u8; 32]> {
    crate::windows::identity_bytes(file)
}

#[cfg(unix)]
fn platform_open_file(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(Into::into)
}

#[cfg(windows)]
fn platform_open_file(path: &Path) -> io::Result<File> {
    crate::windows::open_windows_file_read_only_no_follow(path)
}

#[cfg(unix)]
fn platform_open_directory(path: &Path) -> io::Result<File> {
    use rustix::fs::{Mode, OFlags, open};

    open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(Into::into)
}

#[cfg(windows)]
fn platform_open_directory(path: &Path) -> io::Result<File> {
    crate::windows::open_windows_directory_read_only_no_follow(path)
}

#[cfg(not(any(unix, windows)))]
fn platform_identity(_file: &File) -> io::Result<[u8; 32]> {
    Err(unsupported())
}

#[cfg(not(any(unix, windows)))]
fn platform_open_file(_path: &Path) -> io::Result<File> {
    Err(unsupported())
}

#[cfg(not(any(unix, windows)))]
fn platform_open_directory(_path: &Path) -> io::Result<File> {
    Err(unsupported())
}

#[cfg(not(any(unix, windows)))]
fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "opened-file identity is unsupported on this platform",
    )
}

#[cfg(test)]
mod tests;
