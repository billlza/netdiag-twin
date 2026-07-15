use rustix::fs::{Mode, OFlags, openat};
use std::ffi::OsStr;
use std::fs::File;
use std::io;

pub(super) fn verify_directory_entry_identity(
    parent: &File,
    expected: &File,
    name: &OsStr,
) -> io::Result<()> {
    let source_directory = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)?;
    let source_metadata = File::from(source_directory).metadata()?;
    let expected_metadata = expected.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if source_metadata.dev() == expected_metadata.dev()
        && source_metadata.ino() == expected_metadata.ino()
    {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "staged directory is not the source entry bound to the retained parent",
    ))
}
