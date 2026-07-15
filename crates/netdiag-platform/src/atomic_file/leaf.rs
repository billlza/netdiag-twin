use std::ffi::OsStr;
use std::io;
use std::path::{Component, Path};

pub(crate) fn validate_leaf(name: &OsStr) -> io::Result<()> {
    let mut components = Path::new(name).components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "atomic file name must be one normal path component",
    ))
}

pub(crate) fn validate_publication_names(
    temporary: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    validate_leaf(temporary).map_err(not_published)?;
    validate_leaf(target).map_err(not_published)
}
use super::error::{AtomicPublicationError, not_published};
