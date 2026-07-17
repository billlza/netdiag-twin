use crate::{AtomicPublicationError, TrustedDirectory};
use std::ffi::OsStr;
use std::io;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use unix as platform;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use unsupported as platform;

/// Verifies that this target supports crash-aware, atomic no-clobber directory publication.
///
/// Callers use this before creating any publication artifacts so unsupported platforms fail
/// closed while the intended target is still conclusively unpublished.
pub fn ensure_directory_noclobber_publication_supported() -> Result<(), AtomicPublicationError> {
    platform::ensure_supported()
}

/// Atomically renames one retained child directory to a new name without replacing an existing
/// target, then persists the parent directory entry.
///
/// The source directory is synchronized before the rename. Both names are resolved relative to
/// `parent`; `source` must identify `staged` through that same retained parent handle.
pub fn publish_directory_noclobber_at(
    parent: &TrustedDirectory,
    staged: &TrustedDirectory,
    source: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    super::atomic_file::leaf::validate_publication_names(source, target)?;
    platform::publish_noclobber(parent, staged, source, target)
}

/// Removes an empty directory entry relative to a retained parent handle.
pub fn remove_directory_at(parent: &TrustedDirectory, name: &OsStr) -> io::Result<()> {
    super::atomic_file::leaf::validate_leaf(name)?;
    platform::remove(parent, name)
}

/// Recursively removes a retained child directory without following symbolic links.
///
/// The child name is resolved relative to `parent` and must still identify `staged`. Traversal is
/// handle-relative and bounded; failure to prove identity, stay within the cleanup budget, or
/// provide the required platform primitives is reported to the caller.
pub fn remove_directory_tree_at(
    parent: &TrustedDirectory,
    staged: &TrustedDirectory,
    name: &OsStr,
) -> io::Result<()> {
    super::atomic_file::leaf::validate_leaf(name)?;
    platform::remove_tree(parent, staged, name)
}

#[cfg(test)]
mod tests;
