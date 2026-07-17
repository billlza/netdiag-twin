use crate::atomic_file::error::{not_published, published_uncertain};
use crate::{AtomicPublicationError, TrustedDirectory};
use rustix::fs::{AtFlags, RenameFlags, renameat_with, unlinkat};
use std::ffi::OsStr;
use std::io;

mod identity;
mod removal;
use identity::verify_directory_entry_identity;

pub(super) fn ensure_supported() -> Result<(), AtomicPublicationError> {
    Ok(())
}

pub(super) fn publish_noclobber(
    parent: &TrustedDirectory,
    staged: &TrustedDirectory,
    source: &OsStr,
    target: &OsStr,
) -> Result<(), AtomicPublicationError> {
    publish_noclobber_with(parent, staged, source, target, || {
        parent.as_file().sync_all()
    })
}

fn publish_noclobber_with(
    parent: &TrustedDirectory,
    staged: &TrustedDirectory,
    source: &OsStr,
    target: &OsStr,
    sync_parent: impl FnOnce() -> io::Result<()>,
) -> Result<(), AtomicPublicationError> {
    verify_source_identity(parent, staged, source)?;
    staged.as_file().sync_all().map_err(not_published)?;
    renameat_with(
        parent.as_file(),
        source,
        parent.as_file(),
        target,
        RenameFlags::NOREPLACE,
    )
    .map_err(io::Error::from)
    .map_err(not_published)?;
    sync_parent().map_err(published_uncertain)
}

fn verify_source_identity(
    parent: &TrustedDirectory,
    staged: &TrustedDirectory,
    source: &OsStr,
) -> Result<(), AtomicPublicationError> {
    verify_directory_entry_identity(parent.as_file(), staged.as_file(), source)
        .map_err(not_published)
}

pub(super) fn remove(parent: &TrustedDirectory, name: &OsStr) -> io::Result<()> {
    unlinkat(parent.as_file(), name, AtFlags::REMOVEDIR).map_err(Into::into)
}

pub(super) fn remove_tree(
    parent: &TrustedDirectory,
    staged: &TrustedDirectory,
    name: &OsStr,
) -> io::Result<()> {
    removal::remove(parent, staged, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_new_private_trusted_subdirectory, open_trusted_directory_chain};

    #[test]
    fn parent_sync_failure_reports_published_but_uncertain() {
        let root = tempfile::tempdir().expect("temporary root");
        let parent = open_trusted_directory_chain(root.path()).expect("trusted parent");
        let staged = create_new_private_trusted_subdirectory(&parent, OsStr::new("stage"))
            .expect("private stage");

        let error = publish_noclobber_with(
            &parent,
            &staged,
            OsStr::new("stage"),
            OsStr::new("run"),
            || Err(io::Error::other("injected run parent sync failure")),
        )
        .expect_err("parent sync failure");

        assert_eq!(
            error.state(),
            crate::AtomicPublicationState::PublishedButDurabilityUncertain
        );
        assert_eq!(
            error.primary_io_error().to_string(),
            "injected run parent sync failure"
        );
        assert!(root.path().join("run").is_dir());
        assert!(!root.path().join("stage").exists());
    }
}
