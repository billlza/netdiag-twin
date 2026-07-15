use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::same_file;
use netdiag_platform::TrustedDirectory;
use rustix::fs::{Mode, OFlags, openat};
use rustix::process::geteuid;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(in crate::storage::file_lock) fn validate_namespace(
    namespace: &TrustedDirectory,
) -> Result<()> {
    let metadata = namespace
        .as_file()
        .metadata()
        .with_path(namespace.resolved_path())?;
    if metadata.uid() != geteuid().as_raw() || metadata.mode() & 0o7777 != 0o700 {
        return Err(NetdiagError::InvalidTrace(format!(
            "coordination lock namespace must be owned by the effective uid with mode 0700: {}",
            namespace.resolved_path().display()
        )));
    }
    Ok(())
}

pub(in crate::storage::file_lock) fn open_coordination_file(
    namespace: &TrustedDirectory,
    path: &Path,
) -> Result<File> {
    let name = file_name(path)?;
    openat(
        namespace.as_file(),
        name,
        OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map(File::from)
    .map_err(|source| NetdiagError::Io {
        path: path.to_path_buf(),
        source: source.into(),
    })
}

pub(in crate::storage::file_lock) fn validate_coordination_file(
    namespace: &TrustedDirectory,
    path: &Path,
    file: &File,
) -> Result<()> {
    let opened = file.metadata().with_path(path)?;
    if !opened.is_file()
        || opened.uid() != geteuid().as_raw()
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "coordination lock must be a private 0600 regular file with one link: {}",
            path.display()
        )));
    }
    netdiag_platform::validate_fd_acl_trust(file.as_fd(), geteuid().as_raw()).map_err(
        |source| NetdiagError::CoordinationFileAcl {
            path: path.to_path_buf(),
            source,
        },
    )?;
    let current = openat(
        namespace.as_file(),
        file_name(path)?,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|source| NetdiagError::Io {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    let current_metadata = current.metadata().with_path(path)?;
    if !current_metadata.is_file() || !same_file(file, &current, path)? {
        return Err(NetdiagError::InvalidTrace(format!(
            "coordination lock identity changed: {}",
            path.display()
        )));
    }
    Ok(())
}

fn file_name(path: &Path) -> Result<&std::ffi::OsStr> {
    path.file_name().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "coordination lock path has no file name: {}",
            path.display()
        ))
    })
}
