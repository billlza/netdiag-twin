use std::ffi::OsStr;
#[cfg(not(any(unix, windows)))]
use std::path::PathBuf;
use std::path::{Component, Path};

mod creation;
mod error;
#[cfg(unix)]
mod strict;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use strict::*;
#[cfg(unix)]
pub use unix::TrustedDirectory;
#[cfg(windows)]
pub use windows::TrustedDirectory;
#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub struct TrustedDirectory {
    resolved_path: PathBuf,
}

#[cfg(not(any(unix, windows)))]
impl TrustedDirectory {
    pub fn resolved_path(&self) -> &Path {
        &self.resolved_path
    }
}

pub use creation::create_new_private_trusted_subdirectory;
pub use error::{DirectoryPersistenceStage, DirectoryTrustError};

pub fn open_trusted_directory_chain(path: &Path) -> Result<TrustedDirectory, DirectoryTrustError> {
    platform_open(path, false, false)
}

pub fn open_or_create_trusted_directory_chain(
    path: &Path,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    platform_open(path, true, false)
}

pub fn open_or_create_durable_trusted_directory_chain(
    path: &Path,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    platform_open(path, true, true)
}

pub fn open_or_create_trusted_subdirectory(
    parent: &TrustedDirectory,
    name: &OsStr,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    let path = Path::new(name);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(DirectoryTrustError::InvalidComponent {
            path: parent.resolved_path().join(path),
        });
    }
    platform_open_child(parent, name, false)
}

pub fn open_or_create_durable_trusted_subdirectory(
    parent: &TrustedDirectory,
    name: &OsStr,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    let path = Path::new(name);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(DirectoryTrustError::InvalidComponent {
            path: parent.resolved_path().join(path),
        });
    }
    platform_open_child(parent, name, true)
}

fn platform_open_child(
    parent: &TrustedDirectory,
    name: &OsStr,
    durable: bool,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    #[cfg(unix)]
    {
        unix::open_or_create_child(parent, name, durable)
    }
    #[cfg(windows)]
    {
        if durable {
            return Err(DirectoryTrustError::DurabilityUnavailable {
                path: parent.resolved_path().join(name),
            });
        }
        windows::open_or_create_child(parent, name)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name, durable);
        Err(DirectoryTrustError::UnsupportedPlatform)
    }
}

fn platform_open(
    path: &Path,
    create_missing: bool,
    durable: bool,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    #[cfg(unix)]
    {
        if durable {
            unix::open_durable(path)
        } else {
            unix::open(path, create_missing)
        }
    }
    #[cfg(windows)]
    {
        if durable {
            return Err(DirectoryTrustError::DurabilityUnavailable {
                path: path.to_path_buf(),
            });
        }
        windows::open(path, create_missing)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, create_missing, durable);
        Err(DirectoryTrustError::UnsupportedPlatform)
    }
}
