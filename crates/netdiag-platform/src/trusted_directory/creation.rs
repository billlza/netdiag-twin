use super::{DirectoryTrustError, TrustedDirectory};
use std::ffi::OsStr;
use std::path::{Component, Path};

/// Creates one new owner-private child directory relative to a retained parent handle.
///
/// Unlike the open-or-create APIs, an existing entry is always a collision and is never reused.
pub fn create_new_private_trusted_subdirectory(
    parent: &TrustedDirectory,
    name: &OsStr,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    validate_child_name(parent, name)?;
    platform_create_child(parent, name)
}

fn validate_child_name(parent: &TrustedDirectory, name: &OsStr) -> Result<(), DirectoryTrustError> {
    let path = Path::new(name);
    let mut components = path.components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        return Ok(());
    }
    Err(DirectoryTrustError::InvalidComponent {
        path: parent.resolved_path().join(path),
    })
}

fn platform_create_child(
    parent: &TrustedDirectory,
    name: &OsStr,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    #[cfg(unix)]
    {
        super::unix::create_new_child(parent, name)
    }
    #[cfg(windows)]
    {
        Err(DirectoryTrustError::DurabilityUnavailable {
            path: parent.resolved_path().join(name),
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (parent, name);
        Err(DirectoryTrustError::UnsupportedPlatform)
    }
}
