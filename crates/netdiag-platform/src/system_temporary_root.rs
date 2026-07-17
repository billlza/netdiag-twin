#[cfg(any(unix, windows))]
use std::path::Path;
use std::path::PathBuf;

mod error;
pub use error::SystemTemporaryRootError;
#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests;

/// Resolve the operating system's temporary root to an absolute canonical path.
///
/// This selects and resolves the platform root only. Callers must still open and
/// validate the returned path through the appropriate trusted-directory policy
/// before performing I/O beneath it.
pub fn system_temporary_root_path() -> Result<PathBuf, SystemTemporaryRootError> {
    #[cfg(unix)]
    {
        resolve(Path::new("/tmp"))
    }
    #[cfg(windows)]
    {
        let configured = windows::configured_path()?;
        resolve(&configured)
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(SystemTemporaryRootError::UnsupportedPlatform)
    }
}

#[cfg(any(unix, windows))]
fn resolve(configured: &Path) -> Result<PathBuf, SystemTemporaryRootError> {
    configured
        .canonicalize()
        .map_err(|source| SystemTemporaryRootError::Resolution {
            path: configured.to_path_buf(),
            source,
        })
}
