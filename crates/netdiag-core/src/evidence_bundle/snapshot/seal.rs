#[cfg(unix)]
use crate::error::IoContext;
use crate::error::Result;
use std::path::Path;

#[cfg(unix)]
pub(super) fn seal(path: &Path) -> Result<()> {
    let mut permissions = std::fs::metadata(path).with_path(path)?.permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions).with_path(path)
}

#[cfg(not(unix))]
pub(super) fn seal(_path: &Path) -> Result<()> {
    // The writer is closed and only a read handle is retained. The Windows
    // read-only attribute is avoided because it prevents trusted-directory cleanup.
    Ok(())
}
