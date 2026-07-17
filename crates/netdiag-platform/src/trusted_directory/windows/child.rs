use super::{DirectoryTrustError, TrustedDirectory, open};
use std::ffi::OsStr;

pub(in crate::trusted_directory) fn open_or_create(
    parent: &TrustedDirectory,
    name: &OsStr,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    parent.validate_identity()?;
    parent.validate_private_security()?;
    open(&parent.resolved_path.join(name), true)
}
