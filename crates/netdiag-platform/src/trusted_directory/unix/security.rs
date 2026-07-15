use super::DirectoryTrustError;
use crate::validate_fd_acl_trust;
use rustix::process::geteuid;
use std::fs::{File, Metadata};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DirectoryTrustPolicy {
    TrustedSystemPath,
    StrictNoFollow,
}

pub(super) fn validate_security(
    path: &Path,
    object: &File,
    metadata: &Metadata,
    policy: DirectoryTrustPolicy,
) -> Result<(), DirectoryTrustError> {
    let effective_uid = geteuid().as_raw();
    validate_owner(path, metadata.uid(), effective_uid)?;
    if !mode_is_trusted(metadata.mode(), metadata.uid(), policy) {
        return Err(DirectoryTrustError::Writable {
            path: path.to_path_buf(),
        });
    }
    validate_fd_acl_trust(object.as_fd(), effective_uid).map_err(|source| {
        DirectoryTrustError::UnixAcl {
            path: path.to_path_buf(),
            source,
        }
    })
}

pub(super) fn validate_owner(
    path: &Path,
    owner: u32,
    effective_uid: u32,
) -> Result<(), DirectoryTrustError> {
    if owner_is_trusted(owner, effective_uid) {
        return Ok(());
    }
    Err(DirectoryTrustError::UntrustedOwner {
        path: path.to_path_buf(),
        owner: format!("uid {owner}"),
    })
}

pub(super) fn owner_is_trusted(owner: u32, effective_uid: u32) -> bool {
    owner == 0 || owner == effective_uid
}

pub(super) fn mode_is_trusted(mode: u32, owner: u32, policy: DirectoryTrustPolicy) -> bool {
    mode & 0o022 == 0
        || (policy == DirectoryTrustPolicy::TrustedSystemPath && owner == 0 && mode & 0o1000 != 0)
}
