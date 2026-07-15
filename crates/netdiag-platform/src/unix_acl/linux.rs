use super::UnixAclTrustError;
use rustix::fs::{flistxattr, fstatfs};
use std::os::fd::BorrowedFd;

const MAX_XATTR_LIST_BYTES: usize = 64 * 1024;
const EXT_SUPER_MAGIC: u32 = 0x0000_ef53;
const TMPFS_MAGIC: u32 = 0x0102_1994;
const XFS_SUPER_MAGIC: u32 = 0x5846_5342;
const OVERLAYFS_SUPER_MAGIC: u32 = 0x794c_7630;
const BTRFS_SUPER_MAGIC: u32 = 0x9123_683e;

pub(super) fn validate(fd: BorrowedFd<'_>) -> Result<(), UnixAclTrustError> {
    reject_unprovable_filesystem(fd)?;
    let mut names = vec![0_u8; MAX_XATTR_LIST_BYTES];
    let length = flistxattr(fd, &mut names).map_err(|source| {
        UnixAclTrustError::inspection("flistxattr", std::io::Error::from(source))
    })?;
    names.truncate(length);
    validate_xattr_names(&names)
}

fn reject_unprovable_filesystem(fd: BorrowedFd<'_>) -> Result<(), UnixAclTrustError> {
    let filesystem = fstatfs(fd)
        .map_err(|source| UnixAclTrustError::inspection("fstatfs", std::io::Error::from(source)))?;
    validate_filesystem_type(filesystem.f_type as u32)
}

fn validate_filesystem_type(filesystem_type: u32) -> Result<(), UnixAclTrustError> {
    if [
        EXT_SUPER_MAGIC,
        TMPFS_MAGIC,
        XFS_SUPER_MAGIC,
        OVERLAYFS_SUPER_MAGIC,
        BTRFS_SUPER_MAGIC,
    ]
    .contains(&filesystem_type)
    {
        return Ok(());
    }
    Err(UnixAclTrustError::UnsupportedAcl {
        detail: format!(
            "Linux filesystem type 0x{filesystem_type:08x} is not in the audited POSIX-mode ACL allowlist"
        ),
    })
}

fn validate_xattr_names(names: &[u8]) -> Result<(), UnixAclTrustError> {
    if names.is_empty() {
        return Ok(());
    }
    if names.last() != Some(&0) {
        return Err(UnixAclTrustError::UnsupportedAcl {
            detail: "extended-attribute name list was not NUL-terminated".to_string(),
        });
    }
    for name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let lower = name.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
        if lower == b"system.posix_acl_default" {
            return Err(UnixAclTrustError::UnsupportedAcl {
                detail: "directory carries an inheritable POSIX default ACL".to_string(),
            });
        }
        if lower.windows(4).any(|window| window == b"nfs4")
            || lower.windows(7).any(|window| window == b"richacl")
        {
            return Err(UnixAclTrustError::UnsupportedAcl {
                detail: format!(
                    "opened object carries unsupported rich ACL attribute {}",
                    String::from_utf8_lossy(name)
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_acl_is_accepted_but_default_and_rich_acls_fail_closed() {
        assert!(validate_xattr_names(b"system.posix_acl_access\0").is_ok());
        assert!(validate_xattr_names(b"system.posix_acl_default\0").is_err());
        assert!(validate_xattr_names(b"user.note\0system.nfs4_acl\0").is_err());
        assert!(validate_xattr_names(b"trusted.richacl\0").is_err());
        assert!(validate_xattr_names(b"unterminated").is_err());
    }

    #[test]
    fn only_audited_posix_mode_filesystems_are_accepted() {
        for filesystem_type in [
            EXT_SUPER_MAGIC,
            TMPFS_MAGIC,
            XFS_SUPER_MAGIC,
            OVERLAYFS_SUPER_MAGIC,
            BTRFS_SUPER_MAGIC,
        ] {
            validate_filesystem_type(filesystem_type).expect("audited local filesystem");
        }
        let nfs = validate_filesystem_type(0x0000_6969).expect_err("NFS must fail closed");
        assert!(nfs.to_string().contains("0x00006969"));
        assert!(validate_filesystem_type(0x6573_5546).is_err());
        assert!(validate_filesystem_type(0x00c3_6400).is_err());
        assert!(validate_filesystem_type(0x0102_1997).is_err());
    }
}
