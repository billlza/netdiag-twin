use std::error::Error;
use std::fmt;
use std::io;
use std::os::fd::BorrowedFd;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(test)]
mod tests;

/// A failure to prove that an opened Unix object has no unsafe ACL grant.
#[derive(Debug)]
pub enum UnixAclTrustError {
    Inspection {
        operation: &'static str,
        source: io::Error,
    },
    UntrustedAllow {
        principal: String,
    },
    UnsupportedAcl {
        detail: String,
    },
    UnsupportedPlatform,
}

impl UnixAclTrustError {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn inspection(operation: &'static str, source: impl Into<io::Error>) -> Self {
        Self::Inspection {
            operation,
            source: source.into(),
        }
    }
}

impl fmt::Display for UnixAclTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inspection { operation, source } => {
                write!(
                    formatter,
                    "failed to inspect opened-object ACL ({operation}): {source}"
                )
            }
            Self::UntrustedAllow { principal } => write!(
                formatter,
                "ACL grants write, replacement, ownership, or ACL control to untrusted {principal}"
            ),
            Self::UnsupportedAcl { detail } => {
                write!(formatter, "ACL semantics cannot be proven safe: {detail}")
            }
            Self::UnsupportedPlatform => write!(
                formatter,
                "opened-object ACL trust validation is not implemented on this Unix platform"
            ),
        }
    }
}

impl Error for UnixAclTrustError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspection { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Validates ACL semantics using only the already-open object.
///
/// The caller must separately validate the owner and mode bits. On Linux,
/// POSIX access-ACL named-user/group grants are capped by the `st_mode` group
/// class. Inheritable default ACLs and richer ACL models are rejected because
/// their effect on future children cannot be proven from the current mode.
/// macOS extended ACL entries are inspected directly.
pub fn validate_fd_acl_trust(
    fd: BorrowedFd<'_>,
    effective_uid: u32,
) -> Result<(), UnixAclTrustError> {
    #[cfg(target_os = "linux")]
    {
        let _ = effective_uid;
        linux::validate(fd)
    }
    #[cfg(target_os = "macos")]
    {
        macos::validate(fd, effective_uid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (fd, effective_uid);
        Err(UnixAclTrustError::UnsupportedPlatform)
    }
}
