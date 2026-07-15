use super::DirectoryTrustError;
use std::error::Error;
use std::fmt;

impl fmt::Display for DirectoryTrustError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute { path } => write!(
                formatter,
                "trusted path must be absolute: {}",
                path.display()
            ),
            Self::InvalidComponent { path } => write!(
                formatter,
                "trusted path contains an unsafe component: {}",
                path.display()
            ),
            Self::Inspect { path, source } => write!(
                formatter,
                "failed to inspect trusted path {}: {source}",
                path.display()
            ),
            Self::NotDirectory { path } => write!(
                formatter,
                "trusted path is not a directory: {}",
                path.display()
            ),
            Self::NotRegularFile { path } => write!(
                formatter,
                "trusted path is not a regular file: {}",
                path.display()
            ),
            Self::UntrustedSymlink { path, detail } => write!(
                formatter,
                "trusted path contains an untrusted symlink or reparse point at {}: {detail}",
                path.display()
            ),
            Self::UntrustedOwner { path, owner } => write!(
                formatter,
                "trusted path has an untrusted owner at {}: {owner}",
                path.display()
            ),
            Self::Writable { path } => write!(
                formatter,
                "trusted path is group/world-writable or writable by an untrusted principal: {}",
                path.display()
            ),
            Self::Acl { path, source } => write!(
                formatter,
                "trusted path has an unsafe ACL at {}: {source}",
                path.display()
            ),
            #[cfg(unix)]
            Self::UnixAcl { path, source } => write!(
                formatter,
                "trusted path has an unsafe ACL at {}: {source}",
                path.display()
            ),
            Self::IdentityChanged { path } => write!(
                formatter,
                "trusted path identity changed while it was in use: {}",
                path.display()
            ),
            Self::Persist {
                path,
                stage,
                source,
            } => write!(
                formatter,
                "failed to persist {stage} at {}: {source}",
                path.display()
            ),
            Self::ValidationAndCleanup {
                path,
                validation,
                cleanup,
            } => write!(
                formatter,
                "private directory validation failed at {}; validation={validation}; cleanup={cleanup}",
                path.display()
            ),
            Self::DurabilityUnavailable { path } => write!(
                formatter,
                "durable trusted directory creation is unavailable at {}",
                path.display()
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("trusted path traversal is unavailable on this platform")
            }
        }
    }
}

impl Error for DirectoryTrustError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Inspect { source, .. } => Some(source),
            Self::Persist { source, .. } => Some(source),
            Self::ValidationAndCleanup { validation, .. } => Some(validation),
            Self::Acl { source, .. } => Some(source),
            #[cfg(unix)]
            Self::UnixAcl { source, .. } => Some(source),
            _ => None,
        }
    }
}
