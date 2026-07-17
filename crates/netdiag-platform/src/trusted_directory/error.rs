use std::io;
use std::path::PathBuf;

mod display;
mod persistence;
#[cfg(test)]
mod tests;
pub use persistence::DirectoryPersistenceStage;

#[derive(Debug)]
pub enum DirectoryTrustError {
    NotAbsolute {
        path: PathBuf,
    },
    InvalidComponent {
        path: PathBuf,
    },
    Inspect {
        path: PathBuf,
        source: io::Error,
    },
    NotDirectory {
        path: PathBuf,
    },
    NotRegularFile {
        path: PathBuf,
    },
    UntrustedSymlink {
        path: PathBuf,
        detail: String,
    },
    UntrustedOwner {
        path: PathBuf,
        owner: String,
    },
    Writable {
        path: PathBuf,
    },
    Acl {
        path: PathBuf,
        source: io::Error,
    },
    #[cfg(unix)]
    UnixAcl {
        path: PathBuf,
        source: crate::UnixAclTrustError,
    },
    IdentityChanged {
        path: PathBuf,
    },
    Persist {
        path: PathBuf,
        stage: DirectoryPersistenceStage,
        source: io::Error,
    },
    ValidationAndCleanup {
        path: PathBuf,
        validation: Box<DirectoryTrustError>,
        cleanup: io::Error,
    },
    DurabilityUnavailable {
        path: PathBuf,
    },
    UnsupportedPlatform,
}
