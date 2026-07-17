use crate::{DirectoryTrustError, SystemTemporaryRootError};
use std::io;
use std::path::PathBuf;

mod display;

#[derive(Debug)]
pub enum TrustedTempDirectoryError {
    InvalidPrefix,
    InvalidGeneratedName,
    Random {
        source: getrandom::Error,
    },
    SystemTemporaryRoot {
        source: SystemTemporaryRootError,
    },
    Trust {
        context: &'static str,
        path: PathBuf,
        source: DirectoryTrustError,
    },
    Io {
        context: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    RootPolicy {
        path: PathBuf,
        detail: &'static str,
    },
    ChildPolicy {
        path: PathBuf,
        detail: &'static str,
    },
    IdentityChanged {
        path: PathBuf,
    },
    StateUnavailable {
        path: PathBuf,
    },
    NameCollisionLimit {
        root: PathBuf,
    },
    CleanupSkipped {
        path: PathBuf,
        validation: Box<TrustedTempDirectoryError>,
    },
    ValidationAndCleanup {
        path: PathBuf,
        validation: Box<TrustedTempDirectoryError>,
        cleanup: io::Error,
    },
    UnsupportedPlatform,
}
