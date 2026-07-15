use std::path::PathBuf;

mod atomic_publish_phase;

pub use atomic_publish_phase::AtomicPublishPhase;

#[derive(Debug, thiserror::Error)]
pub enum NetdiagError {
    #[error("atomic file at {path} was {phase}: {source}")]
    AtomicPublish {
        path: PathBuf,
        phase: AtomicPublishPhase,
        #[source]
        source: Box<NetdiagError>,
    },
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("platform atomic publication failed at {path}: {source}")]
    PlatformAtomicPublication {
        path: PathBuf,
        #[source]
        source: netdiag_platform::AtomicPublicationError,
    },
    #[error("failed to create private file at {path}: {source}")]
    PrivateFileCreation {
        path: PathBuf,
        #[source]
        source: netdiag_platform::PrivateFileCreationError,
    },
    #[error(
        "publication state at {path} is indeterminate because the failure classification is missing or belongs to a different target: {source}"
    )]
    PublicationStateIndeterminate {
        path: PathBuf,
        #[source]
        source: Box<NetdiagError>,
    },
    #[error(
        "immutable target collision at {path}; staged-file cleanup also failed: collision={collision}; cleanup={cleanup}"
    )]
    ExistingTargetCollisionCleanup {
        path: PathBuf,
        #[source]
        collision: Box<NetdiagError>,
        cleanup: Box<NetdiagError>,
    },
    #[error("failed to resolve {context}: {source}")]
    CoordinationSystemTemporaryRoot {
        context: &'static str,
        #[source]
        source: netdiag_platform::SystemTemporaryRootError,
    },
    #[cfg(windows)]
    #[error("failed to resolve {context}: {source}")]
    WindowsCoordinationLocalAppData {
        context: &'static str,
        #[source]
        source: netdiag_platform::CurrentUserLocalAppDataError,
    },
    #[cfg(windows)]
    #[error("failed to identify the Windows principal for {context}: {source}")]
    WindowsCoordinationPrincipal {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("filesystem trust validation failed for {context}: {source}")]
    FilesystemTrust {
        context: &'static str,
        #[source]
        source: netdiag_platform::DirectoryTrustError,
    },
    #[error(
        "private directory mode validation failed for {context} at {path}: expected {expected:#o}, found {actual:#o}"
    )]
    PrivateDirectoryMode {
        context: &'static str,
        path: PathBuf,
        expected: u32,
        actual: u32,
    },
    #[error("coordination lock file validation failed at {path}: {source}")]
    CoordinationFileValidation {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(unix)]
    #[error("coordination lock ACL validation failed at {path}: {source}")]
    CoordinationFileAcl {
        path: PathBuf,
        #[source]
        source: netdiag_platform::UnixAclTrustError,
    },
    #[error("{primary_context}: {primary}; {secondary_context}: {secondary}")]
    CombinedFailure {
        primary_context: &'static str,
        #[source]
        primary: Box<NetdiagError>,
        secondary_context: &'static str,
        secondary: Box<NetdiagError>,
    },
    #[error("trusted temporary directory failure for {context}: {source}")]
    TrustedTemporaryDirectory {
        context: &'static str,
        #[source]
        source: netdiag_platform::TrustedTempDirectoryError,
    },
    #[error(
        "operation completed for {context}, but trusted temporary directory cleanup failed: {source}"
    )]
    TrustedTemporaryDirectoryCleanupAfterSuccess {
        context: &'static str,
        #[source]
        source: netdiag_platform::TrustedTempDirectoryError,
    },
    #[error(
        "operation failed for {context}: {operation}; trusted temporary directory cleanup also failed: {cleanup}"
    )]
    TrustedTemporaryDirectoryOperationAndCleanup {
        context: &'static str,
        #[source]
        operation: Box<NetdiagError>,
        cleanup: netdiag_platform::TrustedTempDirectoryError,
    },
    #[error(
        "evidence snapshot operation failed at {path}: {operation}; incomplete snapshot cleanup also failed: {cleanup}"
    )]
    EvidenceSnapshotOperationAndCleanup {
        path: PathBuf,
        #[source]
        operation: Box<NetdiagError>,
        cleanup: std::io::Error,
    },
    #[error(
        "failed to resolve lab verification policy for run {run_id}: lab lookup failed: {lab_resolution}; run-context lookup also failed: {context_resolution}"
    )]
    LabContextResolution {
        run_id: String,
        lab_resolution: Box<NetdiagError>,
        #[source]
        context_resolution: Box<NetdiagError>,
    },
    #[error("CSV parse error: {0}")]
    Csv(#[from] csv::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("timestamp parse error: {0}")]
    Timestamp(String),
    #[error("trace has no rows")]
    EmptyTrace,
    #[error("trace is missing required column: {0}")]
    MissingColumn(String),
    #[error(
        "invalid numeric value at row {row}, column {column}: {value}; expected a finite non-negative number"
    )]
    InvalidNumber {
        row: usize,
        column: String,
        value: String,
    },
    #[error("invalid timestamp at row {row}: {value}")]
    InvalidTimestamp { row: usize, value: String },
    #[error("invalid trace: {0}")]
    InvalidTrace(String),
    #[error("unknown recommendation id: {0}")]
    UnknownRecommendation(String),
    #[error("unknown topology: {0}")]
    UnknownTopology(String),
    #[error("unknown what-if action: {0}")]
    UnknownAction(String),
    #[error("connector error: {0}")]
    Connector(String),
    #[error("capture cancelled: {context}")]
    CaptureCancelled { context: &'static str },
    #[error("connector not ready: {0}")]
    ConnectorNotReady(String),
    #[error("ML training/inference error: {0}")]
    Ml(String),
}

impl NetdiagError {
    pub(crate) fn capture_cancelled(context: &'static str) -> Self {
        Self::CaptureCancelled { context }
    }

    pub(crate) fn atomic_publish(
        path: impl Into<PathBuf>,
        phase: AtomicPublishPhase,
        source: Self,
    ) -> Self {
        Self::AtomicPublish {
            path: path.into(),
            phase,
            source: Box::new(source),
        }
    }

    pub fn atomic_publish_phase(&self) -> Option<AtomicPublishPhase> {
        match self {
            Self::AtomicPublish { phase, .. } => Some(*phase),
            _ => None,
        }
    }

    pub(crate) fn with_secondary_failure(
        self,
        primary_context: &'static str,
        secondary_context: &'static str,
        secondary: NetdiagError,
    ) -> Self {
        match self {
            Self::AtomicPublish {
                path,
                phase,
                source,
            } => Self::AtomicPublish {
                path,
                phase,
                source: Box::new(Self::combined_failure(
                    primary_context,
                    *source,
                    secondary_context,
                    secondary,
                )),
            },
            primary => {
                Self::combined_failure(primary_context, primary, secondary_context, secondary)
            }
        }
    }

    fn combined_failure(
        primary_context: &'static str,
        primary: Self,
        secondary_context: &'static str,
        secondary: Self,
    ) -> Self {
        Self::CombinedFailure {
            primary_context,
            primary: Box::new(primary),
            secondary_context,
            secondary: Box::new(secondary),
        }
    }
}

pub type Result<T> = std::result::Result<T, NetdiagError>;

pub(crate) trait IoContext<T> {
    fn with_path(self, path: impl Into<PathBuf>) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn with_path(self, path: impl Into<PathBuf>) -> Result<T> {
        self.map_err(|source| NetdiagError::Io {
            path: path.into(),
            source,
        })
    }
}

#[cfg(test)]
mod tests;
