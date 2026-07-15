use super::super::{DirectoryPersistenceStage, DirectoryTrustError};
use std::path::Path;

pub(super) fn persist_error(
    path: &Path,
    stage: DirectoryPersistenceStage,
    source: std::io::Error,
) -> DirectoryTrustError {
    DirectoryTrustError::Persist {
        path: path.to_path_buf(),
        stage,
        source,
    }
}
