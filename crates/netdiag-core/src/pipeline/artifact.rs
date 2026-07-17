use crate::error::{NetdiagError, Result};
use std::path::Path;

pub(super) struct BoundedArtifact<'a> {
    pub(super) key: &'a str,
    pub(super) file_name: &'a str,
    pub(super) max_bytes: u64,
    pub(super) kind: &'a str,
}

pub(super) fn validate_artifact_file_name(file_name: &str) -> Result<()> {
    let mut components = Path::new(file_name).components();
    if matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
    {
        return Ok(());
    }
    Err(NetdiagError::InvalidTrace(format!(
        "artifact file name must be a single relative component: {file_name}"
    )))
}
