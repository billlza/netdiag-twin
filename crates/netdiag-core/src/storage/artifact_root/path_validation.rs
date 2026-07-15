use crate::error::{NetdiagError, Result};
use std::path::Path;

pub fn validate_artifact_root_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "artifact root path must not be empty".to_string(),
        ));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && !netdiag_platform::metadata_is_reparse_point(&metadata) =>
        {
            Ok(())
        }
        Ok(_) => Err(NetdiagError::InvalidTrace(format!(
            "artifact root must be a regular directory, not a link or reparse point: {}",
            path.display()
        ))),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(NetdiagError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}
