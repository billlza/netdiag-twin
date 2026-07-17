use crate::error::{IoContext, Result};
use std::path::{Path, PathBuf};

pub(super) fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .with_path(Path::new("."))?
            .join(path))
    }
}
