use crate::error::{NetdiagError, Result};
use std::path::{Component, Path, PathBuf};

pub(super) fn normalize_relative(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => normalized.push(value),
            Component::ParentDir if normalized.file_name().is_some_and(|value| value != "..") => {
                normalized.pop();
            }
            Component::ParentDir => normalized.push(".."),
            Component::RootDir | Component::Prefix(_) => {
                return Err(NetdiagError::InvalidTrace(format!(
                    "adapter path must be relative: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(normalized)
}
