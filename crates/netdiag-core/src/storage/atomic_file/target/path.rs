use crate::error::{NetdiagError, Result};
use std::path::{Component, Path, PathBuf};

pub(super) fn lexical_absolute(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| NetdiagError::Io {
                path: PathBuf::from("."),
                source,
            })?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir if normalized.pop() => {}
            Component::ParentDir => return Err(invalid_target(path)),
        }
    }
    Ok(normalized)
}

pub(super) fn invalid_target(path: &Path) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "atomic file target must name a confined file: {}",
        path.display()
    ))
}
