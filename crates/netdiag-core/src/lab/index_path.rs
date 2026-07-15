use crate::error::{IoContext, NetdiagError, Result};
use std::path::{Component, Path, PathBuf};

pub(super) fn stored_lab_index_path(root: &Path, path: &Path) -> Result<String> {
    let absolute_root = absolute(root)?;
    let absolute_path = absolute(path)?;
    let resolved_root = std::fs::canonicalize(&absolute_root).with_path(&absolute_root)?;
    let relative = absolute_path
        .strip_prefix(&absolute_root)
        .or_else(|_| absolute_path.strip_prefix(&resolved_root))
        .map_err(|_| outside_root(&absolute_path))?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab index path is not a direct artifact-root descendant: {}",
            absolute_path.display()
        )));
    }
    Ok(relative.display().to_string())
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .with_path(Path::new("."))?
            .join(path))
    }
}

fn outside_root(path: &Path) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "lab index path is outside the artifact root: {}",
        path.display()
    ))
}
