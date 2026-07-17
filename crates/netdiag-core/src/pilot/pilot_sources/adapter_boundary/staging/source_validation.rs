use crate::error::{NetdiagError, Result};
use std::path::{Component, Path, PathBuf};

mod normalize;
use normalize::normalize_relative;

pub(super) fn relative_adapter_path(configured_root: &str, endpoint: &str) -> Result<PathBuf> {
    let root = normalize_relative(Path::new(configured_root))?;
    let endpoint = normalize_relative(Path::new(endpoint))?;
    let relative = endpoint.strip_prefix(&root).map_err(|_| {
        NetdiagError::InvalidTrace(format!(
            "adapter endpoint escapes safety.adapter_execution_root: {endpoint:?}"
        ))
    })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter endpoint escapes or does not name a file below safety.adapter_execution_root: {endpoint:?}"
        )));
    }
    Ok(relative.to_path_buf())
}

#[cfg(test)]
mod tests;
