use crate::error::{NetdiagError, Result};
use netdiag_platform::{open_strict_directory_at, open_strict_regular_file_at};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::path::{Component, Path};

mod error;
use error::open_error;

pub(super) fn open_relative_regular_file(
    root: &File,
    root_path: &Path,
    relative: &Path,
    requested: &Path,
) -> Result<(File, Metadata)> {
    let components = relative.components().collect::<Vec<_>>();
    let (file_component, directory_components) = components.split_last().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "adapter endpoint does not name a file: {}",
            requested.display()
        ))
    })?;
    let file_name = normal_component(file_component, requested)?;
    let mut directory = None;
    let mut inspected_path = root_path.to_path_buf();
    for component in directory_components {
        let name = normal_component(component, requested)?;
        inspected_path.push(name);
        let parent = directory.as_ref().unwrap_or(root);
        let (opened, _) = open_strict_directory_at(parent, name, &inspected_path)
            .map_err(|source| open_error(requested, source))?;
        directory = Some(opened);
    }
    let parent = directory.as_ref().unwrap_or(root);
    open_strict_regular_file_at(parent, file_name, requested)
        .map_err(|source| open_error(requested, source))
}

fn normal_component<'a>(component: &Component<'a>, requested: &Path) -> Result<&'a OsStr> {
    match component {
        Component::Normal(value) => Ok(value),
        _ => Err(NetdiagError::InvalidTrace(format!(
            "adapter endpoint escapes safety.adapter_execution_root: {}",
            requested.display()
        ))),
    }
}

#[cfg(test)]
mod tests;
