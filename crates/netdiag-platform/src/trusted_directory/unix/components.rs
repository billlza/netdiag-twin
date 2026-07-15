use super::DirectoryTrustError;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Component, Path};

pub(super) fn normal_components(path: &Path) -> Result<VecDeque<OsString>, DirectoryTrustError> {
    if !path.is_absolute() {
        return Err(DirectoryTrustError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }
    normal_components_allow_relative(path)
}

pub(super) fn normal_components_allow_relative(
    path: &Path,
) -> Result<VecDeque<OsString>, DirectoryTrustError> {
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(name) => Some(Ok(name.to_os_string())),
            _ => Some(Err(DirectoryTrustError::InvalidComponent {
                path: path.to_path_buf(),
            })),
        })
        .collect()
}
