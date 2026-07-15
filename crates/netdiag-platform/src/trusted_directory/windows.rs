use super::DirectoryTrustError;
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

mod child;
mod handle;
mod identity;
#[cfg(test)]
mod tests;
mod validation;
pub(super) use child::open_or_create as open_or_create_child;
use handle::{open_directory, validate_metadata};

#[derive(Debug)]
pub struct TrustedDirectory {
    directory: File,
    resolved_path: PathBuf,
    _ancestors: Vec<File>,
}

impl TrustedDirectory {
    pub fn as_file(&self) -> &File {
        &self.directory
    }

    pub fn resolved_path(&self) -> &Path {
        &self.resolved_path
    }
}

pub(super) fn open(
    path: &Path,
    create_missing: bool,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    if !path.is_absolute() {
        return Err(DirectoryTrustError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }
    let mut current = PathBuf::new();
    let mut ancestors = Vec::new();
    let mut final_directory = None;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => {
                current.push(component.as_os_str());
                let opened = open_directory(&current)?;
                let metadata = opened
                    .metadata()
                    .map_err(|source| inspect(&current, source))?;
                validate_metadata(&current, &metadata)?;
                final_directory = Some(opened);
            }
            Component::Normal(name) => {
                current.push(name);
                let mut private_validation_required = false;
                match fs::symlink_metadata(&current) {
                    Ok(metadata) => validate_metadata(&current, &metadata)?,
                    Err(source)
                        if source.kind() == std::io::ErrorKind::NotFound && create_missing =>
                    {
                        crate::windows::create_private_directory(&current)
                            .map_err(|source| inspect(&current, source))?;
                        private_validation_required = true;
                    }
                    Err(source) => return Err(inspect(&current, source)),
                }
                let opened = open_directory(&current)?;
                let metadata = opened
                    .metadata()
                    .map_err(|source| inspect(&current, source))?;
                validate_metadata(&current, &metadata)?;
                if private_validation_required {
                    crate::windows::validate_private_object_security(&opened).map_err(
                        |source| DirectoryTrustError::Acl {
                            path: current.clone(),
                            source,
                        },
                    )?;
                }
                if let Some(previous) = final_directory.replace(opened) {
                    ancestors.push(previous);
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(DirectoryTrustError::InvalidComponent {
                    path: path.to_path_buf(),
                });
            }
        }
    }
    let directory = final_directory.ok_or_else(|| DirectoryTrustError::NotDirectory {
        path: path.to_path_buf(),
    })?;
    let resolved_path = fs::canonicalize(path).map_err(|source| inspect(path, source))?;
    Ok(TrustedDirectory {
        directory,
        resolved_path,
        _ancestors: ancestors,
    })
}

pub(super) fn inspect(path: &Path, source: std::io::Error) -> DirectoryTrustError {
    DirectoryTrustError::Inspect {
        path: path.to_path_buf(),
        source,
    }
}
