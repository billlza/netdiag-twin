use super::{DirectoryTrustPolicy, inspect, open_directory_at, open_strict, validate_security};
use crate::trusted_directory::DirectoryTrustError;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, openat, statat};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::path::{Component, Path};

const STRICT_FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

pub(in crate::trusted_directory) fn open_strict_regular_file(
    path: &Path,
) -> Result<(File, Metadata), DirectoryTrustError> {
    if !path.is_absolute() {
        return Err(DirectoryTrustError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }
    let parent = path
        .parent()
        .ok_or_else(|| DirectoryTrustError::InvalidComponent {
            path: path.to_path_buf(),
        })?;
    let name = path
        .file_name()
        .ok_or_else(|| DirectoryTrustError::InvalidComponent {
            path: path.to_path_buf(),
        })?;
    let directory = open_strict(parent)?;
    open_strict_regular_file_at(directory.as_file(), name, path)
}

pub(in crate::trusted_directory) fn open_strict_directory_at(
    parent: &File,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, Metadata), DirectoryTrustError> {
    strict_component(name, display_path)?;
    let directory = open_directory_at(parent, name)
        .map_err(|source| strict_directory_open_error(parent, name, display_path, source))?;
    let metadata = validate_opened_strict_directory(display_path, &directory)?;
    Ok((directory, metadata))
}

pub(in crate::trusted_directory) fn open_strict_regular_file_at(
    parent: &File,
    name: &OsStr,
    display_path: &Path,
) -> Result<(File, Metadata), DirectoryTrustError> {
    strict_component(name, display_path)?;
    let file = openat(parent, name, STRICT_FILE_FLAGS, Mode::empty())
        .map(File::from)
        .map_err(|source| {
            if source == Errno::LOOP {
                DirectoryTrustError::UntrustedSymlink {
                    path: display_path.to_path_buf(),
                    detail: "strict regular-file opens do not follow symlinks".to_string(),
                }
            } else {
                inspect(display_path, source)
            }
        })?;
    let metadata = validate_opened_strict_regular_file(display_path, &file)?;
    Ok((file, metadata))
}

pub(in crate::trusted_directory) fn validate_opened_strict_directory(
    path: &Path,
    directory: &File,
) -> Result<Metadata, DirectoryTrustError> {
    let metadata = opened_metadata(path, directory)?;
    if !metadata.is_dir() {
        return Err(DirectoryTrustError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    validate_security(
        path,
        directory,
        &metadata,
        DirectoryTrustPolicy::StrictNoFollow,
    )?;
    Ok(metadata)
}

pub(in crate::trusted_directory) fn validate_opened_strict_regular_file(
    path: &Path,
    file: &File,
) -> Result<Metadata, DirectoryTrustError> {
    let metadata = opened_metadata(path, file)?;
    if !metadata.is_file() {
        return Err(DirectoryTrustError::NotRegularFile {
            path: path.to_path_buf(),
        });
    }
    validate_security(path, file, &metadata, DirectoryTrustPolicy::StrictNoFollow)?;
    Ok(metadata)
}

fn strict_component<'a>(
    name: &'a OsStr,
    display_path: &Path,
) -> Result<&'a OsStr, DirectoryTrustError> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(component)), None) if component == name => Ok(name),
        _ => Err(DirectoryTrustError::InvalidComponent {
            path: display_path.to_path_buf(),
        }),
    }
}

fn strict_directory_open_error(
    parent: &File,
    name: &OsStr,
    path: &Path,
    source: Errno,
) -> DirectoryTrustError {
    if matches!(source, Errno::LOOP | Errno::NOTDIR)
        && statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|metadata| FileType::from_raw_mode(metadata.st_mode).is_symlink())
    {
        return DirectoryTrustError::UntrustedSymlink {
            path: path.to_path_buf(),
            detail: "strict directory opens do not follow symlinks".to_string(),
        };
    }
    if source == Errno::NOTDIR {
        return DirectoryTrustError::NotDirectory {
            path: path.to_path_buf(),
        };
    }
    inspect(path, source)
}

fn opened_metadata(path: &Path, object: &File) -> Result<Metadata, DirectoryTrustError> {
    object
        .metadata()
        .map_err(|source| DirectoryTrustError::Inspect {
            path: path.to_path_buf(),
            source,
        })
}
