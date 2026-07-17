use super::{DirectoryPersistenceStage, DirectoryTrustError};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, mkdirat, open as rustix_open, openat, statat};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const CREATED_DIRECTORY_MODE: Mode = Mode::RUSR.union(Mode::WUSR).union(Mode::XUSR);
const MAX_SYSTEM_SYMLINKS: usize = 16;

mod child;
mod components;
mod durability;
mod entry_error;
mod identity;
mod security;
mod strict;
mod symlink;
pub(super) use child::{create_new as create_new_child, open_or_create as open_or_create_child};
use components::{normal_components, normal_components_allow_relative};
use durability::{
    open_created_directory, persist_directory_chain_if_required, persist_directory_entry,
};
use entry_error::{classify_nofollow_directory_error, open_nofollow_directory};
use security::{DirectoryTrustPolicy, validate_security};
pub(in crate::trusted_directory) use strict::{
    open_strict_directory_at, open_strict_regular_file, open_strict_regular_file_at,
    validate_opened_strict_directory, validate_opened_strict_regular_file,
};
#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct TrustedDirectory {
    directory: File,
    resolved_path: PathBuf,
    metadata: Metadata,
    _ancestors: Vec<File>,
    policy: DirectoryTrustPolicy,
}

impl TrustedDirectory {
    pub fn as_file(&self) -> &File {
        &self.directory
    }

    pub fn resolved_path(&self) -> &Path {
        &self.resolved_path
    }

    pub fn coordination_identity(&self) -> Result<[u8; 32], DirectoryTrustError> {
        Ok(identity::coordination(&self.metadata))
    }

    pub fn validate_private_security(&self) -> Result<(), DirectoryTrustError> {
        validate_directory(&self.resolved_path, &self.directory, self.policy)
    }

    pub fn validate_identity(&self) -> Result<(), DirectoryTrustError> {
        let current = open_with_policy(&self.resolved_path, false, false, self.policy)?;
        if self.resolved_path != current.resolved_path
            || self.metadata.dev() != current.metadata.dev()
            || self.metadata.ino() != current.metadata.ino()
        {
            return Err(DirectoryTrustError::IdentityChanged {
                path: self.resolved_path.clone(),
            });
        }
        Ok(())
    }
}

pub(super) fn open(
    path: &Path,
    create_missing: bool,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    open_with_policy(
        path,
        create_missing,
        false,
        DirectoryTrustPolicy::TrustedSystemPath,
    )
}

pub(super) fn open_durable(path: &Path) -> Result<TrustedDirectory, DirectoryTrustError> {
    open_with_policy(path, true, true, DirectoryTrustPolicy::TrustedSystemPath)
}

pub(super) fn open_strict(path: &Path) -> Result<TrustedDirectory, DirectoryTrustError> {
    open_with_policy(path, false, false, DirectoryTrustPolicy::StrictNoFollow)
}

fn open_with_policy(
    path: &Path,
    create_missing: bool,
    durable: bool,
    policy: DirectoryTrustPolicy,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    if !path.is_absolute() {
        return Err(DirectoryTrustError::NotAbsolute {
            path: path.to_path_buf(),
        });
    }
    let mut remaining = normal_components(path)?;
    let mut directory = open_root()?;
    validate_directory(Path::new("/"), &directory, policy)?;
    let mut resolved = PathBuf::from("/");
    let mut ancestors = Vec::new();
    let mut followed_symlinks = 0;

    while let Some(name) = remaining.pop_front() {
        let candidate = resolved.join(&name);
        match open_directory_at(&directory, &name) {
            Ok(opened) => {
                validate_directory(&candidate, &opened, policy)?;
                ancestors.push((directory, resolved.clone()));
                directory = opened;
                resolved.push(name);
            }
            Err(source) if source == Errno::NOENT && create_missing => {
                match mkdirat(&directory, &name, CREATED_DIRECTORY_MODE) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(source) => return Err(inspect(&candidate, source)),
                }
                let opened = open_created_directory(&directory, &name, &candidate)?;
                validate_directory(&candidate, &opened, policy)?;
                ancestors.push((directory, resolved.clone()));
                directory = opened;
                resolved.push(name);
            }
            Err(Errno::LOOP | Errno::NOTDIR) => {
                let stat = statat(&directory, &name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|source| inspect(&candidate, source))?;
                if !FileType::from_raw_mode(stat.st_mode).is_symlink() {
                    return Err(DirectoryTrustError::NotDirectory { path: candidate });
                }
                if policy == DirectoryTrustPolicy::StrictNoFollow {
                    return Err(DirectoryTrustError::UntrustedSymlink {
                        path: candidate,
                        detail: "strict directory chains do not follow symlinks".to_string(),
                    });
                }
                followed_symlinks += 1;
                if followed_symlinks > MAX_SYSTEM_SYMLINKS {
                    return Err(DirectoryTrustError::UntrustedSymlink {
                        path: candidate,
                        detail: format!("more than {MAX_SYSTEM_SYMLINKS} system symlinks"),
                    });
                }
                let target = symlink::read_trusted_system_symlink(
                    &directory,
                    &resolved,
                    &candidate,
                    &name,
                    stat.st_uid,
                )?;
                let target_components = normal_components_allow_relative(&target)?;
                if target.is_absolute() {
                    directory = open_root()?;
                    validate_directory(Path::new("/"), &directory, policy)?;
                    ancestors.clear();
                    resolved = PathBuf::from("/");
                }
                for component in target_components.into_iter().rev() {
                    remaining.push_front(component);
                }
            }
            Err(source) => return Err(inspect(&candidate, source)),
        }
    }
    persist_directory_chain_if_required(durable, &directory, &resolved, &ancestors)?;
    let resolved = identity::resolved_path_from_handle(&directory, resolved)?;
    let metadata = directory
        .metadata()
        .map_err(|source| inspect(&resolved, source))?;
    Ok(TrustedDirectory {
        directory,
        resolved_path: resolved,
        metadata,
        _ancestors: ancestors
            .into_iter()
            .map(|(directory, _)| directory)
            .collect(),
        policy,
    })
}

fn open_root() -> Result<File, DirectoryTrustError> {
    rustix_open(Path::new("/"), DIRECTORY_FLAGS, Mode::empty())
        .map(File::from)
        .map_err(|source| inspect(Path::new("/"), source))
}

fn open_directory_at(parent: &File, name: &OsStr) -> rustix::io::Result<File> {
    openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map(File::from)
}

fn validate_directory(
    path: &Path,
    directory: &File,
    policy: DirectoryTrustPolicy,
) -> Result<(), DirectoryTrustError> {
    let metadata = directory
        .metadata()
        .map_err(|source| inspect(path, source))?;
    if !metadata.is_dir() {
        return Err(DirectoryTrustError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    validate_security(path, directory, &metadata, policy)
}

fn inspect(path: &Path, source: impl Into<std::io::Error>) -> DirectoryTrustError {
    DirectoryTrustError::Inspect {
        path: path.to_path_buf(),
        source: source.into(),
    }
}
