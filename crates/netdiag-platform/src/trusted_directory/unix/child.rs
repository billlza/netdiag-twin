use super::{
    CREATED_DIRECTORY_MODE, DirectoryTrustError, TrustedDirectory,
    classify_nofollow_directory_error, identity, inspect, open_directory_at,
    open_nofollow_directory, persist_directory_entry, validate_directory,
};
use rustix::fs::mkdirat;
use rustix::io::Errno;
use std::ffi::OsStr;

mod create;
pub(in crate::trusted_directory) use create::create_new;

pub(in crate::trusted_directory) fn open_or_create(
    parent: &TrustedDirectory,
    name: &OsStr,
    durable: bool,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    parent.validate_private_security()?;
    let candidate = parent.resolved_path.join(name);
    let directory = match open_directory_at(&parent.directory, name) {
        Ok(directory) => directory,
        Err(Errno::NOENT) => {
            match mkdirat(&parent.directory, name, CREATED_DIRECTORY_MODE) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(source) => return Err(inspect(&candidate, source)),
            }
            open_nofollow_directory(
                &parent.directory,
                name,
                &candidate,
                "trusted subdirectories cannot be symbolic links",
            )?
        }
        Err(source) => {
            return Err(classify_nofollow_directory_error(
                &parent.directory,
                name,
                &candidate,
                source,
                "trusted subdirectories cannot be symbolic links",
            ));
        }
    };
    validate_directory(&candidate, &directory, parent.policy)?;
    if durable {
        persist_directory_entry(
            &parent.directory,
            &parent.resolved_path,
            &directory,
            &candidate,
        )?;
    }
    finish_child(parent, candidate, directory)
}

pub(super) fn finish_child(
    parent: &TrustedDirectory,
    candidate: std::path::PathBuf,
    directory: std::fs::File,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    let resolved_path = identity::resolved_path_from_handle(&directory, candidate)?;
    let metadata = directory
        .metadata()
        .map_err(|source| inspect(&resolved_path, source))?;
    let parent_handle = parent
        .directory
        .try_clone()
        .map_err(|source| inspect(parent.resolved_path(), source))?;
    Ok(TrustedDirectory {
        directory,
        resolved_path,
        metadata,
        _ancestors: vec![parent_handle],
        policy: parent.policy,
    })
}
