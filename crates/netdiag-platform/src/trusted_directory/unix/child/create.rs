use super::finish_child;
use crate::trusted_directory::unix::{
    CREATED_DIRECTORY_MODE, DirectoryTrustError, TrustedDirectory, inspect,
    open_nofollow_directory, validate_directory,
};
use rustix::fs::mkdirat;
use std::ffi::OsStr;

mod cleanup;

pub(in crate::trusted_directory) fn create_new(
    parent: &TrustedDirectory,
    name: &OsStr,
) -> Result<TrustedDirectory, DirectoryTrustError> {
    parent.validate_private_security()?;
    let candidate = parent.resolved_path.join(name);
    mkdirat(&parent.directory, name, CREATED_DIRECTORY_MODE)
        .map_err(|source| inspect(&candidate, source))?;
    let prepared = (|| {
        let directory = open_nofollow_directory(
            &parent.directory,
            name,
            &candidate,
            "new private subdirectories cannot be symbolic links",
        )?;
        validate_directory(&candidate, &directory, parent.policy)?;
        finish_child(parent, candidate.clone(), directory)
    })();
    cleanup::finish_preparation(&parent.directory, name, candidate, prepared)
}
