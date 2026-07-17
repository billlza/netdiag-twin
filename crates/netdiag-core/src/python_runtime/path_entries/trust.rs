use crate::error::{NetdiagError, Result};
use netdiag_platform::{
    DirectoryTrustError, open_strict_directory_chain_no_follow, open_strict_regular_file_no_follow,
};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(in crate::python_runtime) fn validate_trusted_interpreter(path: &Path) -> Result<()> {
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(NetdiagError::Connector(format!(
            "Python interpreter has no parent directory: {}",
            path.display()
        )));
    }
    let (_file, metadata) = open_strict_regular_file_no_follow(path)
        .map_err(|source| filesystem_trust("Python interpreter", source))?;
    if metadata.mode() & 0o111 == 0 {
        return Err(NetdiagError::Connector(format!(
            "Python interpreter is not executable: {}",
            path.display()
        )));
    }
    Ok(())
}

pub(super) fn validate_trusted_directory_chain(path: &Path) -> Result<()> {
    open_strict_directory_chain_no_follow(path)
        .map(|_| ())
        .map_err(|source| filesystem_trust("Python PATH directory", source))
}

fn filesystem_trust(context: &'static str, source: DirectoryTrustError) -> NetdiagError {
    NetdiagError::FilesystemTrust { context, source }
}

#[cfg(test)]
mod tests;
