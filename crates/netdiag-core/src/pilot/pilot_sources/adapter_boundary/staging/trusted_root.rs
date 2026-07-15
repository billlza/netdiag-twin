use crate::error::{NetdiagError, Result};
use crate::file_identity::{OpenedFileIdentity, identity};
use netdiag_platform::{
    DirectoryTrustError, TrustedDirectory, open_strict_directory_chain_no_follow,
};
use std::fs::{File, Metadata};
use std::path::{Path, PathBuf};

mod open;
use open::open_relative_regular_file;

use super::source_validation::relative_adapter_path;

pub(super) struct OpenedAdapterSource {
    pub(super) file: File,
    pub(super) metadata: Metadata,
    pub(super) identity: OpenedFileIdentity,
    pub(super) path: PathBuf,
}

pub(super) struct TrustedRoot {
    path: PathBuf,
    configured: String,
    directory: TrustedDirectory,
}

impl TrustedRoot {
    pub(super) fn open(path: &Path, configured: &str) -> Result<Self> {
        let directory = open_strict_directory_chain_no_follow(path)
            .map_err(|source| root_trust_error(path, source))?;
        directory
            .validate_identity()
            .map_err(|source| root_trust_error(path, source))?;
        Ok(Self {
            path: path.to_path_buf(),
            configured: configured.to_string(),
            directory,
        })
    }

    pub(super) fn open_source(&self, endpoint: &str) -> Result<OpenedAdapterSource> {
        let relative = relative_adapter_path(&self.configured, endpoint)?;
        let path = self.path.join(&relative);
        let (file, metadata) =
            open_relative_regular_file(self.directory.as_file(), &self.path, &relative, &path)?;
        Ok(OpenedAdapterSource {
            identity: identity(&file, &path)?,
            file,
            metadata,
            path,
        })
    }

    pub(super) fn verify_unchanged(&self) -> Result<()> {
        self.directory
            .validate_private_security()
            .map_err(|source| root_trust_error(&self.path, source))?;
        self.directory
            .validate_identity()
            .map_err(|source| root_trust_error(&self.path, source))
    }
}

fn root_trust_error(path: &Path, source: DirectoryTrustError) -> NetdiagError {
    if matches!(&source, DirectoryTrustError::IdentityChanged { .. }) {
        return root_changed(path);
    }
    NetdiagError::FilesystemTrust {
        context: "adapter execution root",
        source,
    }
}

fn root_changed(path: &Path) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "adapter execution root changed while adapters were being prepared: {}",
        path.display()
    ))
}

#[cfg(test)]
mod tests;
