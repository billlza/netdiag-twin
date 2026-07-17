use super::temporary_name;
use crate::error::{IoContext, NetdiagError, Result};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod lifecycle;
mod publish;

#[must_use = "staged atomic files must be published or aborted explicitly"]
pub(crate) struct StagedAtomicFile {
    directory: Arc<netdiag_platform::TrustedDirectory>,
    name: OsString,
    path: PathBuf,
    file: Option<File>,
    cleanup_armed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NoClobberDisposition {
    Created,
    Existing,
}

impl StagedAtomicFile {
    pub(crate) fn reserve_in(
        directory: Arc<netdiag_platform::TrustedDirectory>,
        stem: &OsStr,
        default_extension: &str,
    ) -> Result<Self> {
        let name = temporary_name(stem, default_extension);
        Self::reserve_named(directory, name)
    }

    fn reserve_named(
        directory: Arc<netdiag_platform::TrustedDirectory>,
        name: OsString,
    ) -> Result<Self> {
        let path = directory.resolved_path().join(&name);
        let file =
            netdiag_platform::create_new_private_file_at(&directory, &name).map_err(|source| {
                NetdiagError::PrivateFileCreation {
                    path: path.clone(),
                    source,
                }
            })?;
        Ok(Self {
            directory,
            name,
            path,
            file: Some(file),
            cleanup_armed: true,
        })
    }

    pub(crate) fn file_mut(&mut self) -> &mut File {
        self.file
            .as_mut()
            .expect("staged file handle is available before publication")
    }

    pub(crate) fn reopen_rewound(&self) -> Result<File> {
        let mut file = self
            .file
            .as_ref()
            .expect("staged file handle is available before publication")
            .try_clone()
            .with_path(&self.path)?;
        file.seek(SeekFrom::Start(0)).with_path(&self.path)?;
        Ok(file)
    }

    pub(crate) fn sync(&mut self) -> Result<()> {
        self.file_mut().sync_all().with_path(&self.path)
    }

    pub(crate) fn name(&self) -> &OsStr {
        &self.name
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
impl StagedAtomicFile {
    pub(super) fn reserve_named_for_test(
        directory: Arc<netdiag_platform::TrustedDirectory>,
        name: &OsStr,
    ) -> Result<Self> {
        Self::reserve_named(directory, name.to_os_string())
    }

    #[cfg(unix)]
    pub(super) fn metadata_for_test(&self) -> std::io::Result<std::fs::Metadata> {
        self.file
            .as_ref()
            .expect("staged file handle is available before publication")
            .metadata()
    }
}
