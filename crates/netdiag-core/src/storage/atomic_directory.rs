use crate::error::{IoContext, Result};
use crate::storage::atomic_file::BoundAtomicFileTarget;
use crate::storage::atomic_file::write::write_file_atomically_to_bound;
use crate::storage::typed_json::{prepare_json_bounded, save_prepared_json_atomic_to_bound};
use serde::Serialize;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod cleanup;
mod creation;
mod publication;
pub(crate) use publication::preserve_published_directory;

/// A new private directory whose files and final no-clobber publication remain bound to retained
/// directory handles.
#[must_use = "staged atomic directories must be published or aborted explicitly"]
pub(crate) struct StagedAtomicDirectory {
    parent: Arc<netdiag_platform::TrustedDirectory>,
    directory: Arc<netdiag_platform::TrustedDirectory>,
    staging_name: OsString,
    target_name: OsString,
    target_path: PathBuf,
    context: &'static str,
}

impl StagedAtomicDirectory {
    pub(crate) fn trusted_directory(&self) -> &Arc<netdiag_platform::TrustedDirectory> {
        &self.directory
    }

    pub(crate) fn staging_path(&self) -> &Path {
        self.directory.resolved_path()
    }

    pub(crate) fn target_path(&self) -> &Path {
        &self.target_path
    }

    pub(crate) fn parent_path(&self) -> &Path {
        self.parent.resolved_path()
    }

    pub(crate) fn staging_name(&self) -> &OsStr {
        &self.staging_name
    }

    pub(crate) fn target_name(&self) -> &OsStr {
        &self.target_name
    }

    pub(crate) fn coordination_identity(&self) -> Result<[u8; 32]> {
        self.directory.coordination_identity().map_err(|source| {
            crate::error::NetdiagError::FilesystemTrust {
                context: self.context,
                source,
            }
        })
    }

    pub(crate) fn save_json<T: Serialize + ?Sized>(
        &mut self,
        file_name: &str,
        value: &T,
    ) -> Result<()> {
        self.write_file(file_name, "json", |file, path| {
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, value)?;
            writer.flush().with_path(path)
        })
        .map(drop)
    }

    pub(crate) fn write_file<T>(
        &mut self,
        file_name: &str,
        default_extension: &str,
        write: impl FnOnce(&mut File, &Path) -> Result<T>,
    ) -> Result<T> {
        let target = self.target(file_name)?;
        let path = target.resolved_path().to_path_buf();
        write_file_atomically_to_bound(&target, &path, default_extension, |file| write(file, &path))
            .map(|(_, value)| value)
    }

    pub(crate) fn save_json_bounded<T: Serialize + ?Sized>(
        &mut self,
        file_name: &str,
        value: &T,
        max_bytes: u64,
        kind: &str,
    ) -> Result<()> {
        let prepared = prepare_json_bounded(value, max_bytes, kind)?;
        let target = self.target(file_name)?;
        save_prepared_json_atomic_to_bound(&target, prepared)
    }

    pub(crate) fn target(&self, file_name: &str) -> Result<BoundAtomicFileTarget> {
        let name = OsStr::new(file_name);
        BoundAtomicFileTarget::from_directory(Arc::clone(&self.directory), name)
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;
