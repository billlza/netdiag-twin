use super::source::{SourceFile, validate_regular_non_reparse};
use super::stream::{MAX_BUNDLE_BYTES, MAX_SOURCE_FILE_BYTES};
use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::{identity, open_file};
use crate::managed_temp_directory::ManagedTempDirectory;
use digest::{BoundedDigest, copy_and_hash, hash};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

mod cleanup;
mod digest;
mod seal;
use seal::seal;

pub(super) const MAX_SNAPSHOT_SOURCES: usize = 256;

pub(super) struct SnapshotStore {
    directory: ManagedTempDirectory,
    budget: SnapshotBudget,
    next_id: usize,
}

#[derive(Debug)]
pub(super) struct SourceSnapshot {
    pub(super) reported_path: PathBuf,
    pub(super) source_path: PathBuf,
    pub(super) file: File,
    pub(super) digest: BoundedDigest,
}

struct SnapshotBudget {
    sources: usize,
    bytes: u64,
    max_sources: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
}

impl SnapshotStore {
    pub(super) fn new() -> Result<Self> {
        Self::with_limits(
            MAX_SNAPSHOT_SOURCES,
            MAX_SOURCE_FILE_BYTES,
            MAX_BUNDLE_BYTES,
        )
    }

    pub(super) fn with_limits(
        max_sources: usize,
        max_file_bytes: u64,
        max_total_bytes: u64,
    ) -> Result<Self> {
        let directory = ManagedTempDirectory::create(
            "evidence snapshot staging",
            "netdiag-evidence-snapshot-",
        )?;
        Ok(Self {
            directory,
            budget: SnapshotBudget {
                sources: 0,
                bytes: 0,
                max_sources,
                max_file_bytes,
                max_total_bytes,
            },
            next_id: 0,
        })
    }

    pub(super) fn capture(&mut self, source: SourceFile) -> Result<SourceSnapshot> {
        self.capture_with_after_copy(source, |_| {})
    }

    pub(super) fn capture_with_after_copy(
        &mut self,
        mut source: SourceFile,
        after_copy: impl FnOnce(&Path),
    ) -> Result<SourceSnapshot> {
        self.budget
            .validate_declared(&source.canonical_path, source.opened_metadata.len())?;
        let snapshot_path = self.next_snapshot_path();
        let result = self.capture_into(&mut source, &snapshot_path, after_copy);
        match result {
            Ok(snapshot) => {
                self.budget.commit(snapshot.digest.bytes)?;
                Ok(snapshot)
            }
            Err(error) => Err(cleanup::after_capture_failure(&snapshot_path, error)),
        }
    }

    fn capture_into(
        &self,
        source: &mut SourceFile,
        snapshot_path: &Path,
        after_copy: impl FnOnce(&Path),
    ) -> Result<SourceSnapshot> {
        let mut snapshot_writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(snapshot_path)
            .with_path(snapshot_path)?;
        let remaining = self
            .budget
            .max_total_bytes
            .checked_sub(self.budget.bytes)
            .ok_or_else(|| {
                NetdiagError::InvalidTrace("evidence snapshot byte budget underflowed".to_string())
            })?;
        let copied = copy_and_hash(
            &mut source.file,
            &source.canonical_path,
            &mut snapshot_writer,
            snapshot_path,
            self.budget.max_file_bytes,
            remaining,
        )?;
        snapshot_writer.sync_all().with_path(snapshot_path)?;
        drop(snapshot_writer);

        after_copy(&source.canonical_path);
        source
            .file
            .seek(SeekFrom::Start(0))
            .with_path(&source.canonical_path)?;
        let verified = hash(
            &mut source.file,
            &source.canonical_path,
            self.budget.max_file_bytes,
        )?;
        let final_opened = source.file.metadata().with_path(&source.canonical_path)?;
        let final_path_file = open_file(&source.canonical_path)?;
        let final_path = final_path_file
            .metadata()
            .with_path(&source.canonical_path)?;
        let opened_modified = source
            .opened_metadata
            .modified()
            .with_path(&source.canonical_path)?;
        let final_modified = final_opened.modified().with_path(&source.canonical_path)?;
        if validate_regular_non_reparse(&source.canonical_path, &final_path).is_err()
            || copied != verified
            || copied.bytes != source.opened_metadata.len()
            || source.opened_metadata.len() != final_opened.len()
            || opened_modified != final_modified
            || identity(&final_path_file, &source.canonical_path)? != source.opened_identity
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "evidence bundle source changed while its immutable snapshot was captured: {}",
                source.canonical_path.display()
            )));
        }

        seal(snapshot_path)?;
        let file = File::open(snapshot_path).with_path(snapshot_path)?;
        Ok(SourceSnapshot {
            reported_path: source.reported_path.clone(),
            source_path: source.canonical_path.clone(),
            file,
            digest: copied,
        })
    }

    fn next_snapshot_path(&mut self) -> PathBuf {
        let id = self.next_id;
        self.next_id += 1;
        self.directory.path().join(format!("source-{id}.snapshot"))
    }

    pub(super) fn path(&self) -> &Path {
        self.directory.path()
    }

    pub(super) fn validate_identity(&self) -> Result<()> {
        self.directory.validate_identity()
    }

    pub(super) fn finish<T>(self, operation: Result<T>) -> Result<T> {
        self.directory.finish(operation)
    }
}

impl SnapshotBudget {
    fn validate_declared(&self, source: &Path, bytes: u64) -> Result<()> {
        if self.sources >= self.max_sources {
            return Err(NetdiagError::InvalidTrace(format!(
                "evidence bundle source count limit exceeded: {} > {}",
                self.sources + 1,
                self.max_sources
            )));
        }
        if bytes > self.max_file_bytes {
            return Err(NetdiagError::InvalidTrace(format!(
                "evidence bundle single source file byte limit exceeded for {}: {bytes} > {}",
                source.display(),
                self.max_file_bytes
            )));
        }
        let projected = self.bytes.checked_add(bytes).ok_or_else(|| {
            NetdiagError::InvalidTrace("evidence snapshot byte count overflowed".to_string())
        })?;
        if projected > self.max_total_bytes {
            return Err(NetdiagError::InvalidTrace(format!(
                "evidence bundle total source snapshot byte limit exceeded for {}: {projected} > {}",
                source.display(),
                self.max_total_bytes
            )));
        }
        Ok(())
    }

    fn commit(&mut self, bytes: u64) -> Result<()> {
        self.bytes = self.bytes.checked_add(bytes).ok_or_else(|| {
            NetdiagError::InvalidTrace("evidence snapshot byte count overflowed".to_string())
        })?;
        self.sources += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
