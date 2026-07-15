use super::bounded_digest::{ensure_size_within_limit, read_and_hash};
use super::digest::hash_reader;
use crate::dataset::trusted_root::TrustedDatasetRoot;
use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::{OpenedFileIdentity, identity, open_file};
use crate::storage::StagedAtomicFile;
use std::ffi::OsStr;
use std::fs::{self, File, Metadata};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;
use std::time::SystemTime;

pub(super) struct CapturedSnapshot {
    pub(super) file: StagedAtomicFile,
    pub(super) hash_sha256: String,
}

pub(super) fn capture(
    source_path: &Path,
    root: &TrustedDatasetRoot,
    source_opened: impl FnOnce(),
    copy_completed: impl FnOnce(),
) -> Result<CapturedSnapshot> {
    let path_metadata = fs::symlink_metadata(source_path).with_path(source_path)?;
    if !is_regular_non_reparse(&path_metadata) {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset registration source must be a regular, non-symlink file: {}",
            source_path.display()
        )));
    }

    let mut source = open_file(source_path)?;
    let opened_metadata = source.metadata().with_path(source_path)?;
    let opened_identity = identity(&source, source_path)?;
    let current = open_file(source_path)?;
    let current_metadata = current.metadata().with_path(source_path)?;
    if !is_regular_non_reparse(&opened_metadata)
        || !is_regular_non_reparse(&current_metadata)
        || identity(&current, source_path)? != opened_identity
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset registration source changed while it was opened: {}",
            source_path.display()
        )));
    }
    ensure_size_within_limit(source_path, opened_metadata.len())?;
    let opened_modified = opened_metadata.modified().with_path(source_path)?;
    source_opened();

    let mut staged = StagedAtomicFile::reserve_in(
        root.directory_arc(),
        OsStr::new("dataset-registration"),
        "jsonl",
    )?;
    let operation = (|| {
        let staged_path = staged.path().to_path_buf();
        let streamed_hash =
            copy_bounded_and_hash(source_path, &mut source, &staged_path, staged.file_mut())?;
        copy_completed();

        source.seek(SeekFrom::Start(0)).with_path(source_path)?;
        let recaptured_hash = read_and_hash(source_path, &mut source, |_| Ok(()))?;
        if recaptured_hash != streamed_hash {
            return Err(NetdiagError::InvalidTrace(format!(
                "dataset registration source content changed while it was being copied: {}",
                source_path.display()
            )));
        }
        ensure_source_unchanged(
            source_path,
            &source,
            opened_identity,
            &opened_metadata,
            opened_modified,
        )?;

        staged.sync()?;
        staged
            .file_mut()
            .seek(SeekFrom::Start(0))
            .with_path(&staged_path)?;
        let copied_hash = hash_reader(staged.file_mut(), &staged_path)?;
        if copied_hash != streamed_hash {
            return Err(NetdiagError::InvalidTrace(format!(
                "dataset registration snapshot hash changed after copying {}",
                source_path.display()
            )));
        }
        Ok(copied_hash)
    })();
    match operation {
        Ok(hash_sha256) => Ok(CapturedSnapshot {
            file: staged,
            hash_sha256,
        }),
        Err(error) => Err(staged.abort(error)),
    }
}

fn copy_bounded_and_hash(
    source_path: &Path,
    input: &mut File,
    staged_path: &Path,
    output: &mut File,
) -> Result<String> {
    read_and_hash(source_path, input, |chunk| {
        output.write_all(chunk).with_path(staged_path)
    })
}

fn ensure_source_unchanged(
    source_path: &Path,
    source: &File,
    opened_identity: OpenedFileIdentity,
    opened_metadata: &Metadata,
    opened_modified: SystemTime,
) -> Result<()> {
    let final_opened_metadata = source.metadata().with_path(source_path)?;
    let final_path = open_file(source_path)?;
    let final_path_metadata = final_path.metadata().with_path(source_path)?;
    let final_modified = final_opened_metadata.modified().with_path(source_path)?;
    if !is_regular_non_reparse(&final_opened_metadata)
        || !is_regular_non_reparse(&final_path_metadata)
        || identity(&final_path, source_path)? != opened_identity
        || opened_metadata.len() != final_opened_metadata.len()
        || opened_modified != final_modified
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset registration source changed while it was being copied: {}",
            source_path.display()
        )));
    }
    Ok(())
}

fn is_regular_non_reparse(metadata: &Metadata) -> bool {
    metadata.is_file()
        && !metadata.file_type().is_symlink()
        && !netdiag_platform::metadata_is_reparse_point(metadata)
}
