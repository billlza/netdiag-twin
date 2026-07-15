use super::{FeedbackTrainingRow, MAX_FEEDBACK_EXPORT_BYTES};
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::{
    BoundAtomicFileTarget, SnapshotOutputTarget, with_exclusive_bound_file_lock,
    write_file_atomically_to_bound,
};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

mod digest_writer;
use digest_writer::DigestWriter;

pub(super) fn checked_serialized_size(current: u64, row: &FeedbackTrainingRow) -> Result<u64> {
    let row_bytes = u64::try_from(serde_json::to_vec(row)?.len())
        .map_err(|_| NetdiagError::InvalidTrace("feedback row size overflow".to_string()))?;
    let projected = current
        .checked_add(row_bytes)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| NetdiagError::InvalidTrace("feedback dataset size overflow".to_string()))?;
    if projected > MAX_FEEDBACK_EXPORT_BYTES {
        return Err(NetdiagError::InvalidTrace(format!(
            "feedback dataset exceeds the {MAX_FEEDBACK_EXPORT_BYTES}-byte safety limit"
        )));
    }
    Ok(projected)
}

pub(super) fn publish_dataset(
    output: &SnapshotOutputTarget,
    bound: &BoundAtomicFileTarget,
    rows: &[FeedbackTrainingRow],
) -> Result<String> {
    let path = output.path();
    with_exclusive_bound_file_lock(bound, || {
        write_jsonl_atomic(bound, path, rows).map(|(_, hash)| hash)
    })
}

fn write_jsonl_atomic(
    bound: &BoundAtomicFileTarget,
    path: &Path,
    rows: &[FeedbackTrainingRow],
) -> Result<(PathBuf, String)> {
    write_file_atomically_to_bound(bound, path, "jsonl", |file| {
        let mut writer = DigestWriter::new(BufWriter::new(file));
        for row in rows {
            serde_json::to_writer(&mut writer, row)?;
            writer.write_all(b"\n").with_path(path)?;
        }
        writer.finish(path)
    })
}
