use crate::dataset::rows::{DatasetSummary, read_dataset_summary_from_reader};
use crate::dataset::split_publication::plan::{PartitionPlan, hex_digest};
use crate::error::{IoContext, NetdiagError, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

mod publication;
pub(in crate::dataset::split_publication) use publication::recover_or_publish;

#[derive(Debug, Eq, PartialEq)]
struct PartitionObservation {
    byte_len: u64,
    hash_sha256: String,
    summary: Option<DatasetSummary>,
}

pub(in crate::dataset::split_publication) fn verify_owned_partition(
    plan: &PartitionPlan,
) -> Result<()> {
    let mut semantic_failure = None;
    let actual = crate::storage::read_stable_regular_file_bounded_at_with(
        &plan.target,
        crate::dataset::limits::MAX_INPUT_BYTES,
        |file, path, max_bytes, read_limit, declared_bytes| {
            observe_partition(
                file,
                path,
                max_bytes,
                read_limit,
                declared_bytes,
                &mut semantic_failure,
            )
        },
    )?
    .ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "dataset split partition disappeared while it was verified: {}",
            plan.target.resolved_path().display()
        ))
    })?;
    let expected = &plan.receipt;
    if actual.hash_sha256 != expected.hash_sha256 || actual.byte_len != expected.byte_len {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset split owned partition does not match its transaction receipt at {}; refusing to overwrite",
            plan.target.resolved_path().display()
        )));
    }
    let summary = actual.summary.ok_or_else(|| {
        semantic_failure.take().unwrap_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "dataset split partition verification lost its semantic failure at {}",
                plan.target.resolved_path().display()
            ))
        })
    })?;
    if summary.rows != expected.rows || summary.label_distribution != expected.label_distribution {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset split owned partition does not match its transaction receipt at {}; refusing to overwrite",
            plan.target.resolved_path().display()
        )));
    }
    Ok(())
}

fn observe_partition(
    file: &mut File,
    path: &Path,
    max_bytes: u64,
    read_limit: u64,
    declared_bytes: u64,
    semantic_failure: &mut Option<NetdiagError>,
) -> Result<PartitionObservation> {
    let mut reader = HashingReader::new(file.take(read_limit));
    let summary = if declared_bytes == 0 {
        std::io::copy(&mut reader, &mut std::io::sink()).with_path(path)?;
        Some(DatasetSummary::default())
    } else {
        match read_dataset_summary_from_reader(path, BufReader::new(&mut reader)) {
            Ok(summary) => Some(summary),
            Err(error) => {
                // The parser may stop before EOF. Drain the same bounded stream so
                // ownership is still decided from the complete raw file identity.
                std::io::copy(&mut reader, &mut std::io::sink()).with_path(path)?;
                *semantic_failure = Some(error);
                None
            }
        }
    };
    let (byte_len, hash_sha256) = reader.finish();
    if byte_len > max_bytes || byte_len != declared_bytes {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset split partition changed while it was being verified: {}",
            path.display()
        )));
    }
    Ok(PartitionObservation {
        byte_len,
        hash_sha256,
        summary,
    })
}

struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> (u64, String) {
        (self.bytes, hex_digest(self.hasher.finalize()))
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        let read_bytes = u64::try_from(read)
            .map_err(|_| std::io::Error::other("partition byte count is not representable"))?;
        self.bytes = self
            .bytes
            .checked_add(read_bytes)
            .ok_or_else(|| std::io::Error::other("partition byte count overflowed"))?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}
