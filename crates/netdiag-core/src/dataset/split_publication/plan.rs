use crate::dataset::DatasetPartition;
use crate::dataset::rows::{DatasetRow, label_distribution};
use crate::dataset::trusted_root::TrustedDatasetRoot;
use crate::error::{NetdiagError, Result};
use crate::storage::BoundAtomicFileTarget;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const RECEIPT_FILE_NAME: &str = ".dataset-split-transaction.json";
pub(super) const MANIFEST_FILE_NAME: &str = "dataset_manifest.json";

mod receipt;
pub(super) use receipt::SplitReceipt;

#[derive(Clone)]
pub(super) struct PartitionPlan {
    pub(super) target: BoundAtomicFileTarget,
    pub(super) receipt: PartitionReceipt,
}

pub(super) struct SplitTargets {
    pub(super) train: PartitionPlan,
    pub(super) validation: PartitionPlan,
    pub(super) test: Option<PartitionPlan>,
    pub(super) test_target: BoundAtomicFileTarget,
    pub(super) manifest: BoundAtomicFileTarget,
    pub(super) receipt: BoundAtomicFileTarget,
}

impl SplitTargets {
    pub(super) fn new(
        root: &TrustedDatasetRoot,
        stem: &str,
        train_rows: &[DatasetRow],
        validation_rows: &[DatasetRow],
        test_rows: &[DatasetRow],
    ) -> Result<Self> {
        let train = PartitionPlan::new(root.target(&format!("{stem}-train.jsonl"))?, train_rows)?;
        let validation = PartitionPlan::new(
            root.target(&format!("{stem}-validation.jsonl"))?,
            validation_rows,
        )?;
        let test_target = root.target(&format!("{stem}-test.jsonl"))?;
        let test = (!test_rows.is_empty())
            .then(|| PartitionPlan::new(test_target.clone(), test_rows))
            .transpose()?;
        Ok(Self {
            train,
            validation,
            test,
            test_target,
            manifest: root.target(MANIFEST_FILE_NAME)?,
            receipt: root.target(RECEIPT_FILE_NAME)?,
        })
    }

    pub(super) fn public_targets(&self) -> [&BoundAtomicFileTarget; 4] {
        [
            &self.train.target,
            &self.validation.target,
            &self.test_target,
            &self.manifest,
        ]
    }
}

impl PartitionPlan {
    pub(super) fn new(target: BoundAtomicFileTarget, rows: &[DatasetRow]) -> Result<Self> {
        let file_name = target
            .target_name()
            .to_str()
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(format!(
                    "dataset split output name is not valid UTF-8: {}",
                    target.resolved_path().display()
                ))
            })?
            .to_string();
        let (byte_len, hash_sha256) = partition_identity(rows)?;
        Ok(Self {
            target,
            receipt: PartitionReceipt {
                file_name,
                byte_len,
                rows: rows.len(),
                hash_sha256,
                label_distribution: label_distribution(rows),
            },
        })
    }

    pub(super) fn report(&self) -> DatasetPartition {
        DatasetPartition {
            path: self.target.resolved_path().display().to_string(),
            rows: self.receipt.rows,
            hash_sha256: self.receipt.hash_sha256.clone(),
            label_distribution: self.receipt.label_distribution.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PartitionReceipt {
    pub(super) file_name: String,
    pub(super) byte_len: u64,
    pub(super) rows: usize,
    pub(super) hash_sha256: String,
    pub(super) label_distribution: BTreeMap<String, usize>,
}

fn partition_identity(rows: &[DatasetRow]) -> Result<(u64, String)> {
    let mut byte_len = 0_u64;
    let mut hasher = Sha256::new();
    for row in rows {
        let line_bytes = u64::try_from(row.line.len()).map_err(|_| {
            NetdiagError::InvalidTrace(
                "dataset split partition line size could not be represented".to_string(),
            )
        })?;
        byte_len = byte_len
            .checked_add(line_bytes)
            .and_then(|bytes| bytes.checked_add(1))
            .ok_or_else(|| {
                NetdiagError::InvalidTrace("dataset split partition size overflowed".to_string())
            })?;
        hasher.update(row.line.as_bytes());
        hasher.update(b"\n");
    }
    Ok((byte_len, hex_digest(hasher.finalize())))
}

pub(super) fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
