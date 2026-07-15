use super::rows::DatasetRow;
use super::trusted_root::TrustedDatasetRoot;
use super::{DatasetManifest, DatasetPartition};
use crate::error::Result;
use crate::storage::{BoundAtomicFileTarget, with_exclusive_bound_file_lock};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

mod plan;
mod recovery;
#[cfg(test)]
mod tests;

use plan::{PartitionPlan, SplitReceipt, SplitTargets};

// Publication invariant: the durable receipt owns the flat output namespace
// before the first partition appears. Only an exact receipt match may resume;
// the public manifest remains the final commit record.

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SplitRequest {
    pub(super) seed: u64,
    pub(super) stratified: bool,
    pub(super) validation_ratio: f64,
    pub(super) test_ratio: f64,
}

pub(super) struct PublishedSplit {
    pub(super) output_dir: String,
    pub(super) train: DatasetPartition,
    pub(super) validation: DatasetPartition,
    pub(super) test: Option<DatasetPartition>,
    pub(super) manifest: DatasetManifest,
    pub(super) manifest_path: PathBuf,
}

#[derive(Clone, Copy)]
struct SplitRows<'a> {
    train: &'a [DatasetRow],
    validation: &'a [DatasetRow],
    test: &'a [DatasetRow],
}

pub(super) fn publish(
    output_dir: &Path,
    stem: &str,
    train_rows: &[DatasetRow],
    validation_rows: &[DatasetRow],
    test_rows: &[DatasetRow],
    manifest: &DatasetManifest,
    request: SplitRequest,
) -> Result<PublishedSplit> {
    publish_with_operations(
        output_dir,
        stem,
        SplitRows {
            train: train_rows,
            validation: validation_rows,
            test: test_rows,
        },
        manifest,
        request,
        |root, target| root.confirm_publication_durability(target),
        recovery::recover_or_publish,
    )
}

fn publish_with_operations(
    output_dir: &Path,
    stem: &str,
    rows: SplitRows<'_>,
    manifest: &DatasetManifest,
    request: SplitRequest,
    mut confirm_publication_durability: impl FnMut(
        &TrustedDatasetRoot,
        &BoundAtomicFileTarget,
    ) -> Result<()>,
    mut recover_or_publish: impl FnMut(
        &TrustedDatasetRoot,
        &PartitionPlan,
        &[DatasetRow],
    ) -> Result<DatasetPartition>,
) -> Result<PublishedSplit> {
    let root = TrustedDatasetRoot::open_durable(output_dir)?;
    let targets = SplitTargets::new(&root, stem, rows.train, rows.validation, rows.test)?;
    let receipt = SplitReceipt::new(
        manifest,
        request,
        &targets.train,
        &targets.validation,
        targets.test.as_ref(),
    );

    with_exclusive_bound_file_lock(&targets.manifest, || {
        root.validate()?;
        let mut manifest_committed = false;
        let result = (|| {
            let claim =
                recovery::claim(&root, &targets.receipt, &targets.public_targets(), &receipt)?;
            if claim.was_existing {
                confirm_publication_durability(&root, &targets.receipt)?;
            }
            let receipt = claim.receipt;
            let committed = recovery::target_exists(&targets.manifest)?;
            let (train_report, validation_report, test_report) = if committed {
                recovery::verify_committed_manifest(&targets.manifest, &receipt.manifest)?;
                manifest_committed = true;
                let train_report = recovery::verify_committed_partition(&targets.train)?;
                let validation_report = recovery::verify_committed_partition(&targets.validation)?;
                let test_report = match &targets.test {
                    Some(plan) => Some(recovery::verify_committed_partition(plan)?),
                    None => {
                        recovery::ensure_absent(
                            &[&targets.test_target],
                            "an unexpected test partition",
                        )?;
                        None
                    }
                };
                confirm_publication_durability(&root, &targets.manifest)?;
                (train_report, validation_report, test_report)
            } else {
                let train_report = recover_or_publish(&root, &targets.train, rows.train)?;
                let validation_report =
                    recover_or_publish(&root, &targets.validation, rows.validation)?;
                let test_report = match &targets.test {
                    Some(plan) => Some(recover_or_publish(&root, plan, rows.test)?),
                    None => {
                        recovery::ensure_absent(
                            &[&targets.test_target],
                            "an unexpected test partition",
                        )?;
                        None
                    }
                };
                recovery::publish_manifest(&targets.manifest, &receipt.manifest)?;
                manifest_committed = true;
                (train_report, validation_report, test_report)
            };
            Ok(PublishedSplit {
                output_dir: root.path().display().to_string(),
                train: train_report,
                validation: validation_report,
                test: test_report,
                manifest: receipt.manifest,
                manifest_path: targets.manifest.resolved_path().to_path_buf(),
            })
        })();
        if manifest_committed {
            root.finish_published(&targets.manifest, result)
        } else {
            root.finish(result)
        }
    })
}
