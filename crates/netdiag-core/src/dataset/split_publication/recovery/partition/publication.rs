use super::super::{preserve_failed_noclobber_state, target_exists};
use super::{PartitionPlan, verify_owned_partition};
use crate::dataset::rows::DatasetRow;
use crate::dataset::trusted_root::TrustedDatasetRoot;
use crate::error::{AtomicPublishPhase, IoContext, Result};
use crate::storage::{NoClobberDisposition, write_file_atomically_noclobber_or_existing_to_bound};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

pub(in crate::dataset::split_publication) fn recover_or_publish(
    root: &TrustedDatasetRoot,
    plan: &PartitionPlan,
    rows: &[DatasetRow],
) -> Result<crate::dataset::DatasetPartition> {
    recover_or_publish_with(root, plan, rows, verify_owned_partition)
}

fn recover_or_publish_with(
    root: &TrustedDatasetRoot,
    plan: &PartitionPlan,
    rows: &[DatasetRow],
    mut verify: impl FnMut(&PartitionPlan) -> Result<()>,
) -> Result<crate::dataset::DatasetPartition> {
    if target_exists(&plan.target)? {
        verify(plan)?;
        return Ok(plan.report());
    }
    let publication =
        write_file_atomically_noclobber_or_existing_to_bound(&plan.target, "jsonl", |file| {
            write_partition(file, plan.target.resolved_path(), rows)
        });
    match publication {
        Ok((NoClobberDisposition::Created, ())) => {
            if let Err(error) = verify(plan) {
                return root.remove_created_file_after_error(
                    &plan.target,
                    AtomicPublishPhase::Published,
                    error,
                );
            }
        }
        Ok((NoClobberDisposition::Existing, ())) => verify(plan)?,
        Err(error) => {
            return Err(preserve_failed_noclobber_state(&plan.target, error, || {
                verify(plan)
            }));
        }
    }
    Ok(plan.report())
}

fn write_partition(file: &mut File, path: &Path, rows: &[DatasetRow]) -> Result<()> {
    let mut writer = BufWriter::new(file);
    for row in rows {
        writer.write_all(row.line.as_bytes()).with_path(path)?;
        writer.write_all(b"\n").with_path(path)?;
    }
    writer.flush().with_path(path)
}

#[cfg(test)]
mod tests;
