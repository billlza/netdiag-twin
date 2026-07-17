use super::verify_owned_partition;
use crate::dataset::DatasetPartition;
use crate::dataset::split_publication::plan::PartitionPlan;
use crate::error::{NetdiagError, Result};

mod manifest;
pub(in crate::dataset::split_publication) use manifest::{publish, verify};

pub(in crate::dataset::split_publication) fn verify_partition(
    plan: &PartitionPlan,
) -> Result<DatasetPartition> {
    if !super::target_exists(&plan.target)? {
        return Err(NetdiagError::InvalidTrace(format!(
            "committed dataset split partition is missing: {}",
            plan.target.resolved_path().display()
        )));
    }
    verify_owned_partition(plan)?;
    Ok(plan.report())
}
