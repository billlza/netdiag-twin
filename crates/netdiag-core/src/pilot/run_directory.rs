use crate::error::Result;
use crate::storage::{
    OwnedArtifactRoot, StagedAtomicDirectory, create_root_bound_staged_directory,
};
use uuid::Uuid;

pub(super) fn create_staged_pilot_run(
    owned: &OwnedArtifactRoot,
    pilot_id: &str,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<StagedAtomicDirectory> {
    let pilot_root = std::path::Path::new("pilot-runs").join(pilot_id);
    let directory_name = format!(
        "{}-{}",
        created_at.format("%Y%m%dT%H%M%S%.3fZ"),
        Uuid::new_v4().simple()
    );
    create_root_bound_staged_directory(
        owned,
        &pilot_root,
        directory_name.into(),
        "pilot run staging failed",
    )
}

#[cfg(test)]
mod tests;
