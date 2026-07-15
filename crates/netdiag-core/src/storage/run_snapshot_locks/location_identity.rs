use crate::error::{NetdiagError, Result};
use crate::storage::{RunLocation, read_manifest_at_location, resolve_run_location};
use std::path::Path;

mod path_identity;
use path_identity::PathIdentity;

pub(super) struct ResolvedRunLocation {
    pub(super) location: RunLocation,
    identities: RunLocationIdentities,
}

impl ResolvedRunLocation {
    pub(super) fn capture(artifact_root: &Path, run_id: &str) -> Result<Self> {
        let location = resolve_run_location(artifact_root, run_id)?;
        Self::capture_resolved(&location, run_id)
    }

    pub(super) fn capture_resolved(location: &RunLocation, run_id: &str) -> Result<Self> {
        let manifest = read_manifest_at_location(location)?;
        if manifest.run_id != run_id {
            return Err(NetdiagError::InvalidTrace(format!(
                "run location manifest id {} does not match requested run id {run_id}",
                manifest.run_id
            )));
        }
        let identities = RunLocationIdentities::capture(location)?;
        Ok(Self {
            location: location.clone(),
            identities,
        })
    }

    pub(super) fn ensure_same_location(&self, current: &Self) -> Result<()> {
        if same_location_paths(&self.location, &current.location)
            && self.identities.same_as(&current.identities)
        {
            return Ok(());
        }
        Err(NetdiagError::InvalidTrace(format!(
            "run location changed while acquiring evidence snapshot locks: {}",
            self.location.run_dir.display()
        )))
    }
}

fn same_location_paths(left: &RunLocation, right: &RunLocation) -> bool {
    left.artifact_root == right.artifact_root
        && left.run_dir == right.run_dir
        && left.lab_run_dir == right.lab_run_dir
        && left.lab_index_root == right.lab_index_root
}

struct RunLocationIdentities {
    artifact_root: PathIdentity,
    run_dir: PathIdentity,
    lab_run_dir: Option<PathIdentity>,
    lab_index_root: Option<PathIdentity>,
}

impl RunLocationIdentities {
    fn capture(location: &RunLocation) -> Result<Self> {
        Ok(Self {
            artifact_root: PathIdentity::capture(&location.artifact_root)?,
            run_dir: PathIdentity::capture(&location.run_dir)?,
            lab_run_dir: location
                .lab_run_dir
                .as_deref()
                .map(PathIdentity::capture)
                .transpose()?,
            lab_index_root: location
                .lab_index_root
                .as_deref()
                .map(PathIdentity::capture)
                .transpose()?,
        })
    }

    fn same_as(&self, current: &Self) -> bool {
        self.artifact_root.same_as(&current.artifact_root)
            && self.run_dir.same_as(&current.run_dir)
            && same_optional_identity(self.lab_run_dir.as_ref(), current.lab_run_dir.as_ref())
            && same_optional_identity(
                self.lab_index_root.as_ref(),
                current.lab_index_root.as_ref(),
            )
    }
}

fn same_optional_identity(left: Option<&PathIdentity>, right: Option<&PathIdentity>) -> bool {
    left.zip(right)
        .is_some_and(|(left, right)| left.same_as(right))
        || left.is_none() && right.is_none()
}
