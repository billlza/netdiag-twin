use crate::error::{NetdiagError, Result};
use crate::storage::prospective_component_alias;
use std::path::{Component, Path};

const RESERVED_MUTABLE_SUBTREES: [&str; 3] = ["runs", "lab-runs", "pilot-runs"];

pub(super) fn ensure_outside_reserved_subtrees(
    artifact_root: &Path,
    output: &Path,
    reported: &Path,
) -> Result<()> {
    let Ok(relative) = output.strip_prefix(artifact_root) else {
        return Ok(());
    };
    let Some(Component::Normal(first)) = relative.components().next() else {
        return Ok(());
    };
    if RESERVED_MUTABLE_SUBTREES
        .iter()
        .any(|reserved| prospective_component_alias(first, reserved.as_ref()))
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "snapshot output must not be inside a reserved artifact run subtree: {}",
            reported.display()
        )));
    }
    Ok(())
}
