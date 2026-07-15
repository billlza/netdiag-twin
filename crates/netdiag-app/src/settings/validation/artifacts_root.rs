use super::SettingsBudget;
use anyhow::Result;
use std::path::Path;

pub(super) fn validate(path: &Path, budget: &mut SettingsBudget) -> Result<()> {
    super::path::validate_path("artifacts root", Some(path), budget)?;
    netdiag_core::storage::validate_artifact_root_path(path)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}
