use super::SettingsBudget;
use anyhow::Result;
use std::path::Path;

pub(super) fn validate_path(
    kind: &str,
    path: Option<&Path>,
    budget: &mut SettingsBudget,
) -> Result<()> {
    if let Some(path) = path {
        let path = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("{kind} must be valid Unicode to persist as JSON"))?;
        budget.validate_string(kind, path, false)?;
    }
    Ok(())
}
