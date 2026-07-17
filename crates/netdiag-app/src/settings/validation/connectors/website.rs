use super::SettingsBudget;
use anyhow::{Result, bail};

const MAX_WEBSITE_TARGETS: usize = 64;

pub(super) fn validate_website_targets(
    kind: &str,
    targets: &[String],
    budget: &mut SettingsBudget,
) -> Result<()> {
    if targets.len() > MAX_WEBSITE_TARGETS {
        bail!("{kind} contains more than {MAX_WEBSITE_TARGETS} targets");
    }
    budget.add_website_targets(targets.len())?;
    for target in targets {
        budget.validate_string(kind, target, false)?;
    }
    Ok(())
}
