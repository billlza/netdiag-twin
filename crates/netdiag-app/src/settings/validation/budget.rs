use anyhow::{Result, bail};

const MAX_SETTING_STRING_BYTES: usize = 16 * 1024;
const MAX_TOTAL_SETTING_STRING_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_WEBSITE_TARGETS: usize = 4_096;

#[derive(Default)]
pub(super) struct SettingsBudget {
    string_bytes: usize,
    website_targets: usize,
}

impl SettingsBudget {
    pub(super) fn validate_string(
        &mut self,
        kind: &str,
        value: &str,
        allow_empty: bool,
    ) -> Result<()> {
        if !allow_empty && value.trim().is_empty() {
            bail!("{kind} must not be empty");
        }
        if value.len() > MAX_SETTING_STRING_BYTES {
            bail!("{kind} exceeds the {MAX_SETTING_STRING_BYTES}-byte settings limit");
        }
        self.string_bytes = checked_total(
            "string bytes",
            self.string_bytes,
            value.len(),
            MAX_TOTAL_SETTING_STRING_BYTES,
        )?;
        Ok(())
    }

    pub(super) fn add_website_targets(&mut self, targets: usize) -> Result<()> {
        self.website_targets = checked_total(
            "website targets",
            self.website_targets,
            targets,
            MAX_TOTAL_WEBSITE_TARGETS,
        )?;
        Ok(())
    }
}

fn checked_total(kind: &str, current: usize, added: usize, maximum: usize) -> Result<usize> {
    let total = current
        .checked_add(added)
        .ok_or_else(|| anyhow::anyhow!("settings {kind} count overflowed"))?;
    if total > maximum {
        bail!("settings contain {total} {kind}, maximum is {maximum}");
    }
    Ok(total)
}
