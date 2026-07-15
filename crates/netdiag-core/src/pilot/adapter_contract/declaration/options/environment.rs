use crate::error::{NetdiagError, Result};
use crate::pilot::PilotSource;
use std::collections::BTreeSet;

const MAX_ADAPTER_ENVIRONMENT_VARIABLES: usize = 16;

pub(super) fn validate_env_allowlist(source: &PilotSource) -> Result<()> {
    if source.adapter.env_allowlist.len() > MAX_ADAPTER_ENVIRONMENT_VARIABLES {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} declares more than {MAX_ADAPTER_ENVIRONMENT_VARIABLES} environment variables",
            source.name
        )));
    }
    let mut names = BTreeSet::new();
    for name in &source.adapter.env_allowlist {
        let mut chars = name.chars();
        let valid_start = chars
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_');
        let valid_rest = chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !valid_start || !valid_rest || name.len() > 128 {
            return Err(NetdiagError::InvalidTrace(format!(
                "adapter source {} environment variable {name:?} is not a valid bounded name",
                source.name
            )));
        }
        let normalized = name.to_ascii_uppercase();
        if is_controlled_environment_name(&normalized) {
            return Err(NetdiagError::InvalidTrace(format!(
                "adapter source {} environment variable {name:?} overrides the controlled runtime environment",
                source.name
            )));
        }
        if !names.insert(normalized) {
            return Err(NetdiagError::InvalidTrace(format!(
                "adapter source {} repeats environment variable {name:?}",
                source.name
            )));
        }
    }
    Ok(())
}

fn is_controlled_environment_name(name: &str) -> bool {
    matches!(
        name,
        "PATH"
            | "PYTHONPATH"
            | "PYTHONHOME"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "TMPDIR"
            | "TMP"
            | "TEMP"
    ) || name.starts_with("DYLD_")
        || name.starts_with("PYTHON")
}
