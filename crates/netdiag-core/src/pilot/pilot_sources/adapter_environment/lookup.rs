use super::redaction::passthrough_redaction_values;
use super::{AdapterEnvironment, PilotSource};
use crate::error::{NetdiagError, Result};
use std::env::{self, VarError};
use std::path::Path;

const MAX_RUNTIME_ENV_VALUE_BYTES: usize = 64 * 1024;
const MAX_RUNTIME_ENV_TOTAL_BYTES: usize = 256 * 1024;
const SYSTEM_ENVIRONMENT: [&str; 3] = ["TMPDIR", "TMP", "TEMP"];

pub(super) fn build(
    source: &PilotSource,
    runtime_path: &str,
    runtime_directory: &Path,
) -> Result<AdapterEnvironment> {
    let mut lookup = |name: &str| env::var(name);
    build_with_lookup(source, runtime_path, runtime_directory, &mut lookup)
}

fn build_with_lookup(
    source: &PilotSource,
    runtime_path: &str,
    runtime_directory: &Path,
    lookup: &mut dyn FnMut(&str) -> std::result::Result<String, VarError>,
) -> Result<AdapterEnvironment> {
    let runtime_directory = runtime_directory.to_str().ok_or_else(|| {
        NetdiagError::Connector(
            "adapter private runtime directory is not valid Unicode".to_string(),
        )
    })?;
    if !Path::new(runtime_directory).is_absolute() {
        return Err(NetdiagError::Connector(
            "adapter private runtime directory must be absolute".to_string(),
        ));
    }
    let mut environment = AdapterEnvironment {
        redaction_values: passthrough_redaction_values(&source.adapter.args),
        ..AdapterEnvironment::default()
    };
    environment
        .entries
        .push(("PATH".to_string(), runtime_path.to_string()));
    for name in SYSTEM_ENVIRONMENT {
        environment
            .entries
            .push((name.to_string(), runtime_directory.to_string()));
    }

    let mut total = 0_usize;
    for name in &source.adapter.env_allowlist {
        let value = match lookup(name) {
            Ok(value) => value,
            Err(VarError::NotPresent) => {
                return Err(NetdiagError::Connector(format!(
                    "adapter source {} explicitly allows environment variable {name}, but it is not set",
                    source.name
                )));
            }
            Err(VarError::NotUnicode(_)) => {
                return Err(NetdiagError::Connector(format!(
                    "adapter source {} environment variable {name} is not valid Unicode",
                    source.name
                )));
            }
        };
        if value.is_empty() {
            return Err(NetdiagError::Connector(format!(
                "adapter source {} environment variable {name} is empty",
                source.name
            )));
        }
        if value.len() > MAX_RUNTIME_ENV_VALUE_BYTES {
            return Err(NetdiagError::Connector(format!(
                "adapter source {} environment variable {name} exceeds {MAX_RUNTIME_ENV_VALUE_BYTES} bytes",
                source.name
            )));
        }
        total = total.checked_add(value.len()).ok_or_else(|| {
            NetdiagError::Connector(format!(
                "adapter source {} environment size overflowed",
                source.name
            ))
        })?;
        if total > MAX_RUNTIME_ENV_TOTAL_BYTES {
            return Err(NetdiagError::Connector(format!(
                "adapter source {} allowed environment exceeds {MAX_RUNTIME_ENV_TOTAL_BYTES} bytes",
                source.name
            )));
        }
        environment.entries.push((name.to_string(), value.clone()));
        environment.redaction_values.push(value);
    }
    environment
        .redaction_values
        .sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    environment.redaction_values.dedup();
    Ok(environment)
}

#[cfg(test)]
mod tests;
