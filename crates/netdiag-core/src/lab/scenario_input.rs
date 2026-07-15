use super::LabScenario;
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::{read_stable_regular_file_bounded, write_file_atomically};
use std::io::Write;
use std::path::Path;

pub(super) const MAX_LAB_SCENARIO_BYTES: u64 = 1024 * 1024;
mod validation;
pub use validation::validate_lab_scenario;

pub(super) struct LabScenarioSnapshot {
    scenario: LabScenario,
    bytes: Vec<u8>,
}

impl LabScenarioSnapshot {
    pub(super) fn scenario(&self) -> &LabScenario {
        &self.scenario
    }

    pub(super) fn publish_to(&self, target: &Path) -> Result<()> {
        write_file_atomically(target, "yaml", |file| {
            file.write_all(&self.bytes).with_path(target)
        })
        .map(|_| ())
    }

    pub(super) fn into_scenario(self) -> LabScenario {
        self.scenario
    }
}

pub(super) fn load_lab_scenario_snapshot(path: &Path) -> Result<LabScenarioSnapshot> {
    let bytes =
        read_stable_regular_file_bounded(path, MAX_LAB_SCENARIO_BYTES)?.ok_or_else(|| {
            NetdiagError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "lab scenario is missing",
                ),
            }
        })?;
    let scenario: LabScenario = serde_yaml::from_slice(&bytes)
        .map_err(|err| NetdiagError::InvalidTrace(format!("invalid lab scenario YAML: {err}")))?;
    validate_lab_scenario(&scenario)?;
    Ok(LabScenarioSnapshot { scenario, bytes })
}

pub fn load_lab_scenario(path: impl AsRef<Path>) -> Result<LabScenario> {
    Ok(load_lab_scenario_snapshot(path.as_ref())?.into_scenario())
}

#[cfg(test)]
mod tests;
