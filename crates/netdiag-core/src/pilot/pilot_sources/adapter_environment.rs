use super::super::PilotSource;
use crate::error::Result;
use std::path::Path;

mod lookup;
mod redaction;

#[derive(Debug, Clone, Default)]
pub(super) struct AdapterEnvironment {
    entries: Vec<(String, String)>,
    redaction_values: Vec<String>,
}

impl AdapterEnvironment {
    pub(super) fn from_source(
        source: &PilotSource,
        runtime_path: &str,
        runtime_directory: &Path,
    ) -> Result<Self> {
        lookup::build(source, runtime_path, runtime_directory)
    }

    pub(super) fn entries(&self) -> &[(String, String)] {
        &self.entries
    }

    pub(super) fn redaction_values(&self) -> &[String] {
        &self.redaction_values
    }
}
