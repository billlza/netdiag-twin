use super::super::MAX_CURRENT_DESCRIPTOR_BYTES;
use super::super::trust::TrustedModelDirectory;
use super::validate_generation_name;
use crate::error::{NetdiagError, Result};
use crate::ml::MODEL_CURRENT_SCHEMA;
use crate::storage::read_stable_regular_file_bounded;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::ml::model_bundle) struct CurrentDescriptor {
    pub(in crate::ml::model_bundle) schema_version: String,
    pub(in crate::ml::model_bundle) generation: String,
}

impl CurrentDescriptor {
    pub(in crate::ml::model_bundle) fn new(generation: String) -> Self {
        Self {
            schema_version: MODEL_CURRENT_SCHEMA.to_string(),
            generation,
        }
    }
}

pub(super) fn read(
    bundle_root: &TrustedModelDirectory,
    path: &Path,
) -> Result<Option<CurrentDescriptor>> {
    bundle_root.validate()?;
    let result = (|| {
        let Some(bytes) = read_stable_regular_file_bounded(path, MAX_CURRENT_DESCRIPTOR_BYTES)?
        else {
            return Ok(None);
        };
        let descriptor: CurrentDescriptor =
            crate::strict_json::from_slice(&bytes).map_err(|error| {
                NetdiagError::Ml(format!(
                    "model current descriptor {} is invalid: {}",
                    path.display(),
                    crate::strict_json::error_summary(&error)
                ))
            })?;
        if descriptor.schema_version != MODEL_CURRENT_SCHEMA {
            return Err(NetdiagError::Ml(format!(
                "unsupported model current descriptor schema {}; expected {MODEL_CURRENT_SCHEMA}",
                descriptor.schema_version
            )));
        }
        validate_generation_name(&descriptor.generation)?;
        Ok(Some(descriptor))
    })();
    bundle_root.finish(result)
}
