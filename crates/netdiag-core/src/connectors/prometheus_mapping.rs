use crate::error::{NetdiagError, Result};
use crate::storage::read_stable_regular_file_bounded;
use std::collections::BTreeMap;
use std::path::Path;

mod decode;
mod unique_object;
use decode::decode_mapping;

const MAX_PROMETHEUS_MAPPING_BYTES: u64 = 1024 * 1024;

pub fn load_prometheus_mapping_file(path: impl AsRef<Path>) -> Result<BTreeMap<String, String>> {
    let path = path.as_ref();
    let bytes =
        read_stable_regular_file_bounded(path, MAX_PROMETHEUS_MAPPING_BYTES)?.ok_or_else(|| {
            NetdiagError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Prometheus mapping file is missing",
                ),
            }
        })?;
    let mapping = decode_mapping(&bytes, path)?;
    super::metric_mapping::validate_canonical_fields(&mapping).map_err(|error| {
        NetdiagError::InvalidTrace(format!("mapping file has invalid fields: {error}"))
    })?;
    Ok(mapping)
}

#[cfg(test)]
mod tests;
