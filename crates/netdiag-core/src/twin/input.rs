use super::{TopologyFormat, import_policy_action, import_topology};
use crate::error::{NetdiagError, Result};
use crate::models::{TopologyModel, TwinPolicyAction};
use crate::storage::read_stable_regular_file_bounded;
use std::path::Path;

pub(super) const MAX_TOPOLOGY_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const MAX_POLICY_FILE_BYTES: u64 = 256 * 1024;

pub fn load_topology_file(path: impl AsRef<Path>) -> Result<TopologyModel> {
    let path = path.as_ref();
    let input = read_required_utf8(path, MAX_TOPOLOGY_FILE_BYTES, "topology")?;
    import_topology(&input, format_for_path(path))
}

pub fn load_policy_action_file(path: impl AsRef<Path>) -> Result<TwinPolicyAction> {
    let path = path.as_ref();
    let input = read_required_utf8(path, MAX_POLICY_FILE_BYTES, "policy action")?;
    import_policy_action(&input, format_for_path(path))
}

fn read_required_utf8(path: &Path, max_bytes: u64, kind: &str) -> Result<String> {
    let bytes = read_stable_regular_file_bounded(path, max_bytes)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!("{kind} file is missing: {}", path.display()))
    })?;
    String::from_utf8(bytes).map_err(|error| {
        NetdiagError::InvalidTrace(format!(
            "{kind} file is not valid UTF-8 at {}: {error}",
            path.display()
        ))
    })
}

fn format_for_path(path: &Path) -> TopologyFormat {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "yaml" | "yml" => TopologyFormat::Yaml,
        _ => TopologyFormat::Json,
    }
}
