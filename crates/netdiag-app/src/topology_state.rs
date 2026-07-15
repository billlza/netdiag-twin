use netdiag_core::NetdiagError;
use netdiag_core::models::TopologyModel;
use netdiag_core::storage::save_json_atomic;
use netdiag_core::twin::{topology_model, validate_topology_model};
use std::path::Path;

pub(super) fn write_topology_export(
    path: &Path,
    topology: &TopologyModel,
) -> Result<(), NetdiagError> {
    validate_topology_model(topology)?;
    save_json_atomic(path, topology).map(drop)
}

pub(super) fn selected_topology_model(
    selection: &str,
    custom: Option<&TopologyModel>,
) -> Result<TopologyModel, NetdiagError> {
    let topology = if selection == "custom" {
        custom.cloned().ok_or_else(|| {
            NetdiagError::InvalidTrace(
                "custom topology is selected but no topology model is loaded".to_string(),
            )
        })?
    } else {
        topology_model(selection)?
    };
    validate_topology_model(&topology)?;
    Ok(topology)
}
