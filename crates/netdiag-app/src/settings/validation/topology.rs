use super::budget::SettingsBudget;
use anyhow::Result;
use netdiag_core::models::TopologyModel;
use serde_json::Value;

pub(super) fn validate_topology_strings(
    topology: &TopologyModel,
    budget: &mut SettingsBudget,
) -> Result<()> {
    budget.validate_string("custom topology key", &topology.key, true)?;
    budget.validate_string("custom topology name", &topology.name, true)?;
    validate_metadata_strings("custom topology metadata", &topology.metadata, budget)?;
    for node in &topology.nodes {
        budget.validate_string("custom topology node id", &node.id, true)?;
        budget.validate_string("custom topology node label", &node.label, true)?;
        budget.validate_string("custom topology node role", &node.role, true)?;
        validate_metadata_strings("custom topology node metadata", &node.metadata, budget)?;
    }
    for link in &topology.links {
        budget.validate_string("custom topology link id", &link.id, true)?;
        budget.validate_string("custom topology link source", &link.source, true)?;
        budget.validate_string("custom topology link target", &link.target, true)?;
        validate_metadata_strings("custom topology link metadata", &link.metadata, budget)?;
    }
    Ok(())
}

fn validate_metadata_strings(
    kind: &str,
    metadata: &std::collections::BTreeMap<String, Value>,
    budget: &mut SettingsBudget,
) -> Result<()> {
    let mut pending = Vec::with_capacity(metadata.len());
    for (key, value) in metadata {
        budget.validate_string(kind, key, true)?;
        pending.push(value);
    }
    while let Some(value) = pending.pop() {
        match value {
            Value::String(value) => budget.validate_string(kind, value, true)?,
            Value::Array(values) => pending.extend(values),
            Value::Object(values) => {
                for (key, value) in values {
                    budget.validate_string(kind, key, true)?;
                    pending.push(value);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    Ok(())
}
