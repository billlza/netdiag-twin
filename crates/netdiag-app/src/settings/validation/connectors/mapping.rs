use super::SettingsBudget;
use crate::settings::BTreeMapString;
use anyhow::{Result, bail};
use netdiag_core::connectors::{
    validate_prometheus_query_mapping as validate_core_query_mapping,
    validate_wire_metric_mapping as validate_core_wire_mapping,
};

const MAX_MAPPING_ENTRIES: usize = 256;

fn validate_mapping_shape(
    kind: &str,
    mapping: &BTreeMapString,
    budget: &mut SettingsBudget,
) -> Result<()> {
    if mapping.len() > MAX_MAPPING_ENTRIES {
        bail!("{kind} contains more than {MAX_MAPPING_ENTRIES} entries");
    }
    for (key, value) in mapping {
        budget.validate_string(kind, key, false)?;
        budget.validate_string(kind, value, false)?;
    }
    Ok(())
}

pub(super) fn validate_query_mapping(
    kind: &str,
    mapping: &BTreeMapString,
    budget: &mut SettingsBudget,
) -> Result<()> {
    validate_mapping_shape(kind, mapping, budget)?;
    validate_core_query_mapping(mapping).map_err(|error| anyhow::anyhow!("{kind} {error}"))
}

pub(super) fn validate_wire_mapping(
    kind: &str,
    mapping: &BTreeMapString,
    budget: &mut SettingsBudget,
) -> Result<()> {
    validate_mapping_shape(kind, mapping, budget)?;
    validate_core_wire_mapping(mapping).map_err(|error| anyhow::anyhow!("{kind} {error}"))
}
