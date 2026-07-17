use super::super::{
    LabAcceptance, LabCollection, LabDataSourceRole, LabScenario, LabVerification, bearer,
};
use crate::error::{NetdiagError, Result};
use crate::resource_limits::{
    MAX_COLLECTION_TIMEOUT_SECS, MAX_DECLARED_SOURCES, MAX_PCAP_PACKET_LIMIT,
    MAX_TOTAL_SOURCE_EXECUTION_SECS,
};
use std::collections::BTreeMap;

const MAX_LAB_SCHEMA_BYTES: usize = 64;
pub(super) const MAX_LAB_NAME_BYTES: usize = 256;
const MAX_LAB_PATH_BYTES: usize = 4 * 1024;
const MAX_LAB_HASH_BYTES: usize = 256;
pub(super) const MAX_LAB_COLLECTION_ITEMS: usize = 128;
const MAX_LAB_ENUM_ITEMS: usize = 16;
pub(super) const MAX_LAB_SOURCES: usize = MAX_DECLARED_SOURCES;
const MAX_LAB_TOTAL_COLLECTION_TIMEOUT_SECS: u64 = MAX_TOTAL_SOURCE_EXECUTION_SECS;

pub fn validate_lab_scenario(scenario: &LabScenario) -> Result<()> {
    validate_bounded_text(
        "lab scenario schema",
        &scenario.schema,
        MAX_LAB_SCHEMA_BYTES,
    )?;
    if scenario.schema.trim() != "netdiag-lab-scenario/v1" {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported lab scenario schema: {}",
            scenario.schema
        )));
    }
    crate::identifiers::validate_portable_id("lab scenario id", &scenario.id)?;
    validate_bounded_text("lab scenario name", &scenario.name, MAX_LAB_NAME_BYTES)?;
    validate_source_count_and_budget(scenario)?;
    validate_lab_collection(&scenario.collection)?;

    let primary_count = scenario
        .data_sources
        .iter()
        .filter(|source| source.role == LabDataSourceRole::Primary)
        .count();
    if primary_count != 1 {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab scenario {} must declare exactly one primary data source",
            scenario.id
        )));
    }
    bearer::declarations(scenario)?;
    for source in &scenario.data_sources {
        if let Some(name) = source.name.as_deref() {
            validate_bounded_text("lab data source name", name, MAX_LAB_NAME_BYTES)?;
        }
        validate_bounded_text(
            "lab data source endpoint",
            &source.endpoint,
            MAX_LAB_PATH_BYTES,
        )?;
        if let Some(mapping) = source.mapping.as_deref() {
            validate_bounded_text("lab data source mapping path", mapping, MAX_LAB_PATH_BYTES)?;
        }
    }
    if let Some(topology) = scenario.topology.as_deref() {
        validate_bounded_text("lab topology path", topology, MAX_LAB_PATH_BYTES)?;
    }
    if let Some(what_if) = &scenario.what_if {
        validate_bounded_text(
            "lab what-if topology path",
            &what_if.topology,
            MAX_LAB_PATH_BYTES,
        )?;
        validate_bounded_text(
            "lab what-if policy path",
            &what_if.policy,
            MAX_LAB_PATH_BYTES,
        )?;
    }
    validate_acceptance(&scenario.acceptance)?;
    validate_verification(&scenario.verification)
}

fn validate_source_count_and_budget(scenario: &LabScenario) -> Result<()> {
    let source_count = scenario.data_sources.len();
    if source_count == 0 {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab scenario {} has no data_sources",
            scenario.id
        )));
    }
    if source_count > MAX_LAB_SOURCES {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab scenario {} has more than {MAX_LAB_SOURCES} data sources",
            scenario.id
        )));
    }
    let source_count = u64::try_from(source_count).map_err(|_| {
        NetdiagError::InvalidTrace("lab collection source count cannot fit in u64".to_string())
    })?;
    let total_timeout = scenario
        .collection
        .timeout_secs
        .checked_mul(source_count)
        .ok_or_else(|| {
            NetdiagError::InvalidTrace("lab collection execution budget overflowed".to_string())
        })?;
    if total_timeout > MAX_LAB_TOTAL_COLLECTION_TIMEOUT_SECS {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab collection execution budget {total_timeout}s exceeds {MAX_LAB_TOTAL_COLLECTION_TIMEOUT_SECS}s"
        )));
    }
    Ok(())
}

fn validate_lab_collection(collection: &LabCollection) -> Result<()> {
    if !(1..=MAX_COLLECTION_TIMEOUT_SECS).contains(&collection.timeout_secs) {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab collection timeout_secs must be between 1 and {MAX_COLLECTION_TIMEOUT_SECS}"
        )));
    }
    if !(1..=86_400).contains(&collection.lookback_secs) {
        return Err(NetdiagError::InvalidTrace(
            "lab collection lookback_secs must be between 1 and 86400".to_string(),
        ));
    }
    if !(1..=3_600).contains(&collection.step_secs)
        || i64::try_from(collection.step_secs)
            .map(|step| step > collection.lookback_secs)
            .unwrap_or(true)
    {
        return Err(NetdiagError::InvalidTrace(
            "lab collection step_secs must be between 1 and 3600 and no greater than lookback_secs"
                .to_string(),
        ));
    }
    if !(1..=MAX_PCAP_PACKET_LIMIT).contains(&collection.packet_limit) {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab collection packet_limit must be between 1 and {MAX_PCAP_PACKET_LIMIT}"
        )));
    }
    if !(1..=10).contains(&collection.interval_secs) {
        return Err(NetdiagError::InvalidTrace(
            "lab collection interval_secs must be between 1 and 10".to_string(),
        ));
    }
    Ok(())
}

fn validate_acceptance(acceptance: &LabAcceptance) -> Result<()> {
    validate_probability("min_rule_confidence", acceptance.min_rule_confidence)?;
    validate_probability("min_ml_probability", acceptance.min_ml_probability)?;
    validate_collection_len("allowed_quality", acceptance.allowed_quality.len())?;
    for field in acceptance.allowed_quality.keys() {
        validate_bounded_text("allowed quality field", field, MAX_LAB_NAME_BYTES)?;
    }
    validate_len(
        "allowed connector statuses",
        acceptance.allowed_connector_status.len(),
        MAX_LAB_ENUM_ITEMS,
    )?;
    validate_len(
        "allowed diagnosis statuses",
        acceptance.allowed_diagnosis_statuses.len(),
        MAX_LAB_ENUM_ITEMS,
    )?;
    validate_collection_len("required artifacts", acceptance.required_artifacts.len())?;
    for artifact in &acceptance.required_artifacts {
        validate_bounded_text("required artifact", artifact, MAX_LAB_NAME_BYTES)?;
    }
    for (name, hash) in [
        (
            "required model dataset hash",
            acceptance.required_model_dataset_hash.as_deref(),
        ),
        (
            "required model manifest hash",
            acceptance.required_model_manifest_hash.as_deref(),
        ),
        (
            "required model file hash",
            acceptance.required_model_file_hash.as_deref(),
        ),
    ] {
        if let Some(hash) = hash {
            validate_bounded_text(name, hash, MAX_LAB_HASH_BYTES)?;
        }
    }
    Ok(())
}

fn validate_verification(verification: &LabVerification) -> Result<()> {
    validate_text_map("verification objective", &verification.objective)?;
    validate_text_map("verification fail_if", &verification.fail_if)
}

fn validate_text_map(kind: &str, values: &BTreeMap<String, String>) -> Result<()> {
    validate_collection_len(kind, values.len())?;
    for (key, value) in values {
        validate_bounded_text(&format!("{kind} key"), key, MAX_LAB_NAME_BYTES)?;
        validate_bounded_text(&format!("{kind} value"), value, MAX_LAB_PATH_BYTES)?;
    }
    Ok(())
}

fn validate_probability(kind: &str, value: f64) -> Result<()> {
    if value.is_finite() && (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "lab acceptance {kind} must be finite and between 0 and 1"
        )))
    }
}

fn validate_collection_len(kind: &str, length: usize) -> Result<()> {
    validate_len(kind, length, MAX_LAB_COLLECTION_ITEMS)
}

fn validate_len(kind: &str, length: usize, maximum: usize) -> Result<()> {
    if length <= maximum {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "lab {kind} has {length} items; maximum is {maximum}"
        )))
    }
}

fn validate_bounded_text(kind: &str, value: &str, maximum: usize) -> Result<()> {
    if value.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace(format!("{kind} is empty")));
    }
    if value.len() > maximum {
        return Err(NetdiagError::InvalidTrace(format!(
            "{kind} exceeds {maximum} bytes"
        )));
    }
    Ok(())
}
