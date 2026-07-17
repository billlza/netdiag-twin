use super::budget::SettingsBudget;
use crate::settings::DataConnectorsSettings;
use crate::settings::otlp::validate_otlp_bind_addr;
use anyhow::{Result, bail};
use std::collections::HashSet;

mod authentication;
mod http_endpoint;
mod mapping;
mod profile;
mod website;
use authentication::validate_profile_authentication;
use http_endpoint::validate_connector_http_endpoints;
pub(in crate::settings::validation) use http_endpoint::validate_optional_http_endpoint;
use mapping::{validate_query_mapping, validate_wire_mapping};
use profile::validate_profile;
use website::validate_website_targets;

const MAX_SOURCE_PROFILES: usize = 64;

pub(super) fn validate_connectors(
    connectors: &DataConnectorsSettings,
    budget: &mut SettingsBudget,
) -> Result<()> {
    if connectors.profiles.is_empty() || connectors.profiles.len() > MAX_SOURCE_PROFILES {
        bail!("settings must contain 1..={MAX_SOURCE_PROFILES} source profiles");
    }
    budget.validate_string("active profile id", &connectors.active_profile_id, false)?;
    let mut ids = HashSet::with_capacity(connectors.profiles.len());
    for profile in &connectors.profiles {
        validate_profile_authentication(profile)?;
        validate_profile(profile, budget)?;
        if !ids.insert(profile.id.as_str()) {
            bail!("settings source profile id is duplicated: {}", profile.id);
        }
    }
    if !ids.contains(connectors.active_profile_id.as_str()) {
        bail!("settings active profile id does not name a source profile");
    }
    connectors.local_probe.validate()?;
    connectors.website_probe.validate()?;
    connectors.prometheus_query.validate()?;
    connectors.otlp_grpc.validate()?;
    connectors.native_pcap.validate()?;
    connectors.system_counters.validate()?;
    validate_website_targets("website probe", &connectors.website_probe.targets, budget)?;
    validate_query_mapping(
        "Prometheus query mapping",
        &connectors.prometheus_query.mapping,
        budget,
    )?;
    validate_wire_mapping(
        "Prometheus exposition mapping",
        &connectors.prometheus_exposition.mapping,
        budget,
    )?;
    validate_wire_mapping("OTLP mapping", &connectors.otlp_grpc.mapping, budget)?;
    validate_otlp_bind_addr(&connectors.otlp_grpc.bind_addr)?;
    validate_connector_strings(connectors, budget)
}

fn validate_connector_strings(
    connectors: &DataConnectorsSettings,
    budget: &mut SettingsBudget,
) -> Result<()> {
    validate_connector_http_endpoints(connectors, budget)?;
    for (kind, value) in [
        ("OTLP bind address", connectors.otlp_grpc.bind_addr.as_str()),
        ("pcap source", connectors.native_pcap.source.as_str()),
        (
            "system-counter interface",
            connectors.system_counters.interface.as_str(),
        ),
    ] {
        budget.validate_string(kind, value, true)?;
    }
    Ok(())
}
