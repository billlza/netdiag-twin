use super::http_endpoint::validate_profile_http_endpoints;
use super::{validate_query_mapping, validate_website_targets, validate_wire_mapping};
use crate::settings::validation::budget::SettingsBudget;
use crate::settings::{LEGACY_LIVE_API_SCOPE_ID, SourceProfile};
use anyhow::Result;

pub(super) fn validate_profile(profile: &SourceProfile, budget: &mut SettingsBudget) -> Result<()> {
    budget.validate_string("source profile id", &profile.id, false)?;
    if profile.id == LEGACY_LIVE_API_SCOPE_ID {
        anyhow::bail!("source profile id is reserved for the legacy Live API credential scope");
    }
    budget.validate_string("source profile name", &profile.name, false)?;
    profile.local_probe.validate()?;
    profile.website_probe.validate()?;
    profile.http_json.validated_timeout_secs()?;
    profile.prometheus_query.validate()?;
    profile.otlp_grpc.validate()?;
    profile.native_pcap.validate()?;
    profile.system_counters.validate()?;
    validate_website_targets(
        "profile website probe",
        &profile.website_probe.targets,
        budget,
    )?;
    validate_profile_http_endpoints(profile, budget)?;
    for (kind, value) in [
        (
            "profile OTLP bind address",
            profile.otlp_grpc.bind_addr.as_str(),
        ),
        ("profile pcap source", profile.native_pcap.source.as_str()),
        (
            "profile system-counter interface",
            profile.system_counters.interface.as_str(),
        ),
    ] {
        budget.validate_string(kind, value, true)?;
    }
    validate_query_mapping(
        "profile Prometheus query mapping",
        &profile.prometheus_query.mapping,
        budget,
    )?;
    validate_wire_mapping(
        "profile Prometheus exposition mapping",
        &profile.prometheus_exposition.mapping,
        budget,
    )?;
    validate_wire_mapping("profile OTLP mapping", &profile.otlp_grpc.mapping, budget)
}
