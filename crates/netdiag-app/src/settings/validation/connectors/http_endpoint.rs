use crate::settings::validation::budget::SettingsBudget;
use crate::settings::{DataConnectorsSettings, SourceProfile};
use anyhow::Result;
use netdiag_core::connectors::validate_http_connector_endpoint;

pub(in crate::settings::validation) fn validate_optional_http_endpoint(
    kind: &str,
    value: &str,
    budget: &mut SettingsBudget,
) -> Result<()> {
    budget.validate_string(kind, value, true)?;
    if value.trim().is_empty() {
        return Ok(());
    }
    validate_http_connector_endpoint(value).map_err(|error| anyhow::anyhow!("{kind} {error}"))
}

pub(super) fn validate_connector_http_endpoints(
    connectors: &DataConnectorsSettings,
    budget: &mut SettingsBudget,
) -> Result<()> {
    for (kind, value) in [
        (
            "Prometheus base URL",
            connectors.prometheus_query.base_url.as_str(),
        ),
        (
            "Prometheus exposition endpoint",
            connectors.prometheus_exposition.endpoint.as_str(),
        ),
    ] {
        validate_optional_http_endpoint(kind, value, budget)?;
    }
    Ok(())
}

pub(super) fn validate_profile_http_endpoints(
    profile: &SourceProfile,
    budget: &mut SettingsBudget,
) -> Result<()> {
    for (kind, value) in [
        ("profile HTTP endpoint", profile.http_json.endpoint.as_str()),
        (
            "profile Prometheus base URL",
            profile.prometheus_query.base_url.as_str(),
        ),
        (
            "profile Prometheus exposition endpoint",
            profile.prometheus_exposition.endpoint.as_str(),
        ),
    ] {
        validate_optional_http_endpoint(kind, value, budget)?;
    }
    Ok(())
}
