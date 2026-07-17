use super::{AppSettings, MAX_SETTINGS_FILE_BYTES, validate_api_timeout};
use anyhow::Result;
use netdiag_core::connectors::validate_http_connector_bearer_endpoint;

mod artifacts_root;
mod bearer_credentials;
mod budget;
mod connectors;
mod path;
mod serialized_size;
mod topology;

use budget::SettingsBudget;
use connectors::{validate_connectors, validate_optional_http_endpoint};
use path::validate_path;
use serialized_size::validate_serialized_size;
use topology::validate_topology_strings;

pub(super) fn validate_settings(settings: &AppSettings) -> Result<()> {
    let mut budget = SettingsBudget::default();
    validate_path(
        "last imported trace",
        settings.last_imported_trace.as_deref(),
        &mut budget,
    )?;
    artifacts_root::validate(&settings.artifacts_root, &mut budget)?;
    validate_optional_http_endpoint("API endpoint", &settings.api.endpoint, &mut budget)?;
    if !settings.api.endpoint.trim().is_empty() {
        validate_http_connector_bearer_endpoint(&settings.api.endpoint)
            .map_err(|error| anyhow::anyhow!("API endpoint {error}"))?;
    }
    if settings.api.timeout_secs != 0 {
        validate_api_timeout(settings.api.timeout_secs)?;
    }
    budget.validate_string("what-if topology", &settings.what_if.topology, false)?;
    budget.validate_string("what-if action", &settings.what_if.action, false)?;
    if let Some(topology) = &settings.what_if.custom_topology {
        validate_topology_strings(topology, &mut budget)?;
    }
    validate_connectors(&settings.data_connectors, &mut budget)?;
    bearer_credentials::validate(settings, &mut budget)?;
    validate_serialized_size(settings, MAX_SETTINGS_FILE_BYTES)
}
