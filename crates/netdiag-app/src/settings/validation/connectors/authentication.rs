use crate::settings::{ConnectorAuthentication, SourceProfile};
use anyhow::{Result, bail};
use netdiag_core::connectors::validate_http_connector_bearer_endpoint;

pub(super) fn validate_profile_authentication(profile: &SourceProfile) -> Result<()> {
    if profile.authentication == ConnectorAuthentication::None {
        return Ok(());
    }
    if !profile.kind.supports_bearer_authentication() {
        bail!(
            "source profile {} cannot use bearer authentication with {}",
            profile.id,
            profile.kind.stable_name()
        );
    }
    let endpoint = profile
        .http_endpoint()
        .ok_or_else(|| anyhow::anyhow!("source profile has no HTTP endpoint"))?;
    validate_http_connector_bearer_endpoint(endpoint)
        .map_err(|error| anyhow::anyhow!("profile authenticated endpoint {error}"))
}
