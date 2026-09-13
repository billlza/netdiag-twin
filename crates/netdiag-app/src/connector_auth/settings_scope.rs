use super::{BearerSecretScope, BearerSourceKind, Result, bearer_scope_for_endpoint};

/// An empty settings form has no credential scope. Runtime requests and
/// credential writes still require a validated endpoint through the strict API.
pub fn live_api_settings_bearer_scope(endpoint: &str) -> Result<Option<BearerSecretScope>> {
    if endpoint.trim().is_empty() {
        return Ok(None);
    }
    bearer_scope_for_endpoint("legacy_live_api", BearerSourceKind::HttpJson, endpoint).map(Some)
}
