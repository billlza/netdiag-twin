use crate::secrets::{BearerSecretScope, SecretStore};
use crate::settings::{ConnectorAuthentication, SourceProfile};
use anyhow::{Result, bail};
use netdiag_core::authentication::{BearerSourceKind, ValidatedBearerToken, canonical_http_origin};
use netdiag_core::connectors::validate_http_connector_bearer_endpoint;

mod settings_scope;
pub use settings_scope::live_api_settings_bearer_scope;

pub fn bearer_scope_for_endpoint(
    profile_id: &str,
    source_kind: BearerSourceKind,
    endpoint: &str,
) -> Result<BearerSecretScope> {
    let origin = canonical_http_origin(endpoint).map_err(anyhow::Error::from)?;
    BearerSecretScope::new(profile_id, source_kind, &origin)
}

pub fn profile_bearer_scope(profile: &SourceProfile) -> Result<Option<BearerSecretScope>> {
    if profile.authentication == ConnectorAuthentication::None {
        return Ok(None);
    }
    if !profile.kind.supports_bearer_authentication() {
        bail!(
            "source profile cannot use bearer authentication with {}",
            profile.kind.stable_name()
        );
    }
    let endpoint = profile
        .http_endpoint()
        .ok_or_else(|| anyhow::anyhow!("source profile has no HTTP endpoint"))?;
    bearer_scope_for_endpoint(&profile.id, bearer_source_kind(profile)?, endpoint).map(Some)
}

pub fn resolve_bearer_token(
    secrets: &dyn SecretStore,
    scope: Option<&BearerSecretScope>,
    source_kind: BearerSourceKind,
    endpoint: &str,
) -> Result<Option<ValidatedBearerToken>> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    validate_http_connector_bearer_endpoint(endpoint).map_err(anyhow::Error::from)?;
    let origin = canonical_http_origin(endpoint).map_err(anyhow::Error::from)?;
    scope.ensure_matches(source_kind, &origin)?;
    let token = secrets.get_bearer_token(scope)?.ok_or_else(|| {
        anyhow::anyhow!("bearer authentication is enabled but no token is bound to this source")
    })?;
    Ok(Some(token))
}

fn bearer_source_kind(profile: &SourceProfile) -> Result<BearerSourceKind> {
    match profile.kind {
        crate::settings::ConnectorKind::HttpJson => Ok(BearerSourceKind::HttpJson),
        crate::settings::ConnectorKind::PrometheusQueryRange => {
            Ok(BearerSourceKind::PrometheusQuery)
        }
        crate::settings::ConnectorKind::PrometheusExposition => {
            Ok(BearerSourceKind::PrometheusMetrics)
        }
        kind => bail!(
            "source profile cannot use bearer authentication with {}",
            kind.stable_name()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unconfigured_live_api_form_has_no_credential_scope() {
        for empty in ["", "   "] {
            assert_eq!(
                live_api_settings_bearer_scope(empty).expect("unconfigured form"),
                None
            );
            bearer_scope_for_endpoint("legacy_live_api", BearerSourceKind::HttpJson, empty)
                .expect_err("runtime and credential writes must still reject an empty endpoint");
        }
    }

    #[test]
    fn configured_live_api_forms_keep_origin_validation() {
        let endpoint = "https://example.com/trace";
        let expected =
            bearer_scope_for_endpoint("legacy_live_api", BearerSourceKind::HttpJson, endpoint)
                .expect("valid endpoint");
        assert_eq!(
            live_api_settings_bearer_scope(endpoint).expect("configured form"),
            Some(expected)
        );
        live_api_settings_bearer_scope("not a URL").expect_err("invalid configured endpoint");
    }
}
