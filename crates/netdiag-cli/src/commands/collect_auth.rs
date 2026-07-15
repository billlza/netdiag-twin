mod binding;

use netdiag_core::authentication::ValidatedBearerToken;

pub(crate) fn optional_bearer_token_from_lookup<F>(
    connector_kind: &str,
    endpoint: &str,
    environment_variable: Option<&str>,
    lookup: F,
) -> anyhow::Result<Option<ValidatedBearerToken>>
where
    F: FnMut(&str) -> std::result::Result<String, std::env::VarError>,
{
    let Some(environment_variable) = environment_variable else {
        return Ok(None);
    };
    binding::resolve(connector_kind, endpoint, environment_variable, lookup).map(Some)
}
