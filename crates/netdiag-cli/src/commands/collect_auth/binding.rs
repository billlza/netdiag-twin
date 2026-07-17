use netdiag_core::authentication::{
    BearerEnvironmentBinding, BearerEnvironmentBindings, BearerSourceDeclaration,
    ValidatedBearerToken,
};

use super::super::bearer_source_kind;

pub(super) fn resolve<F>(
    connector_kind: &str,
    endpoint: &str,
    environment_variable: &str,
    lookup: F,
) -> anyhow::Result<ValidatedBearerToken>
where
    F: FnMut(&str) -> std::result::Result<String, std::env::VarError>,
{
    let source_kind = bearer_source_kind::parse(connector_kind).map_err(|_| {
        anyhow::anyhow!("--bearer-token-env is only valid for HTTP/JSON and Prometheus connectors")
    })?;
    let declaration =
        BearerSourceDeclaration::new("cli-collect", source_kind, endpoint, environment_variable)?;
    let binding =
        BearerEnvironmentBinding::new("cli-collect", source_kind, endpoint, environment_variable)?;
    let bindings = BearerEnvironmentBindings::new([binding])?;
    let tokens = bindings.resolve_all_with_lookup(std::slice::from_ref(&declaration), lookup)?;
    tokens
        .into_token_for(&declaration)
        .map_err(anyhow::Error::from)
}
