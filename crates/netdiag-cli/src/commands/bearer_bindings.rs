use clap::Args;
use netdiag_core::authentication::{
    BearerEnvironmentBinding, BearerEnvironmentBindings, canonical_http_origin,
};

use super::bearer_source_kind;

const BINDING_FIELDS: usize = 4;

#[derive(Debug, Clone, Default, Args)]
pub(crate) struct CliBearerBindings {
    /// Authorize one manifest bearer declaration: source name, HTTP source kind,
    /// canonical HTTP origin, and environment-variable name. Repeat for each source.
    #[arg(
        long = "bearer-binding",
        num_args = BINDING_FIELDS,
        action = clap::ArgAction::Append,
        value_names = ["SOURCE_NAME", "SOURCE_KIND", "CANONICAL_ORIGIN", "ENV_NAME"]
    )]
    values: Vec<String>,
}

impl CliBearerBindings {
    pub(crate) fn build(&self) -> anyhow::Result<BearerEnvironmentBindings> {
        if !self.values.len().is_multiple_of(BINDING_FIELDS) {
            anyhow::bail!("each --bearer-binding requires exactly four values");
        }
        self.values
            .chunks_exact(BINDING_FIELDS)
            .map(binding_from_values)
            .collect::<anyhow::Result<Vec<_>>>()
            .and_then(|bindings| BearerEnvironmentBindings::new(bindings).map_err(Into::into))
    }
}

fn binding_from_values(values: &[String]) -> anyhow::Result<BearerEnvironmentBinding> {
    let [source_name, source_kind, origin, environment_variable] = values else {
        anyhow::bail!("each --bearer-binding requires exactly four values");
    };
    let source_kind = bearer_source_kind::parse(source_kind)?;
    let canonical = canonical_http_origin(origin)?;
    if canonical.as_str() != origin {
        anyhow::bail!(
            "bearer binding origin must be canonical; expected {:?}",
            canonical.as_str()
        );
    }
    BearerEnvironmentBinding::new(source_name, source_kind, origin, environment_variable)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests;
