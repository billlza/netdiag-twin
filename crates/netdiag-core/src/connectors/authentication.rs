use crate::error::NetdiagError;
use std::fmt;

mod bindings;
mod identity;
mod origin;
mod token;

pub use bindings::{BearerEnvironmentBindings, ResolvedBearerTokens};
pub use identity::{
    BearerEnvironmentBinding, BearerSourceDeclaration, BearerSourceKind,
    validate_environment_variable_name,
};
pub use origin::{CanonicalHttpOrigin, canonical_http_origin};
pub use token::{MAX_BEARER_TOKEN_BYTES, ValidatedBearerToken, validate_bearer_token};

fn authentication_error(detail: impl fmt::Display) -> NetdiagError {
    NetdiagError::Connector(format!("bearer authentication failed: {detail}"))
}

#[cfg(test)]
mod tests;
