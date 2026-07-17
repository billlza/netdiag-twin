use super::super::http_endpoint::parse_http_endpoint;
use crate::error::{NetdiagError, Result};
use std::fmt;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalHttpOrigin(String);

impl CanonicalHttpOrigin {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(super) fn from_parsed(endpoint: &reqwest::Url) -> Self {
        Self(endpoint.origin().ascii_serialization())
    }
}

impl fmt::Debug for CanonicalHttpOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("CanonicalHttpOrigin")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for CanonicalHttpOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub fn canonical_http_origin(endpoint: &str) -> Result<CanonicalHttpOrigin> {
    let endpoint = parse_http_endpoint(endpoint)
        .map_err(|error| NetdiagError::Connector(format!("HTTP endpoint {error}")))?;
    Ok(CanonicalHttpOrigin::from_parsed(&endpoint))
}
