use crate::error::{NetdiagError, Result};
use crate::reliability::{
    is_sensitive_parameter_key, query_contains_sensitive_or_ambiguous_syntax,
};
use reqwest::Url;
use std::net::IpAddr;

mod error;
pub use error::HttpEndpointError;

pub const MAX_HTTP_ENDPOINT_BYTES: usize = 16 * 1024;

pub(crate) fn parse_http_endpoint(value: &str) -> std::result::Result<Url, HttpEndpointError> {
    if value.len() > MAX_HTTP_ENDPOINT_BYTES {
        return Err(HttpEndpointError::TooLong);
    }
    let value = value.trim();
    if value.is_empty() {
        return Err(HttpEndpointError::Empty);
    }
    let url = Url::parse(value).map_err(|_| HttpEndpointError::Invalid)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(HttpEndpointError::UnsupportedScheme);
    }
    if !url.has_host() {
        return Err(HttpEndpointError::MissingHost);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(HttpEndpointError::UserInfo);
    }
    if url.fragment().is_some() {
        return Err(HttpEndpointError::Fragment);
    }
    if url
        .query_pairs()
        .any(|(key, _)| is_sensitive_parameter_key(&key))
        || url
            .query()
            .is_some_and(query_contains_sensitive_or_ambiguous_syntax)
    {
        return Err(HttpEndpointError::SensitiveQuery);
    }
    Ok(url)
}

pub fn validate_http_connector_endpoint(value: &str) -> std::result::Result<(), HttpEndpointError> {
    parse_http_endpoint(value).map(drop)
}

pub fn validate_http_connector_bearer_endpoint(
    value: &str,
) -> std::result::Result<(), HttpEndpointError> {
    let endpoint = parse_http_endpoint(value)?;
    require_bearer_transport(&endpoint)
}

pub(super) fn connector_endpoint(value: &str, context: &str) -> Result<Url> {
    parse_http_endpoint(value)
        .map_err(|error| NetdiagError::Connector(format!("{context} {error}")))
}

pub(super) fn require_bearer_transport(
    endpoint: &Url,
) -> std::result::Result<(), HttpEndpointError> {
    if endpoint.scheme() == "https" || is_loopback_ip_literal(endpoint) {
        Ok(())
    } else {
        Err(HttpEndpointError::InsecureBearerTransport)
    }
}

fn is_loopback_ip_literal(endpoint: &Url) -> bool {
    endpoint
        .host_str()
        .map(|host| {
            host.strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host)
        })
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}
