use super::{MAX_PROBE_TARGET_BYTES, MAX_WEBSITE_PROBE_TARGETS};
use crate::error::{NetdiagError, Result};
use reqwest::Url;
use std::collections::BTreeSet;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub(super) enum ProbeTarget {
    Http(Url),
    Tcp(SocketAddr),
}

pub(super) fn parse_website_targets(values: &[String]) -> Result<Vec<ProbeTarget>> {
    if values.is_empty() {
        return Err(NetdiagError::Connector(
            "website probe requires at least one target".to_string(),
        ));
    }
    if values.len() > MAX_WEBSITE_PROBE_TARGETS {
        return Err(NetdiagError::Connector(format!(
            "website probe supports at most {MAX_WEBSITE_PROBE_TARGETS} targets"
        )));
    }

    let mut identities = BTreeSet::new();
    let mut targets = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let target = parse_target(value, index)?;
        if !identities.insert(target.identity()) {
            return Err(target_error(index, "duplicates another canonical target"));
        }
        targets.push(target);
    }
    Ok(targets)
}

fn parse_target(value: &str, index: usize) -> Result<ProbeTarget> {
    if value.is_empty() {
        return Err(target_error(index, "is empty"));
    }
    if value.len() > MAX_PROBE_TARGET_BYTES {
        return Err(target_error(index, "exceeds the 2048-byte limit"));
    }
    if value.trim() != value {
        return Err(target_error(
            index,
            "contains leading or trailing whitespace",
        ));
    }
    if value.contains("://") {
        return parse_http_target(value, index);
    }
    value
        .parse::<SocketAddr>()
        .map(ProbeTarget::Tcp)
        .map_err(|_| {
            target_error(
                index,
                "must be an exact http/https URL or an IP socket address",
            )
        })
}

fn parse_http_target(value: &str, index: usize) -> Result<ProbeTarget> {
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(target_error(
            index,
            "must use the lowercase http or https scheme",
        ));
    }
    let endpoint = super::super::http_endpoint::parse_http_endpoint(value)
        .map_err(|error| target_error(index, &error.to_string()))?;
    Ok(ProbeTarget::Http(endpoint))
}

impl ProbeTarget {
    fn identity(&self) -> String {
        match self {
            Self::Http(endpoint) => format!("http:{}", endpoint.as_str()),
            Self::Tcp(address) => format!("tcp:{address}"),
        }
    }
}

fn target_error(index: usize, reason: &str) -> NetdiagError {
    NetdiagError::Connector(format!(
        "website probe target {} {reason}",
        index.saturating_add(1)
    ))
}
