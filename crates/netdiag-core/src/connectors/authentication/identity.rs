use super::super::http_endpoint::{parse_http_endpoint, require_bearer_transport};
use super::authentication_error;
use super::origin::CanonicalHttpOrigin;
use crate::error::Result;
use std::fmt;

const MAX_SOURCE_NAME_BYTES: usize = 256;
const MAX_ENVIRONMENT_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BearerSourceKind {
    HttpJson,
    PrometheusQuery,
    PrometheusMetrics,
}

impl BearerSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpJson => "http-json",
            Self::PrometheusQuery => "prometheus-query",
            Self::PrometheusMetrics => "prometheus-metrics",
        }
    }
}

impl fmt::Display for BearerSourceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct BearerSourceIdentity {
    pub(super) source_name: String,
    source_kind: BearerSourceKind,
    canonical_origin: CanonicalHttpOrigin,
    pub(super) environment_variable: String,
}

impl BearerSourceIdentity {
    fn new(
        source_name: impl Into<String>,
        source_kind: BearerSourceKind,
        endpoint: &str,
        environment_variable: impl Into<String>,
    ) -> Result<Self> {
        let source_name = source_name.into();
        validate_source_name(&source_name)?;
        let environment_variable = environment_variable.into();
        validate_environment_variable_name(&environment_variable)?;
        let parsed = parse_http_endpoint(endpoint)
            .map_err(|error| authentication_error(format!("HTTP endpoint {error}")))?;
        require_bearer_transport(&parsed)
            .map_err(|error| authentication_error(format!("HTTP endpoint {error}")))?;
        Ok(Self {
            source_name,
            source_kind,
            canonical_origin: CanonicalHttpOrigin::from_parsed(&parsed),
            environment_variable,
        })
    }

    pub(super) fn description(&self) -> String {
        format!(
            "source {:?} ({}, origin {}, environment {:?})",
            self.source_name, self.source_kind, self.canonical_origin, self.environment_variable
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BearerEnvironmentBinding(pub(super) BearerSourceIdentity);

impl BearerEnvironmentBinding {
    pub fn new(
        source_name: impl Into<String>,
        source_kind: BearerSourceKind,
        endpoint: &str,
        environment_variable: impl Into<String>,
    ) -> Result<Self> {
        BearerSourceIdentity::new(source_name, source_kind, endpoint, environment_variable)
            .map(Self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BearerSourceDeclaration(pub(super) BearerSourceIdentity);

impl BearerSourceDeclaration {
    pub fn new(
        source_name: impl Into<String>,
        source_kind: BearerSourceKind,
        endpoint: &str,
        environment_variable: impl Into<String>,
    ) -> Result<Self> {
        BearerSourceIdentity::new(source_name, source_kind, endpoint, environment_variable)
            .map(Self)
    }
}

fn validate_source_name(source_name: &str) -> Result<()> {
    if source_name.is_empty()
        || source_name.trim() != source_name
        || source_name.len() > MAX_SOURCE_NAME_BYTES
    {
        return Err(authentication_error(format!(
            "bearer source name must contain 1..={MAX_SOURCE_NAME_BYTES} bytes with no surrounding whitespace"
        )));
    }
    Ok(())
}

pub fn validate_environment_variable_name(name: &str) -> Result<()> {
    let mut characters = name.chars();
    let valid_start = characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_');
    let valid_rest =
        characters.all(|character| character.is_ascii_alphanumeric() || character == '_');
    if !valid_start || !valid_rest || name.len() > MAX_ENVIRONMENT_NAME_BYTES {
        return Err(authentication_error(format!(
            "bearer environment variable name must be a valid 1..={MAX_ENVIRONMENT_NAME_BYTES}-byte name"
        )));
    }
    Ok(())
}
