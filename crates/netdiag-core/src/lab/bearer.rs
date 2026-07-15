use super::{LabDataSource, LabDataSourceKind, LabScenario};
use crate::connectors::authentication::{
    BearerSourceDeclaration, BearerSourceKind, ResolvedBearerTokens, ValidatedBearerToken,
};
use crate::error::{NetdiagError, Result};
use std::collections::BTreeSet;

pub(super) fn declarations(scenario: &LabScenario) -> Result<Vec<BearerSourceDeclaration>> {
    let mut names = BTreeSet::new();
    let mut declarations = Vec::new();
    for source in &scenario.data_sources {
        let Some(declaration) = declaration(source)? else {
            continue;
        };
        let source_name = source.name.as_deref().ok_or_else(|| {
            NetdiagError::InvalidTrace(
                "authenticated lab data source name is missing after validation".to_string(),
            )
        })?;
        if !names.insert(source_name.to_ascii_lowercase()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab scenario {} has duplicate authenticated data source name {source_name:?}",
                scenario.id
            )));
        }
        declarations.push(declaration);
    }
    Ok(declarations)
}

pub(super) fn declaration(source: &LabDataSource) -> Result<Option<BearerSourceDeclaration>> {
    let Some(environment_variable) = source.bearer_token_env.clone() else {
        return Ok(None);
    };
    let source_name = source.name.clone().ok_or_else(|| {
        NetdiagError::InvalidTrace(
            "lab data source with bearer authentication must declare an explicit name".to_string(),
        )
    })?;
    crate::identifiers::validate_portable_id("authenticated lab data source name", &source_name)?;
    let source_kind = bearer_source_kind(source.kind).ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "lab data source {source_name:?} cannot declare bearer authentication for non-HTTP kind {}",
            source.kind.as_str()
        ))
    })?;
    BearerSourceDeclaration::new(
        source_name,
        source_kind,
        &source.endpoint,
        environment_variable,
    )
    .map(Some)
}

pub(super) fn token_for_source<'a>(
    source: &LabDataSource,
    resolved_tokens: &'a ResolvedBearerTokens,
) -> Result<Option<&'a ValidatedBearerToken>> {
    declaration(source)?
        .as_ref()
        .map(|declaration| resolved_tokens.token_for(declaration))
        .transpose()
}

fn bearer_source_kind(kind: LabDataSourceKind) -> Option<BearerSourceKind> {
    match kind {
        LabDataSourceKind::HttpJson => Some(BearerSourceKind::HttpJson),
        LabDataSourceKind::PrometheusQuery => Some(BearerSourceKind::PrometheusQuery),
        LabDataSourceKind::PrometheusMetrics => Some(BearerSourceKind::PrometheusMetrics),
        LabDataSourceKind::TraceFile
        | LabDataSourceKind::NativePcap
        | LabDataSourceKind::OtlpGrpc
        | LabDataSourceKind::SystemCounters => None,
    }
}
