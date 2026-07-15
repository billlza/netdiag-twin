use super::{PilotManifest, PilotSource, PilotSourceKind};
use crate::connectors::authentication::{
    BearerSourceDeclaration, BearerSourceKind, ResolvedBearerTokens, ValidatedBearerToken,
};
use crate::error::{NetdiagError, Result};

pub(super) fn declarations(manifest: &PilotManifest) -> Result<Vec<BearerSourceDeclaration>> {
    manifest
        .sources
        .iter()
        .filter_map(|source| declaration(source).transpose())
        .collect()
}

pub(super) fn declaration(source: &PilotSource) -> Result<Option<BearerSourceDeclaration>> {
    let Some(environment_variable) = source.bearer_token_env.clone() else {
        return Ok(None);
    };
    let source_kind = bearer_source_kind(source.kind).ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "pilot source {:?} cannot declare bearer authentication for non-HTTP kind {}",
            source.name,
            source_kind_name(source.kind)
        ))
    })?;
    BearerSourceDeclaration::new(
        source.name.clone(),
        source_kind,
        &source.endpoint,
        environment_variable,
    )
    .map(Some)
}

pub(super) fn token_for_source<'a>(
    source: &PilotSource,
    resolved_tokens: &'a ResolvedBearerTokens,
) -> Result<Option<&'a ValidatedBearerToken>> {
    declaration(source)?
        .as_ref()
        .map(|declaration| resolved_tokens.token_for(declaration))
        .transpose()
}

fn bearer_source_kind(kind: PilotSourceKind) -> Option<BearerSourceKind> {
    match kind {
        PilotSourceKind::HttpJson => Some(BearerSourceKind::HttpJson),
        PilotSourceKind::PrometheusQuery => Some(BearerSourceKind::PrometheusQuery),
        PilotSourceKind::PrometheusMetrics => Some(BearerSourceKind::PrometheusMetrics),
        PilotSourceKind::TraceFile
        | PilotSourceKind::AdapterSample
        | PilotSourceKind::OtlpGrpc
        | PilotSourceKind::NativePcap
        | PilotSourceKind::SystemCounters => None,
    }
}

fn source_kind_name(kind: PilotSourceKind) -> &'static str {
    match kind {
        PilotSourceKind::TraceFile => "trace-file",
        PilotSourceKind::AdapterSample => "adapter-sample",
        PilotSourceKind::HttpJson => "http-json",
        PilotSourceKind::PrometheusQuery => "prometheus-query",
        PilotSourceKind::PrometheusMetrics => "prometheus-metrics",
        PilotSourceKind::OtlpGrpc => "otlp-grpc",
        PilotSourceKind::NativePcap => "native-pcap",
        PilotSourceKind::SystemCounters => "system-counters",
    }
}

#[cfg(test)]
mod tests;
