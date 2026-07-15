use super::{PilotManifest, PilotSource, PilotSourceInventory, PilotSourceKind};
use crate::error::{NetdiagError, Result};
use crate::reliability::{redact_json_value, redact_string, redact_url, write_text_atomic};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;

mod adapter_arguments;
pub(super) use adapter_arguments::redacted_adapter_argument;

pub(super) fn source_inventory(manifest: &PilotManifest) -> Result<Vec<PilotSourceInventory>> {
    manifest
        .sources
        .iter()
        .map(|source| {
            Ok(PilotSourceInventory {
                name: source.name.clone(),
                kind: source.kind,
                role: source.role,
                endpoint: redacted_endpoint(source),
                active: source.active,
                metadata: redacted_metadata(&source.metadata)?,
            })
        })
        .collect()
}

pub(super) fn redacted_endpoint(source: &PilotSource) -> String {
    let endpoint = match source.kind {
        PilotSourceKind::HttpJson
        | PilotSourceKind::PrometheusQuery
        | PilotSourceKind::PrometheusMetrics => redact_url(&source.endpoint),
        PilotSourceKind::OtlpGrpc => source
            .endpoint
            .trim()
            .parse::<SocketAddr>()
            .map_or_else(|_| "[redacted]".to_string(), |address| address.to_string()),
        _ => redact_string(&source.endpoint),
    };
    if source.bearer_token_env.is_some() && endpoint != "[redacted]" {
        let Ok(mut url) = reqwest::Url::parse(&endpoint) else {
            return "[redacted]".to_string();
        };
        url.query_pairs_mut().append_pair("auth", "[redacted-env]");
        url.to_string()
    } else {
        endpoint
    }
}

fn redacted_metadata(metadata: &BTreeMap<String, String>) -> Result<BTreeMap<String, String>> {
    let mut value = serde_json::to_value(metadata)?;
    redact_json_value(&mut value);
    serde_json::from_value(value).map_err(Into::into)
}

pub(super) fn persist_redacted_pilot_manifest(manifest: &PilotManifest, path: &Path) -> Result<()> {
    let mut redacted_manifest = manifest.clone();
    for source in &mut redacted_manifest.sources {
        let endpoint = redacted_endpoint(source);
        source.endpoint = endpoint;
        source.adapter.args = source
            .adapter
            .args
            .iter()
            .map(|argument| redacted_adapter_argument(argument))
            .collect();
    }
    let mut value = serde_json::to_value(redacted_manifest)?;
    redact_json_value(&mut value);
    let manifest: PilotManifest = serde_json::from_value(value)?;
    let body = serde_yaml::to_string(&manifest).map_err(|err| {
        NetdiagError::InvalidTrace(format!("failed to render redacted pilot manifest: {err}"))
    })?;
    write_text_atomic(path, &body).map(drop)
}
