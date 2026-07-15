use super::{PilotSource, PilotSourceKind, redacted_endpoint};
use crate::connectors::authentication::ResolvedBearerTokens;
use crate::connectors::{
    ConnectorLoadResult, ConnectorResourceUsage, HttpJsonConfig, NativePcapConfig,
    NativePcapSource, OtlpGrpcReceiverConfig, PrometheusExpositionConfig,
    PrometheusQueryRangeConfig, SystemCountersConfig, default_prometheus_mapping, load_http_json,
    load_native_pcap, load_otlp_grpc_receiver, load_prometheus_exposition,
    load_prometheus_mapping_file, load_prometheus_query_range, load_system_counters,
    parse_http_endpoint,
};
use crate::error::{NetdiagError, Result};
use crate::ingest::{ingest_trace, ingest_trace_with_usage};
use crate::models::{ConnectorHealthSnapshot, ConnectorHealthStatus, IngestResult};
use crate::reliability::{ReliabilityCheck, ReliabilityReasonCode, redact_json_value};
use crate::storage::{PathStatus, path_status};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod adapter_args;
use adapter_args::adapter_preflight_invocation;
mod adapter_boundary;
pub(super) use adapter_boundary::AdapterExecutionBoundary;
mod adapter_environment;
mod adapter_source;
use adapter_source::load_adapter_sample_source;
mod payload_contract;
use super::bearer::{declaration as bearer_declaration, token_for_source};

pub(super) struct LoadedPilotSource {
    pub(super) source: PilotSource,
    pub(super) ingest: IngestResult,
    pub(super) health: ConnectorHealthSnapshot,
    pub(super) redacted_payload: Option<Value>,
}

pub(super) fn load_pilot_source_with_boundary(
    source: &PilotSource,
    base_dir: &Path,
    adapter_boundary: Option<&AdapterExecutionBoundary>,
    allow_adapter_execution: bool,
    resolved_tokens: &ResolvedBearerTokens,
) -> Result<LoadedPilotSource> {
    match source.kind {
        PilotSourceKind::TraceFile => {
            let loaded = load_trace_file_source(source, base_dir)?;
            Ok(from_connector_result("trace-file", source, loaded, None))
        }
        PilotSourceKind::AdapterSample => {
            load_adapter_sample_source(source, adapter_boundary, allow_adapter_execution)
        }
        PilotSourceKind::HttpJson => {
            let mut loaded = load_http_json(
                &HttpJsonConfig {
                    endpoint: source.endpoint.clone(),
                    timeout: timeout(source),
                },
                token_for_source(source, resolved_tokens)?,
            )?;
            let mut payload = loaded.payload.take().ok_or_else(|| {
                NetdiagError::Connector(format!(
                    "HTTP/JSON pilot source {} returned no payload",
                    source.name
                ))
            })?;
            redact_json_value(&mut payload);
            Ok(from_connector_result(
                "http-json",
                source,
                loaded,
                Some(payload),
            ))
        }
        PilotSourceKind::PrometheusQuery => {
            let loaded = load_prometheus_query_range(
                &PrometheusQueryRangeConfig {
                    base_url: source.endpoint.clone(),
                    timeout: timeout(source),
                    lookback_seconds: source.collection.lookback_secs,
                    step_seconds: source.collection.step_secs,
                    queries: load_mapping(source, base_dir)?,
                    sample: source.name.clone(),
                },
                token_for_source(source, resolved_tokens)?,
            )?;
            Ok(from_connector_result(
                "prometheus-query",
                source,
                loaded,
                None,
            ))
        }
        PilotSourceKind::PrometheusMetrics => {
            let loaded = load_prometheus_exposition(
                &PrometheusExpositionConfig {
                    endpoint: source.endpoint.clone(),
                    timeout: timeout(source),
                    metrics: load_mapping(source, base_dir)?,
                    sample: source.name.clone(),
                },
                token_for_source(source, resolved_tokens)?,
            )?;
            Ok(from_connector_result(
                "prometheus-metrics",
                source,
                loaded,
                None,
            ))
        }
        PilotSourceKind::OtlpGrpc => {
            let loaded = load_otlp_grpc_receiver(&OtlpGrpcReceiverConfig {
                bind_addr: source.endpoint.clone(),
                timeout: timeout(source),
                metrics: load_mapping(source, base_dir)?,
                sample: source.name.clone(),
            })?;
            Ok(from_connector_result("otlp-grpc", source, loaded, None))
        }
        PilotSourceKind::NativePcap => {
            let loaded = load_native_pcap(&NativePcapConfig {
                source: native_pcap_source(&source.endpoint, base_dir)?,
                timeout: timeout(source),
                packet_limit: source.collection.packet_limit,
                sample: source.name.clone(),
            })?;
            Ok(from_connector_result("native-pcap", source, loaded, None))
        }
        PilotSourceKind::SystemCounters => {
            let loaded = load_system_counters(&SystemCountersConfig {
                interface: system_counter_interface(&source.endpoint),
                interval: Duration::from_secs(source.collection.interval_secs),
                sample: source.name.clone(),
            })?;
            Ok(from_connector_result(
                "system-counters",
                source,
                loaded,
                None,
            ))
        }
    }
}

pub(super) fn check_source_static_with_boundary(
    source: &PilotSource,
    base_dir: &Path,
    adapter_boundary: Option<&AdapterExecutionBoundary>,
) -> ReliabilityCheck {
    let validation = validate_source_static(source, base_dir, adapter_boundary);
    let status = if validation.is_ok() {
        ConnectorHealthStatus::Ok
    } else {
        ConnectorHealthStatus::Error
    };
    ReliabilityCheck {
        name: format!("source {} valid", source.name),
        status,
        run_id: None,
        artifact: Some(redacted_endpoint(source)),
        reason_codes: if validation.is_ok() {
            Vec::new()
        } else {
            vec![source_static_failure_reason(source.kind)]
        },
        message: validation.unwrap_or_else(|err| err.to_string()),
    }
}

fn validate_source_static(
    source: &PilotSource,
    base_dir: &Path,
    adapter_boundary: Option<&AdapterExecutionBoundary>,
) -> Result<String> {
    bearer_declaration(source)?;
    match source.kind {
        PilotSourceKind::TraceFile => {
            let path = resolve_path(base_dir, &source.endpoint);
            if path_status(&path)? != PathStatus::RegularFile {
                return Err(NetdiagError::InvalidTrace(format!(
                    "trace file does not exist: {}",
                    path.display()
                )));
            }
            let ingest = ingest_trace(&path)?;
            Ok(format!(
                "trace file schema valid: {} rows from {}",
                ingest.schema.rows,
                path.display()
            ))
        }
        PilotSourceKind::AdapterSample => {
            let boundary = adapter_boundary.ok_or_else(|| {
                NetdiagError::InvalidTrace(
                    "adapter execution boundary is not configured".to_string(),
                )
            })?;
            let adapter = boundary.original_adapter(&source.name)?;
            adapter_preflight_invocation(source)?;
            Ok(format!(
                "trusted adapter path and contract are statically valid: {}",
                adapter.display()
            ))
        }
        PilotSourceKind::HttpJson => {
            validate_http_endpoint(&source.endpoint)?;
            Ok("HTTP/JSON endpoint URL is syntactically valid".to_string())
        }
        PilotSourceKind::PrometheusQuery | PilotSourceKind::PrometheusMetrics => {
            validate_http_endpoint(&source.endpoint)?;
            load_mapping(source, base_dir)?;
            Ok(format!(
                "{} endpoint and mapping are statically valid",
                source_kind_name(source.kind)
            ))
        }
        PilotSourceKind::OtlpGrpc => {
            let bind_addr =
                crate::connectors::parse_loopback_bind_addr(&source.endpoint).map_err(|_| {
                    NetdiagError::InvalidTrace(
                        "OTLP bind address must be a valid loopback host:port value".to_string(),
                    )
                })?;
            load_mapping(source, base_dir)?;
            Ok(format!("OTLP loopback bind address valid: {bind_addr}"))
        }
        PilotSourceKind::NativePcap => match native_pcap_source(&source.endpoint, base_dir)? {
            NativePcapSource::File(path) => {
                if path_status(&path)? == PathStatus::RegularFile {
                    Ok(format!("pcap file exists: {}", path.display()))
                } else {
                    Err(NetdiagError::InvalidTrace(format!(
                        "pcap file does not exist: {}",
                        path.display()
                    )))
                }
            }
            NativePcapSource::Interface(interface) => {
                if interface.trim().is_empty() {
                    Err(NetdiagError::InvalidTrace(
                        "pcap interface name is empty".to_string(),
                    ))
                } else {
                    Ok(format!("pcap interface configured: {interface}"))
                }
            }
        },
        PilotSourceKind::SystemCounters => Ok(if source.endpoint.trim().is_empty() {
            "system counters will sample all interfaces".to_string()
        } else {
            format!("system counters interface configured: {}", source.endpoint)
        }),
    }
}

fn load_trace_file_source(source: &PilotSource, base_dir: &Path) -> Result<ConnectorLoadResult> {
    let path = resolve_path(base_dir, &source.endpoint);
    let loaded = ingest_trace_with_usage(&path)?;
    let resource_usage = ConnectorResourceUsage {
        input_bytes: loaded.input_bytes,
        records: loaded.ingest.schema.rows,
    };
    let ingest = loaded.ingest;
    Ok(ConnectorLoadResult {
        sample: ingest.schema.sample.clone(),
        ingest,
        provenance: BTreeMap::from([
            ("kind".to_string(), "trace-file".to_string()),
            ("path".to_string(), path.display().to_string()),
        ]),
        payload: None,
        resource_usage,
    })
}

fn from_connector_result(
    source_kind: &str,
    source: &PilotSource,
    loaded: ConnectorLoadResult,
    redacted_payload: Option<Value>,
) -> LoadedPilotSource {
    let health = ConnectorHealthSnapshot::from_ingest(
        source_kind,
        &source.name,
        &loaded.sample,
        &loaded.ingest,
    );
    LoadedPilotSource {
        source: source.clone(),
        ingest: loaded.ingest,
        health,
        redacted_payload,
    }
}

fn load_mapping(source: &PilotSource, base_dir: &Path) -> Result<BTreeMap<String, String>> {
    let Some(mapping) = source
        .mapping
        .as_deref()
        .map(str::trim)
        .filter(|mapping| !mapping.is_empty())
    else {
        return Ok(default_prometheus_mapping());
    };
    let path = resolve_path(base_dir, mapping);
    load_prometheus_mapping_file(path)
}

fn timeout(source: &PilotSource) -> Duration {
    Duration::from_secs(source.collection.timeout_secs)
}

fn validate_http_endpoint(endpoint: &str) -> Result<()> {
    parse_http_endpoint(endpoint)
        .map(drop)
        .map_err(|error| NetdiagError::InvalidTrace(error.to_string()))
}

fn native_pcap_source(endpoint: &str, base_dir: &Path) -> Result<NativePcapSource> {
    let trimmed = endpoint.trim();
    if let Some(interface) = trimmed.strip_prefix("iface:") {
        return Ok(NativePcapSource::Interface(interface.trim().to_string()));
    }
    let path = resolve_path(base_dir, trimmed);
    match path_status(&path)? {
        PathStatus::RegularFile => Ok(NativePcapSource::File(path)),
        PathStatus::Missing if trimmed.ends_with(".pcap") || trimmed.contains('/') => {
            Ok(NativePcapSource::File(path))
        }
        PathStatus::Missing => Ok(NativePcapSource::Interface(trimmed.to_string())),
        _ => Err(NetdiagError::InvalidTrace(format!(
            "native pcap source is neither a regular file nor an explicit iface: value: {}",
            path.display()
        ))),
    }
}

fn system_counter_interface(endpoint: &str) -> Option<String> {
    let endpoint = endpoint.trim();
    (!endpoint.is_empty() && endpoint != "all").then(|| endpoint.to_string())
}

fn resolve_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn source_static_failure_reason(kind: PilotSourceKind) -> ReliabilityReasonCode {
    match kind {
        PilotSourceKind::TraceFile
        | PilotSourceKind::AdapterSample
        | PilotSourceKind::NativePcap => ReliabilityReasonCode::ArtifactMissing,
        PilotSourceKind::HttpJson
        | PilotSourceKind::PrometheusQuery
        | PilotSourceKind::PrometheusMetrics
        | PilotSourceKind::OtlpGrpc
        | PilotSourceKind::SystemCounters => ReliabilityReasonCode::UnreachableEndpoint,
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
