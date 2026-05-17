use super::adapter_contract::{
    adapter_contract_enabled, run_python_adapter, validate_adapter_preflight,
};
use super::{PilotSource, PilotSourceKind, redacted_endpoint, safe_name};
use crate::connectors::{
    ConnectorLoadResult, HttpJsonConfig, NativePcapConfig, NativePcapSource,
    OtlpGrpcReceiverConfig, PrometheusExpositionConfig, PrometheusQueryRangeConfig,
    SystemCountersConfig, default_prometheus_mapping, load_http_json, load_native_pcap,
    load_otlp_grpc_receiver, load_prometheus_exposition, load_prometheus_query_range,
    load_system_counters,
};
use crate::error::{IoContext, NetdiagError, Result};
use crate::ingest::{ingest_json_value, ingest_trace};
use crate::models::{ConnectorHealthSnapshot, ConnectorHealthStatus, IngestResult};
use crate::reliability::{ReliabilityCheck, ReliabilityReasonCode, redact_json_value};
use crate::storage::connector_health_from_ingest;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(super) struct LoadedPilotSource {
    pub(super) source: PilotSource,
    pub(super) ingest: IngestResult,
    pub(super) health: ConnectorHealthSnapshot,
    pub(super) redacted_payload: Option<Value>,
}

pub(super) fn load_pilot_source(
    source: &PilotSource,
    base_dir: &Path,
) -> Result<LoadedPilotSource> {
    match source.kind {
        PilotSourceKind::TraceFile => {
            let loaded = load_trace_file_source(source, base_dir)?;
            Ok(from_connector_result("trace-file", source, loaded, None))
        }
        PilotSourceKind::AdapterSample => load_adapter_sample_source(source, base_dir),
        PilotSourceKind::HttpJson => {
            let loaded = load_http_json(&HttpJsonConfig {
                endpoint: source.endpoint.clone(),
                bearer_token: bearer_token(source),
                timeout: timeout(source),
            })?;
            let mut payload = loaded.payload.clone().unwrap_or_else(|| json!({}));
            redact_json_value(&mut payload);
            Ok(from_connector_result(
                "http-json",
                source,
                loaded,
                Some(payload),
            ))
        }
        PilotSourceKind::PrometheusQuery => {
            let loaded = load_prometheus_query_range(&PrometheusQueryRangeConfig {
                base_url: source.endpoint.clone(),
                bearer_token: bearer_token(source),
                timeout: timeout(source),
                lookback_seconds: source.collection.lookback_secs,
                step_seconds: source.collection.step_secs.max(1),
                queries: load_mapping(source, base_dir)?,
                sample: safe_name(&source.name),
            })?;
            Ok(from_connector_result(
                "prometheus-query",
                source,
                loaded,
                None,
            ))
        }
        PilotSourceKind::PrometheusMetrics => {
            let loaded = load_prometheus_exposition(&PrometheusExpositionConfig {
                endpoint: source.endpoint.clone(),
                bearer_token: bearer_token(source),
                timeout: timeout(source),
                metrics: load_mapping(source, base_dir)?,
                sample: safe_name(&source.name),
            })?;
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
                sample: safe_name(&source.name),
            })?;
            Ok(from_connector_result("otlp-grpc", source, loaded, None))
        }
        PilotSourceKind::NativePcap => {
            let loaded = load_native_pcap(&NativePcapConfig {
                source: native_pcap_source(&source.endpoint, base_dir),
                timeout: timeout(source),
                packet_limit: source.collection.packet_limit.max(1),
                sample: safe_name(&source.name),
            })?;
            Ok(from_connector_result("native-pcap", source, loaded, None))
        }
        PilotSourceKind::SystemCounters => {
            let loaded = load_system_counters(&SystemCountersConfig {
                interface: system_counter_interface(&source.endpoint),
                interval: Duration::from_secs(source.collection.interval_secs.clamp(1, 10)),
                sample: safe_name(&source.name),
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

pub(super) fn check_source_static(source: &PilotSource, base_dir: &Path) -> ReliabilityCheck {
    let validation = validate_source_static(source, base_dir);
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

fn validate_source_static(source: &PilotSource, base_dir: &Path) -> Result<String> {
    match source.kind {
        PilotSourceKind::TraceFile => {
            let path = resolve_path(base_dir, &source.endpoint);
            if !path.is_file() {
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
            let path = resolve_path(base_dir, &source.endpoint);
            if !path.is_file() {
                Err(NetdiagError::InvalidTrace(format!(
                    "adapter file does not exist: {}",
                    path.display()
                )))
            } else if adapter_contract_enabled(source) {
                let adapter = path.canonicalize().with_path(&path)?;
                let output = run_python_adapter(
                    &adapter,
                    adapter.parent().unwrap_or(base_dir),
                    &["--preflight", "--emit-sample"],
                    timeout(source),
                )?;
                if !output.status.success() {
                    return Err(NetdiagError::Connector(format!(
                        "adapter preflight {} exited {}: {}",
                        adapter.display(),
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
                let preflight: Value = serde_json::from_slice(&output.stdout)?;
                validate_adapter_preflight(&preflight)?;
                Ok(format!(
                    "adapter contract preflight passed: {}",
                    adapter.display()
                ))
            } else {
                Ok(format!("adapter is present: {}", path.display()))
            }
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
            source
                .endpoint
                .trim()
                .parse::<SocketAddr>()
                .map_err(|err| {
                    NetdiagError::InvalidTrace(format!(
                        "OTLP bind address {} is not host:port: {err}",
                        source.endpoint
                    ))
                })?;
            load_mapping(source, base_dir)?;
            Ok(format!(
                "OTLP bind address shape valid: {}",
                source.endpoint
            ))
        }
        PilotSourceKind::NativePcap => match native_pcap_source(&source.endpoint, base_dir) {
            NativePcapSource::File(path) => {
                if path.is_file() {
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
    let ingest = ingest_trace(&path)?;
    Ok(ConnectorLoadResult {
        sample: ingest.schema.sample.clone(),
        ingest,
        provenance: BTreeMap::from([
            ("kind".to_string(), "trace-file".to_string()),
            ("path".to_string(), path.display().to_string()),
        ]),
        payload: None,
    })
}

fn load_adapter_sample_source(source: &PilotSource, base_dir: &Path) -> Result<LoadedPilotSource> {
    let adapter = resolve_path(base_dir, &source.endpoint);
    let adapter = adapter.canonicalize().with_path(&adapter)?;
    let args = if adapter_contract_enabled(source) {
        vec!["--collect", "--emit-sample"]
    } else {
        vec!["--emit-sample"]
    };
    let output = run_python_adapter(
        &adapter,
        adapter.parent().unwrap_or(base_dir),
        &args,
        timeout(source),
    )?;
    if !output.status.success() {
        return Err(NetdiagError::Connector(format!(
            "adapter sample {} exited {}: {}",
            adapter.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let payload: Value = serde_json::from_slice(&output.stdout)?;
    let ingest = ingest_json_value(payload.clone(), safe_name(&source.name))?;
    let mut redacted_payload = payload;
    redact_json_value(&mut redacted_payload);
    let health =
        connector_health_from_ingest("adapter-sample", &source.name, &source.name, &ingest);
    Ok(LoadedPilotSource {
        source: source.clone(),
        ingest,
        health,
        redacted_payload: Some(redacted_payload),
    })
}

fn from_connector_result(
    source_kind: &str,
    source: &PilotSource,
    loaded: ConnectorLoadResult,
    redacted_payload: Option<Value>,
) -> LoadedPilotSource {
    let health =
        connector_health_from_ingest(source_kind, &source.name, &loaded.sample, &loaded.ingest);
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
    let raw = fs::read_to_string(&path).with_path(&path)?;
    serde_json::from_str(&raw).map_err(|err| {
        NetdiagError::InvalidTrace(format!(
            "mapping file is not valid JSON: {}: {err}",
            path.display()
        ))
    })
}

fn bearer_token(source: &PilotSource) -> Option<String> {
    match &source.bearer_token_env {
        Some(name) => std::env::var(name).ok(),
        None => std::env::var("NETDIAG_API_TOKEN").ok(),
    }
}

fn timeout(source: &PilotSource) -> Duration {
    Duration::from_secs(source.collection.timeout_secs.max(1))
}

fn validate_http_endpoint(endpoint: &str) -> Result<()> {
    let url = reqwest::Url::parse(endpoint).map_err(|err| {
        NetdiagError::InvalidTrace(format!("endpoint {endpoint} is not a valid URL: {err}"))
    })?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        scheme => Err(NetdiagError::InvalidTrace(format!(
            "endpoint {endpoint} must use http or https, got {scheme}"
        ))),
    }
}

fn native_pcap_source(endpoint: &str, base_dir: &Path) -> NativePcapSource {
    let trimmed = endpoint.trim();
    if let Some(interface) = trimmed.strip_prefix("iface:") {
        return NativePcapSource::Interface(interface.trim().to_string());
    }
    let path = resolve_path(base_dir, trimmed);
    if path.is_file() || trimmed.ends_with(".pcap") || trimmed.contains('/') {
        NativePcapSource::File(path)
    } else {
        NativePcapSource::Interface(trimmed.to_string())
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
mod tests {
    use super::super::{PilotCollection, PilotSourceRole};
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use tempfile::tempdir;

    fn source(kind: PilotSourceKind, endpoint: impl Into<String>) -> PilotSource {
        PilotSource {
            name: "source".to_string(),
            kind,
            endpoint: endpoint.into(),
            role: PilotSourceRole::Primary,
            active: false,
            bearer_token_env: None,
            mapping: None,
            collection: PilotCollection::default(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn static_validation_accepts_readonly_connector_shapes() {
        let temp = tempdir().expect("tempdir");
        let mapping = temp.path().join("mapping.json");
        fs::write(
            &mapping,
            serde_json::to_string(&default_prometheus_mapping()).expect("mapping"),
        )
        .expect("write mapping");

        let mut prometheus = source(PilotSourceKind::PrometheusQuery, "http://127.0.0.1:9090");
        prometheus.mapping = Some("mapping.json".to_string());
        assert_eq!(
            check_source_static(&prometheus, temp.path()).status,
            ConnectorHealthStatus::Ok
        );

        let mut metrics = source(
            PilotSourceKind::PrometheusMetrics,
            "https://node.example.invalid/metrics",
        );
        metrics.mapping = Some(mapping.display().to_string());
        assert_eq!(
            check_source_static(&metrics, temp.path()).status,
            ConnectorHealthStatus::Ok
        );

        let mut otlp = source(PilotSourceKind::OtlpGrpc, "127.0.0.1:4317");
        otlp.mapping = Some("mapping.json".to_string());
        assert_eq!(
            check_source_static(&otlp, temp.path()).status,
            ConnectorHealthStatus::Ok
        );

        assert_eq!(
            check_source_static(
                &source(PilotSourceKind::NativePcap, "iface:en0"),
                temp.path(),
            )
            .status,
            ConnectorHealthStatus::Ok
        );
        assert_eq!(
            check_source_static(&source(PilotSourceKind::SystemCounters, "all"), temp.path())
                .status,
            ConnectorHealthStatus::Ok
        );
    }

    #[test]
    fn static_validation_reports_bad_connector_shapes() {
        let temp = tempdir().expect("tempdir");
        fs::write(temp.path().join("bad-mapping.json"), "bad json").expect("bad mapping");
        assert_eq!(
            check_source_static(
                &source(PilotSourceKind::HttpJson, "ftp://example"),
                temp.path()
            )
            .status,
            ConnectorHealthStatus::Error
        );
        assert_eq!(
            check_source_static(&source(PilotSourceKind::HttpJson, "::not-url"), temp.path())
                .status,
            ConnectorHealthStatus::Error
        );
        let mut bad_mapping = source(PilotSourceKind::PrometheusQuery, "http://127.0.0.1:9090");
        bad_mapping.mapping = Some("bad-mapping.json".to_string());
        assert_eq!(
            check_source_static(&bad_mapping, temp.path()).status,
            ConnectorHealthStatus::Error
        );
        assert_eq!(
            check_source_static(
                &source(PilotSourceKind::OtlpGrpc, "not-a-socket"),
                temp.path()
            )
            .status,
            ConnectorHealthStatus::Error
        );
        assert_eq!(
            check_source_static(&source(PilotSourceKind::NativePcap, "iface:"), temp.path()).status,
            ConnectorHealthStatus::Error
        );
        assert_eq!(
            check_source_static(
                &source(PilotSourceKind::NativePcap, "missing.pcap"),
                temp.path(),
            )
            .status,
            ConnectorHealthStatus::Error
        );
    }

    #[test]
    fn native_pcap_source_distinguishes_files_and_interfaces() {
        let temp = tempdir().expect("tempdir");
        let pcap = temp.path().join("capture.pcap");
        fs::write(&pcap, []).expect("pcap placeholder");

        assert!(matches!(
            native_pcap_source("iface:eth0", temp.path()),
            NativePcapSource::Interface(interface) if interface == "eth0"
        ));
        assert!(matches!(
            native_pcap_source("capture.pcap", temp.path()),
            NativePcapSource::File(path) if path == pcap
        ));
        assert!(matches!(
            native_pcap_source("en0", temp.path()),
            NativePcapSource::Interface(interface) if interface == "en0"
        ));
    }

    #[test]
    fn static_validation_accepts_trace_pcap_file_and_empty_system_counters() {
        let root = repo_root();
        assert_eq!(
            check_source_static(
                &source(PilotSourceKind::TraceFile, "data/samples/normal.csv"),
                &root,
            )
            .status,
            ConnectorHealthStatus::Ok
        );

        let temp = tempdir().expect("tempdir");
        let pcap = temp.path().join("capture.pcap");
        fs::write(&pcap, b"pcap placeholder").expect("pcap placeholder");
        assert_eq!(
            check_source_static(
                &source(PilotSourceKind::NativePcap, "capture.pcap"),
                temp.path(),
            )
            .status,
            ConnectorHealthStatus::Ok
        );
        let counters =
            check_source_static(&source(PilotSourceKind::SystemCounters, ""), temp.path());
        assert_eq!(counters.status, ConnectorHealthStatus::Ok);
        assert!(counters.message.contains("all interfaces"));
    }

    #[test]
    fn static_validation_reports_missing_adapter_file() {
        let temp = tempdir().expect("tempdir");
        let check = check_source_static(
            &source(PilotSourceKind::AdapterSample, "missing-adapter.py"),
            temp.path(),
        );
        assert_eq!(check.status, ConnectorHealthStatus::Error);
        assert!(check.message.contains("adapter file does not exist"));
    }

    #[test]
    fn load_source_uses_trace_file_adapter_and_http_json_connectors() {
        let root = repo_root();
        let trace = load_pilot_source(
            &source(PilotSourceKind::TraceFile, "data/samples/normal.csv"),
            &root,
        )
        .expect("trace file");
        assert_eq!(trace.health.status, ConnectorHealthStatus::Ok);

        let adapter = load_pilot_source(
            &source(
                PilotSourceKind::AdapterSample,
                "examples/adapters/iperf3-http-json/adapter.py",
            ),
            &root,
        )
        .expect("adapter sample");
        assert_eq!(adapter.health.status, ConnectorHealthStatus::Ok);
        assert!(adapter.redacted_payload.is_some());

        let payload = serde_json::json!({
            "schema": "netdiag-adapter-payload/v1",
            "sample": "http-json-test",
            "records": [{
                "timestamp": "2026-01-01T00:00:00Z",
                "latency_ms": 10.0,
                "jitter_ms": 1.0,
                "packet_loss_rate": 0.1,
                "retransmission_rate": 0.2,
                "timeout_events": 0.0,
                "retry_events": 1.0,
                "throughput_mbps": 99.0,
                "dns_failure_events": 0.0,
                "tls_failure_events": 0.0,
                "quic_blocked_ratio": 0.0
            }]
        });
        let (url, handle) = serve_repeated(1, 200, payload.to_string());
        let http =
            load_pilot_source(&source(PilotSourceKind::HttpJson, url), &root).expect("http json");
        handle.join().expect("server thread");
        assert_eq!(http.ingest.records.len(), 1);
        assert_eq!(http.health.status, ConnectorHealthStatus::Ok);
        assert!(http.redacted_payload.is_some());
    }

    #[test]
    fn load_source_uses_prometheus_connector_family() {
        let root = repo_root();
        let matrix = serde_json::json!({
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [{
                    "metric": {},
                    "values": [[1.0, "42"], [2.0, "43"]]
                }]
            }
        })
        .to_string();
        let (query_url, query_handle) = serve_repeated(10, 200, matrix);
        let query = load_pilot_source(&source(PilotSourceKind::PrometheusQuery, query_url), &root)
            .expect("prometheus query");
        query_handle.join().expect("query server");
        assert_eq!(query.ingest.records.len(), 2);
        assert_ne!(query.health.status, ConnectorHealthStatus::Error);

        let exposition = r#"
netdiag_latency_ms 42
netdiag_jitter_ms 3
netdiag_packet_loss_rate 0.2
netdiag_retransmission_rate 0.4
netdiag_throughput_mbps 99
"#;
        let (metrics_url, metrics_handle) = serve_repeated(1, 200, exposition.to_string());
        let metrics = load_pilot_source(
            &source(PilotSourceKind::PrometheusMetrics, metrics_url),
            &root,
        )
        .expect("prometheus metrics");
        metrics_handle.join().expect("metrics server");
        assert_eq!(metrics.ingest.records.len(), 1);
        assert_ne!(metrics.health.status, ConnectorHealthStatus::Error);
    }

    #[test]
    fn load_source_reports_live_connector_startup_failures_without_fallback() {
        let temp = tempdir().expect("tempdir");
        let otlp_err = load_pilot_source(
            &source(PilotSourceKind::OtlpGrpc, "not-a-socket"),
            temp.path(),
        )
        .err()
        .expect("invalid otlp");
        assert!(otlp_err.to_string().contains("invalid OTLP bind address"));
        let pcap_err = load_pilot_source(
            &source(PilotSourceKind::NativePcap, "missing.pcap"),
            temp.path(),
        )
        .err()
        .expect("missing pcap");
        assert!(pcap_err.to_string().contains("failed to open pcap file"));
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf()
    }

    fn serve_repeated(count: usize, status: u16, body: String) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        let handle = thread::spawn(move || {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().expect("accept");
                let mut request = [0_u8; 2048];
                let _ = stream.read(&mut request).expect("read request");
                let status_text = if status == 200 { "OK" } else { "ERROR" };
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
        });
        (format!("http://{addr}"), handle)
    }

    #[test]
    fn helpers_normalize_system_counter_interface_and_source_kind_names() {
        assert_eq!(system_counter_interface("all"), None);
        assert_eq!(system_counter_interface(""), None);
        assert_eq!(system_counter_interface(" en0 "), Some("en0".to_string()));

        for (kind, expected) in [
            (PilotSourceKind::TraceFile, "trace-file"),
            (PilotSourceKind::AdapterSample, "adapter-sample"),
            (PilotSourceKind::HttpJson, "http-json"),
            (PilotSourceKind::PrometheusQuery, "prometheus-query"),
            (PilotSourceKind::PrometheusMetrics, "prometheus-metrics"),
            (PilotSourceKind::OtlpGrpc, "otlp-grpc"),
            (PilotSourceKind::NativePcap, "native-pcap"),
            (PilotSourceKind::SystemCounters, "system-counters"),
        ] {
            assert_eq!(source_kind_name(kind), expected);
        }
    }
}
