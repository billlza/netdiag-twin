use super::super::{
    PilotAdapterMode, PilotAdapterOptions, PilotCollection, PilotSource, PilotSourceRole,
};
use super::*;
use super::{
    adapter_args::adapter_runtime_invocation, payload_contract::validate_adapter_payload_contract,
};
use crate::models::MetricQuality;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;
use tempfile::tempdir;

mod support;
use support::{check_source_static, load_pilot_source};
#[cfg(unix)]
mod adapter_invocation;
mod adapter_json;

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
        adapter: PilotAdapterOptions::default(),
        metadata: BTreeMap::new(),
    }
}

fn contract_source(kind: PilotSourceKind, endpoint: impl Into<String>) -> PilotSource {
    let mut source = source(kind, endpoint);
    source.adapter.mode = Some(PilotAdapterMode::Live);
    source.metadata.insert(
        "adapter_contract".to_string(),
        "netdiag-adapter/v1".to_string(),
    );
    source
}

fn contract_sample_source(kind: PilotSourceKind, endpoint: impl Into<String>) -> PilotSource {
    let mut source = contract_source(kind, endpoint);
    source.adapter.mode = Some(PilotAdapterMode::Sample);
    source
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
        check_source_static(&source(PilotSourceKind::SystemCounters, "all"), temp.path()).status,
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
        check_source_static(&source(PilotSourceKind::HttpJson, "::not-url"), temp.path()).status,
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
fn static_http_validation_does_not_echo_url_credentials() {
    let secret = "opaque-static-password";
    let check = check_source_static(
        &source(
            PilotSourceKind::HttpJson,
            format!("https://operator:{secret}@example.test/source"),
        ),
        Path::new("."),
    );

    assert_eq!(check.status, ConnectorHealthStatus::Error);
    assert!(check.message.contains("user information is forbidden"));
    assert!(!check.message.contains(secret));
    assert!(!check.artifact.expect("redacted endpoint").contains(secret));
}

#[test]
fn static_otlp_validation_does_not_echo_invalid_endpoint_values() {
    let secret = "opaque-otlp-endpoint-secret";
    let check = check_source_static(&source(PilotSourceKind::OtlpGrpc, secret), Path::new("."));

    assert_eq!(check.status, ConnectorHealthStatus::Error);
    assert!(!check.message.contains(secret));
    assert!(!check.artifact.expect("redacted endpoint").contains(secret));
}

#[test]
fn native_pcap_source_distinguishes_files_and_interfaces() {
    let temp = tempdir().expect("tempdir");
    let pcap = temp.path().join("capture.pcap");
    fs::write(&pcap, []).expect("pcap placeholder");

    assert!(matches!(
        native_pcap_source("iface:eth0", temp.path()),
        Ok(NativePcapSource::Interface(interface)) if interface == "eth0"
    ));
    assert!(matches!(
        native_pcap_source("capture.pcap", temp.path()),
        Ok(NativePcapSource::File(path)) if path == pcap
    ));
    assert!(matches!(
        native_pcap_source("en0", temp.path()),
        Ok(NativePcapSource::Interface(interface)) if interface == "en0"
    ));

    let invalid = temp.path().join("not-a-capture");
    fs::create_dir(&invalid).expect("invalid source directory");
    let error = native_pcap_source("not-a-capture", temp.path())
        .expect_err("non-file filesystem entries must not fall back to interfaces");
    assert!(
        error.to_string().contains("neither a regular file"),
        "{error}"
    );
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
    let counters = check_source_static(&source(PilotSourceKind::SystemCounters, ""), temp.path());
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
        &contract_sample_source(
            PilotSourceKind::AdapterSample,
            "examples/adapters/iperf3-http-json/adapter.py",
        ),
        &root,
    )
    .expect("adapter sample");
    assert_eq!(adapter.health.status, ConnectorHealthStatus::Degraded);
    assert_eq!(
        adapter
            .ingest
            .metric_provenance
            .iter()
            .find(|item| item.field == "retransmission_rate")
            .map(|item| item.quality),
        Some(MetricQuality::Missing)
    );
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
    assert_eq!(http.health.status, ConnectorHealthStatus::Degraded);
    let evidence_metadata = http
        .redacted_payload
        .expect("HTTP source metadata evidence");
    assert_eq!(evidence_metadata["sample"], "http-json-test");
    assert!(evidence_metadata.get("records").is_none());
}

#[test]
fn adapter_sample_runtime_rejects_payloads_missing_contract_metadata() {
    let temp = tempdir().expect("tempdir");
    let adapter = temp.path().join("adapter.py");
    fs::write(
        &adapter,
        r#"import json
import sys
if "--preflight" in sys.argv:
    print(json.dumps({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "source",
        "collection_mode": "live",
        "passed": True,
        "checks": [{"name": "test", "status": "ok"}],
        "health": {"status": "ok"},
        "redaction": {"fields": []}
    }))
    raise SystemExit(0)
print(json.dumps({
    "schema": "netdiag-adapter-payload/v1",
    "sample": "missing-contract-metadata",
    "records": [{
        "timestamp": "2026-01-01T00:00:00Z",
        "latency_ms": 10.0,
        "jitter_ms": 1.0,
        "packet_loss_rate": 0.0,
        "retransmission_rate": 0.0,
        "timeout_events": 0.0,
        "retry_events": 0.0,
        "throughput_mbps": 100.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0
    }]
}))
"#,
    )
    .expect("adapter script");

    let err = match load_pilot_source(
        &contract_source(PilotSourceKind::AdapterSample, "adapter.py"),
        temp.path(),
    ) {
        Ok(_) => panic!("adapter payload contract metadata is required at runtime"),
        Err(err) => err,
    };

    assert!(err.to_string().contains("protocol"), "{err}");
    assert!(err.to_string().contains("experiment"), "{err}");
}

#[test]
fn adapter_execution_requires_authorization_boundary_and_successful_phases() {
    let source = contract_sample_source(PilotSourceKind::AdapterSample, "adapter.py");
    let unauthorized = load_adapter_sample_source(&source, None, false)
        .err()
        .expect("adapter execution requires explicit authorization");
    assert!(
        unauthorized
            .to_string()
            .contains("explicit allow_adapter_execution")
    );
    let missing_boundary = load_adapter_sample_source(&source, None, true)
        .err()
        .expect("authorized execution still requires a prepared boundary");
    assert!(
        missing_boundary
            .to_string()
            .contains("boundary is not configured")
    );
    let static_check = check_source_static_with_boundary(&source, Path::new("."), None);
    assert_eq!(static_check.status, ConnectorHealthStatus::Error);
    assert!(static_check.message.contains("boundary is not configured"));

    let temp = tempdir().expect("tempdir");
    let adapter = temp.path().join("adapter.py");
    fs::write(
        &adapter,
        r#"import json
import sys
if "--preflight" in sys.argv:
    print("preflight-secret", file=sys.stderr)
    raise SystemExit(7)
raise SystemExit(0)
"#,
    )
    .expect("preflight-failing adapter");
    let preflight_error = load_pilot_source(&source, temp.path())
        .err()
        .expect("non-zero preflight status must fail before collection");
    assert!(preflight_error.to_string().contains("phase=preflight"));
    assert!(preflight_error.to_string().contains("preflight-secret"));

    fs::write(
        &adapter,
        r#"import json
import sys
if "--preflight" in sys.argv:
    print(json.dumps({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "source",
        "collection_mode": "sample",
        "passed": True,
        "checks": [{"name": "ready", "status": "ok"}],
        "health": {"status": "ok"},
        "redaction": {"fields": []}
    }))
    raise SystemExit(0)
print("collection-failed", file=sys.stderr)
raise SystemExit(9)
"#,
    )
    .expect("collection-failing adapter");
    let collect_error = load_pilot_source(&source, temp.path())
        .err()
        .expect("non-zero collection status must fail explicitly");
    assert!(collect_error.to_string().contains("phase=collect"));
    assert!(collect_error.to_string().contains("collection-failed"));
}

#[cfg(unix)]
#[test]
fn adapter_relative_resources_are_not_loaded_from_the_original_parent() {
    let temp = tempdir().expect("tempdir");
    fs::write(temp.path().join("resource.txt"), "original-parent-resource")
        .expect("relative resource");
    fs::write(
        temp.path().join("adapter.py"),
        r#"import json
import sys
from pathlib import Path

resource = Path("resource.txt").read_text(encoding="utf-8")
if "--preflight" in sys.argv:
    print(json.dumps({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "source",
        "collection_mode": "sample",
        "passed": resource == "original-parent-resource",
        "checks": [{"name": "relative-resource", "status": "ok"}],
        "health": {"status": "ok"},
        "redaction": {"fields": [], "secrets": []}
    }))
"#,
    )
    .expect("adapter script");

    let error = load_pilot_source(
        &contract_sample_source(PilotSourceKind::AdapterSample, "adapter.py"),
        temp.path(),
    )
    .err()
    .expect("undeclared relative resources must fail in the private runtime directory");
    assert!(error.to_string().contains("phase=preflight"), "{error}");
    assert!(error.to_string().contains("resource.txt"), "{error}");
}

#[test]
fn adapter_passthrough_values_cannot_leak_from_payload_or_stderr_echoes() {
    let temp = tempdir().expect("tempdir");
    let adapter = temp.path().join("adapter.py");
    fs::write(
        &adapter,
        r#"import json
import sys
if "--preflight" in sys.argv:
    print(json.dumps({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "source",
        "collection_mode": "sample",
        "passed": True,
        "checks": [{"name": "argv-redaction", "status": "ok"}],
        "health": {"status": "ok"},
        "redaction": {"fields": [], "secrets": []}
    }))
    raise SystemExit(0)
if "--fail" in sys.argv:
    print("argv=" + "|".join(sys.argv[1:]), file=sys.stderr)
    raise SystemExit(7)
opaque = next(arg.split("=", 1)[1] for arg in sys.argv if arg.startswith("--opaque="))
print(json.dumps({
    "schema": "netdiag-adapter-payload/v1",
    "collection_mode": "sample",
    "sample": "argv-redaction",
    "protocol": opaque,
    "flow_count": 1,
    "records": [{
        "timestamp": "2026-01-01T00:00:00Z",
        "latency_ms": 10.0,
        "jitter_ms": 1.0,
        "packet_loss_rate": 0.0,
        "retransmission_rate": 0.0,
        "timeout_events": 0.0,
        "retry_events": 0.0,
        "throughput_mbps": 100.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0
    }],
    "experiment": {
        "scenario_id": "argv-redaction",
        "fault_start": "2026-01-01T00:00:00Z",
        "fault_end": "2026-01-01T00:00:01Z",
        "ground_truth": "normal"
    }
}))
"#,
    )
    .expect("adapter script");
    let secrets = ["opaque-inline", "opaque-next", "opaque-positional"];
    let mut source = contract_sample_source(PilotSourceKind::AdapterSample, "adapter.py");
    source.adapter.args = vec![
        format!("--opaque={}", secrets[0]),
        "--label".to_string(),
        secrets[1].to_string(),
        secrets[2].to_string(),
    ];

    let loaded = load_pilot_source(&source, temp.path()).expect("redacted adapter payload");
    let payload = serde_json::to_string(&loaded.redacted_payload).expect("payload JSON");
    assert!(payload.contains("[redacted]"));
    for secret in secrets {
        assert!(!payload.contains(secret), "payload leaked {secret}");
    }

    source.adapter.args.push("--fail".to_string());
    let error = load_pilot_source(&source, temp.path())
        .err()
        .expect("adapter must fail");
    let message = error.to_string();
    assert!(message.contains("[redacted]"));
    for secret in secrets {
        assert!(!message.contains(secret), "stderr leaked {secret}");
    }
}

#[test]
fn adapter_payload_contract_requires_requested_collection_mode() {
    let mut payload = serde_json::json!({
        "schema": "netdiag-adapter-payload/v1",
        "collection_mode": "sample",
        "sample": "contract-test",
        "protocol": "test",
        "flow_count": 1,
        "records": [{"timestamp": "2026-01-01T00:00:00Z"}],
        "experiment": {
            "scenario_id": "scenario",
            "fault_start": "2026-01-01T00:00:00Z",
            "fault_end": "2026-01-01T00:00:01Z",
            "ground_truth": "normal"
        }
    });

    validate_adapter_payload_contract(&payload, PilotAdapterMode::Sample)
        .expect("matching sample mode");
    let mismatch = validate_adapter_payload_contract(&payload, PilotAdapterMode::Live)
        .expect_err("mismatched collection mode must fail");
    assert!(mismatch.to_string().contains("collection_mode"));

    payload["collection_mode"] = serde_json::json!("live");
    validate_adapter_payload_contract(&payload, PilotAdapterMode::Live)
        .expect("matching live mode");
}

#[test]
fn adapter_payload_contract_aggregates_malformed_required_fields_without_echoing_values() {
    const PRIVATE_SCHEMA: &str = "private-schema-sentinel";
    let payload = serde_json::json!({
        "schema": PRIVATE_SCHEMA,
        "collection_mode": "sample",
        "sample": "contract-test",
        "protocol": "test",
        "flow_count": 1,
        "records": [],
        "experiment": {
            "scenario_id": "  ",
            "fault_start": null,
            "fault_end": 7
        }
    });

    let error = validate_adapter_payload_contract(&payload, PilotAdapterMode::Sample)
        .expect_err("malformed required fields must fail as one contract error");
    let crate::error::NetdiagError::Connector(message) = error else {
        panic!("unexpected payload contract error: {error:?}");
    };
    for diagnostic in [
        "schema=netdiag-adapter-payload/v1 or netdiag-adapter-payload/v2",
        "records",
        "experiment.scenario_id",
        "experiment.fault_start",
        "experiment.fault_end",
        "experiment.ground_truth",
    ] {
        assert!(
            message.contains(diagnostic),
            "missing {diagnostic}: {message}"
        );
    }
    assert!(!message.contains(PRIVATE_SCHEMA));
}

#[test]
fn adapter_source_requires_explicit_contract_and_mode() {
    let root = repo_root();
    let absent = source(
        PilotSourceKind::AdapterSample,
        "examples/adapters/iperf3-http-json/adapter.py",
    );
    let error = load_pilot_source(&absent, &root)
        .err()
        .expect("absent contract must fail");
    assert!(
        error
            .to_string()
            .contains("must declare metadata.adapter_contract")
    );

    let mut missing_mode = absent;
    missing_mode.metadata.insert(
        "adapter_contract".to_string(),
        "netdiag-adapter/v1".to_string(),
    );
    let preflight = adapter_preflight_invocation(&missing_mode)
        .expect_err("missing adapter mode must fail preflight");
    let runtime = adapter_runtime_invocation(&missing_mode)
        .expect_err("missing adapter mode must fail runtime");
    assert!(preflight.to_string().contains("adapter.mode"));
    assert!(runtime.to_string().contains("adapter.mode"));
}

#[test]
fn adapter_invocations_share_passthrough_args_for_explicit_modes() {
    let mut strict_live = contract_source(PilotSourceKind::AdapterSample, "adapter.py");
    strict_live.adapter.args = vec!["--input-json".to_string(), "fixture.json".to_string()];
    let strict_live_preflight =
        adapter_preflight_invocation(&strict_live).expect("strict live preflight");
    let strict_live_runtime =
        adapter_runtime_invocation(&strict_live).expect("strict live runtime");
    assert_eq!(strict_live_preflight.mode, PilotAdapterMode::Live);
    assert_eq!(
        strict_live_preflight.args,
        vec!["--preflight", "--input-json", "fixture.json"]
    );
    assert_eq!(
        strict_live_runtime.args,
        vec!["--collect", "--input-json", "fixture.json"]
    );

    let strict_sample = contract_sample_source(PilotSourceKind::AdapterSample, "adapter.py");
    assert_eq!(
        adapter_preflight_invocation(&strict_sample)
            .expect("strict sample preflight")
            .args,
        vec!["--preflight", "--emit-sample"]
    );
    assert_eq!(
        adapter_runtime_invocation(&strict_sample)
            .expect("strict sample runtime")
            .args,
        vec!["--collect", "--emit-sample"]
    );
}

#[test]
fn adapter_invocations_reject_unknown_contracts_and_reserved_args() {
    let mut unknown = source(PilotSourceKind::AdapterSample, "adapter.py");
    unknown
        .metadata
        .insert("adapter_contract".to_string(), "v2".to_string());
    assert!(adapter_runtime_invocation(&unknown).is_err());

    let mut reserved = contract_source(PilotSourceKind::AdapterSample, "adapter.py");
    reserved.adapter.args = vec!["--emit-sample".to_string()];
    assert!(adapter_preflight_invocation(&reserved).is_err());
    assert!(adapter_runtime_invocation(&reserved).is_err());
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
                "values": [[1.0, "0.42"], [2.0, "0.43"]]
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
    assert_eq!(
        pcap_err.to_string(),
        "connector error: native pcap file does not exist"
    );
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
