use super::super::http_client::ConnectorHttpClient;
use super::super::*;
use crate::connectors::authentication::{ValidatedBearerToken, validate_bearer_token};
use crate::resource_limits::MAX_SOURCE_INPUT_BYTES;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

fn bearer_token(value: &str) -> ValidatedBearerToken {
    validate_bearer_token(value.to_owned()).expect("valid bearer token fixture")
}

#[test]
fn http_json_tracks_exact_response_bytes_and_records() {
    let body = serde_json::json!({
        "sample": "http-budget",
        "records": [{
            "timestamp": "2026-07-12T00:00:00Z",
            "latency_ms": 12.0,
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
    })
    .to_string();
    let body_bytes = u64::try_from(body.len()).expect("fixture body length");
    let (url, handle) = serve_once(200, body, None);

    let loaded = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect("bounded HTTP/JSON load");
    handle.join().expect("server thread");

    assert_eq!(
        loaded.resource_usage,
        ConnectorResourceUsage {
            input_bytes: body_bytes,
            records: 1,
        }
    );
}

#[test]
fn http_json_rejects_sensitive_query_parameters_without_echoing_values() {
    for key in [
        "AcCeSs-ToKeN",
        "api_key",
        "password",
        "secret",
        "auth",
        "authorization",
        "%61%70%69%5f%6b%65%79",
    ] {
        let secret = "opaque-http-query-secret";
        let error = load_http_json(
            &HttpJsonConfig {
                endpoint: format!("http://127.0.0.1:1/source?{key}={secret}"),
                timeout: Duration::from_secs(1),
            },
            None,
        )
        .expect_err("credential-bearing query parameters must be rejected");

        assert!(error.to_string().contains("query parameters"));
        assert!(!error.to_string().contains(secret));
    }
}

#[test]
fn http_connector_errors_do_not_echo_endpoint_credentials() {
    let secret = "opaque-connection-token";
    let error = load_http_json(
        &HttpJsonConfig {
            endpoint: format!("http://127.0.0.1:0/{secret}"),
            timeout: Duration::from_secs(1),
        },
        None,
    )
    .expect_err("closed endpoint must fail");

    assert!(error.to_string().contains("HTTP/JSON request failed"));
    assert!(!error.to_string().contains(secret));
}

#[test]
fn bearer_auth_rejects_remote_plaintext_and_localhost_names_without_network_io() {
    for endpoint in ["http://192.0.2.1/source", "http://localhost:8080/source"] {
        let token = bearer_token("opaque-token");
        let error = load_http_json(
            &HttpJsonConfig {
                endpoint: endpoint.to_string(),
                timeout: Duration::from_secs(1),
            },
            Some(&token),
        )
        .expect_err("authenticated plaintext must require a loopback IP literal");

        assert!(error.to_string().contains("loopback IP literal"));
        assert!(!error.to_string().contains("opaque-token"));
    }
}

#[test]
fn bearer_endpoint_validation_accepts_https_and_ip_loopback_only_for_plaintext() {
    for endpoint in [
        "https://example.test/source",
        "http://127.0.0.1/source",
        "http://[::1]/source",
    ] {
        validate_http_connector_bearer_endpoint(endpoint)
            .expect("secure authenticated endpoint shape");
    }
    for endpoint in [
        "http://localhost/source",
        "http://192.0.2.1/source",
        "http://[2001:db8::1]/source",
    ] {
        assert_eq!(
            validate_http_connector_bearer_endpoint(endpoint),
            Err(HttpEndpointError::InsecureBearerTransport)
        );
    }
}

#[test]
fn bearer_auth_allows_plaintext_loopback_ip_literals() {
    let body = serde_json::json!({ "records": [] }).to_string();
    let (url, handle) = serve_once(200, body, Some("authorization: Bearer loopback-token"));

    let token = bearer_token("loopback-token");
    let error = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        Some(&token),
    )
    .expect_err("empty record sets are invalid after the authenticated request succeeds");
    handle.join().expect("server thread");

    assert!(error.to_string().contains("no rows"));
}

#[test]
fn authenticated_connectors_do_not_follow_redirects_or_forward_tokens() {
    let redirected_listener = TcpListener::bind("127.0.0.1:0").expect("redirect target listener");
    redirected_listener
        .set_nonblocking(true)
        .expect("nonblocking redirect target");
    let redirected_url = format!(
        "http://{}",
        redirected_listener
            .local_addr()
            .expect("redirect target addr")
    );
    let (url, handle) = serve_redirect_once(
        &redirected_url,
        Some("authorization: Bearer redirect-token"),
    );

    let token = bearer_token("redirect-token");
    let error = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        Some(&token),
    )
    .expect_err("redirect responses must be explicit connector failures");
    handle.join().expect("redirect server thread");

    assert!(error.to_string().contains("HTTP status 302"));
    assert!(!error.to_string().contains("redirect-token"));
    let accept_error = redirected_listener
        .accept()
        .expect_err("redirect target must not receive a request")
        .kind();
    assert_eq!(accept_error, std::io::ErrorKind::WouldBlock);
}

#[test]
fn connector_config_and_token_debug_output_redact_sensitive_values() {
    let query_secret = "opaque-debug-query-secret";
    let bearer_secret = "opaque-debug-bearer-secret";
    let http = HttpJsonConfig {
        endpoint: format!("https://example.test/source?api_key={query_secret}"),
        timeout: Duration::from_secs(1),
    };
    let prometheus_query = PrometheusQueryRangeConfig {
        base_url: format!("https://example.test?token={query_secret}"),
        timeout: Duration::from_secs(1),
        lookback_seconds: 10,
        step_seconds: 1,
        queries: BTreeMap::new(),
        sample: "debug".to_string(),
    };
    let prometheus_exposition = PrometheusExpositionConfig {
        endpoint: format!("https://example.test/metrics?password={query_secret}"),
        timeout: Duration::from_secs(1),
        metrics: BTreeMap::new(),
        sample: "debug".to_string(),
    };
    let bearer = bearer_token(bearer_secret);

    for output in [
        format!("{http:?}"),
        format!("{prometheus_query:?}"),
        format!("{prometheus_exposition:?}"),
        format!("{bearer:?}"),
    ] {
        assert!(!output.contains(query_secret));
        assert!(!output.contains(bearer_secret));
        assert!(output.contains("redacted"));
    }
}

#[test]
fn http_endpoints_forbid_url_user_information_without_echoing_it() {
    let secret = "opaque-userinfo-password";
    let error = load_http_json(
        &HttpJsonConfig {
            endpoint: format!("https://operator:{secret}@example.test/source"),
            timeout: Duration::from_secs(1),
        },
        None,
    )
    .expect_err("URL user information must be rejected");

    assert!(error.to_string().contains("user information is forbidden"));
    assert!(!error.to_string().contains(secret));
}

#[test]
fn http_json_rejects_oversized_declared_content_length_before_body_read() {
    let declared_length = MAX_SOURCE_INPUT_BYTES + 1;
    let (url, handle) = serve_once_with_declared_length(200, "{}".to_string(), declared_length);

    let error = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect_err("oversized declared response must fail closed");
    handle.join().expect("server thread");

    assert!(error.to_string().contains("declared Content-Length"));
    assert!(error.to_string().contains("HTTP/JSON response"));
}

#[test]
fn http_json_rejects_invalid_bare_record_schema_without_echoing_values() {
    let sensitive = "sensitive-bare-record";
    let body = serde_json::json!([{ "timestamp": sensitive }]).to_string();
    let (url, handle) = serve_once(200, body, None);

    let error = load_http_json(
        &HttpJsonConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
        },
        None,
    )
    .expect_err("invalid bare record response must fail closed");
    handle.join().expect("server thread");

    assert!(error.to_string().contains("required response schema"));
    assert!(!error.to_string().contains(sensitive));
}

#[test]
fn prometheus_exposition_maps_metrics_to_trace_record() {
    let body = r#"
# HELP netdiag_latency_ms RTT
netdiag_latency_ms{target="lab"} 42
netdiag_jitter_ms 3
netdiag_packet_loss_rate 0.2
netdiag_retransmission_rate 0.4
netdiag_throughput_mbps 99
"#;
    let values = prometheus::parse_prometheus_exposition(body, &default_prometheus_mapping())
        .expect("parse exposition");

    assert_eq!(values["latency_ms"], 42.0);
    assert_eq!(values["throughput_mbps"], 99.0);
}

#[test]
fn prometheus_exposition_errors_when_required_metric_missing() {
    let (url, handle) = serve_once(
        200,
        "netdiag_latency_ms 42\nnetdiag_jitter_ms 3\n".to_string(),
        None,
    );
    let err = load_prometheus_exposition(
        &PrometheusExpositionConfig {
            endpoint: url,
            timeout: Duration::from_secs(2),
            metrics: BTreeMap::new(),
            sample: "prom_text".to_string(),
        },
        None,
    )
    .expect_err("missing required metric");
    handle.join().expect("server thread");
    assert!(err.to_string().contains("missing required metric"));
}

#[test]
fn prometheus_query_range_accepts_matrix_and_bearer_token() {
    let response = serde_json::json!({
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
    let response_bytes = u64::try_from(response.len()).expect("fixture response length");
    let (url, handle) = serve_repeated(10, 200, response, Some("authorization: Bearer prom-token"));
    let mut queries = BTreeMap::new();
    for metric in default_prometheus_mapping().keys() {
        queries.insert(metric.clone(), format!("query_{metric}"));
    }
    let token = bearer_token("prom-token");
    let result = load_prometheus_query_range(
        &PrometheusQueryRangeConfig {
            base_url: format!("{url}?tenant=lab"),
            timeout: Duration::from_secs(2),
            lookback_seconds: 30,
            step_seconds: 5,
            queries,
            sample: "prom_query".to_string(),
        },
        Some(&token),
    )
    .expect("query range");
    handle.join().expect("server thread");

    assert_eq!(result.ingest.records.len(), 2);
    assert_eq!(result.ingest.records[0].latency_ms, 0.42);
    assert_eq!(result.resource_usage.input_bytes, response_bytes * 10);
    assert_eq!(result.resource_usage.records, 2);
    assert!(result.provenance["base_url"].contains("tenant=lab"));
    assert!(result.provenance["endpoint"].contains("tenant=lab"));
}

#[test]
fn prometheus_query_range_rejects_excess_series() {
    let series = (0..resource_budget::MAX_PROMETHEUS_SERIES_PER_RESPONSE + 1)
        .map(|_| serde_json::json!({ "metric": {}, "values": [] }))
        .collect::<Vec<_>>();
    let response = serde_json::json!({
        "status": "success",
        "data": { "resultType": "matrix", "result": series }
    })
    .to_string();
    let (url, handle) = serve_once(200, response, None);
    let client = ConnectorHttpClient::new(&url, "fixture").expect("fixture HTTP client");
    let deadline = resource_budget::SourceDeadline::new(Duration::from_secs(2), "fixture")
        .expect("fixture deadline");
    let mut budget = resource_budget::NetworkSourceBudget::default();

    let error = prometheus::query_prometheus_matrix(
        prometheus::PrometheusMatrixRequest {
            client: &client,
            query: "up",
            start: 0,
            end: 1,
            step: 1,
            metric: "latency_ms",
            bearer_token: None,
        },
        &deadline,
        &mut budget,
    )
    .expect_err("excess Prometheus series must fail closed");
    handle.join().expect("server thread");

    assert!(error.to_string().contains("series count"));
}

#[test]
fn prometheus_query_range_enforces_cumulative_sample_limit() {
    let response = serde_json::json!({
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [{ "metric": {}, "values": [[1.0, "42"]] }]
        }
    })
    .to_string();
    let (url, handle) = serve_once(200, response, None);
    let client = ConnectorHttpClient::new(&url, "fixture").expect("fixture HTTP client");
    let deadline = resource_budget::SourceDeadline::new(Duration::from_secs(2), "fixture")
        .expect("fixture deadline");
    let mut budget = resource_budget::NetworkSourceBudget::default();
    budget
        .reserve_prometheus_shape(
            0,
            resource_budget::MAX_PROMETHEUS_SAMPLES_PER_SOURCE,
            "fixture",
        )
        .expect("prefill exact sample budget");

    let error = prometheus::query_prometheus_matrix(
        prometheus::PrometheusMatrixRequest {
            client: &client,
            query: "up",
            start: 0,
            end: 1,
            step: 1,
            metric: "latency_ms",
            bearer_token: None,
        },
        &deadline,
        &mut budget,
    )
    .expect_err("cumulative Prometheus sample overflow must fail closed");
    handle.join().expect("server thread");

    assert!(error.to_string().contains("cumulative sample count"));
}

#[test]
fn prometheus_matrix_rejects_malformed_samples_instead_of_using_partial_data() {
    let malformed = [
        vec![serde_json::json!("bad timestamp"), serde_json::json!("42")],
        vec![serde_json::json!(1.0), serde_json::json!(42)],
        vec![serde_json::json!(1.0), serde_json::json!("NaN")],
        vec![serde_json::json!(1.0)],
    ];

    for pair in malformed {
        let error = prometheus_matrix::parse_prometheus_matrix_sample(&pair, 2, 3)
            .expect_err("malformed Prometheus samples must fail closed");
        assert!(
            error.to_string().contains("series 2 sample 3"),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn prometheus_query_range_reports_error_envelope() {
    let secret = "opaque-prom-error-token";
    let response = serde_json::json!({
        "status": "error",
        "errorType": "bad_data",
        "error": format!("https://example.test/query?access_token={secret}")
    })
    .to_string();
    let (url, handle) = serve_repeated(1, 200, response, None);
    let err = load_prometheus_query_range(
        &PrometheusQueryRangeConfig {
            base_url: url,
            timeout: Duration::from_secs(2),
            lookback_seconds: 30,
            step_seconds: 5,
            queries: BTreeMap::new(),
            sample: "prom_query".to_string(),
        },
        None,
    )
    .expect_err("prom error");
    handle.join().expect("server thread");
    assert!(err.to_string().contains("bad_data"));
    assert!(!err.to_string().contains(secret));
}

#[test]
fn prometheus_exposition_missing_optional_events_emit_warnings() {
    let body = r#"
netdiag_latency_ms 42
netdiag_jitter_ms 3
netdiag_packet_loss_rate 0.2
netdiag_retransmission_rate 0.4
netdiag_throughput_mbps 99
"#;
    let body_bytes = u64::try_from(body.len()).expect("fixture exposition length");
    let (url, handle) = serve_once(200, body.to_string(), None);
    let loaded = load_prometheus_exposition(
        &PrometheusExpositionConfig {
            endpoint: format!("{url}?region=lab"),
            timeout: Duration::from_secs(2),
            metrics: BTreeMap::new(),
            sample: "prom_text".to_string(),
        },
        None,
    )
    .expect("prom exposition with optional fallbacks");
    handle.join().expect("server thread");

    assert_eq!(loaded.ingest.records.len(), 1);
    assert_eq!(loaded.resource_usage.input_bytes, body_bytes);
    assert_eq!(loaded.resource_usage.records, 1);
    assert!(loaded.provenance["endpoint"].contains("region=lab"));
    for column in EVENT_METRICS {
        assert!(
            loaded
                .ingest
                .warnings
                .iter()
                .any(|warning| warning.column == column),
            "{column}"
        );
    }
}

pub(super) fn serve_once(
    status: u16,
    body: String,
    expected_header: Option<&'static str>,
) -> (String, thread::JoinHandle<()>) {
    serve_repeated(1, status, body, expected_header)
}

fn serve_once_with_declared_length(
    status: u16,
    body: String,
    declared_length: u64,
) -> (String, thread::JoinHandle<()>) {
    serve_repeated_with_declared_length(1, status, body, None, Some(declared_length))
}

fn serve_redirect_once(
    location: &str,
    expected_header: Option<&'static str>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind redirect server");
    let addr = listener.local_addr().expect("redirect server addr");
    let location = location.to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept redirect request");
        let mut request = [0_u8; 4096];
        let bytes = stream.read(&mut request).expect("read redirect request");
        let request_text = String::from_utf8_lossy(&request[..bytes]);
        if let Some(header) = expected_header {
            assert!(request_text.contains(header), "{request_text}");
        }
        let response = format!(
            "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .expect("write redirect response");
    });
    (format!("http://{addr}"), handle)
}

fn serve_repeated(
    count: usize,
    status: u16,
    body: String,
    expected_header: Option<&'static str>,
) -> (String, thread::JoinHandle<()>) {
    serve_repeated_with_declared_length(count, status, body, expected_header, None)
}

fn serve_repeated_with_declared_length(
    count: usize,
    status: u16,
    body: String,
    expected_header: Option<&'static str>,
    declared_length: Option<u64>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
    let addr = listener.local_addr().expect("local addr");
    let handle = thread::spawn(move || {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0_u8; 4096];
            let bytes = stream.read(&mut request).expect("read request");
            let request_text = String::from_utf8_lossy(&request[..bytes]);
            if let Some(header) = expected_header {
                assert!(request_text.contains(header), "{request_text}");
            }
            let status_text = if status == 200 { "OK" } else { "ERROR" };
            let content_length = declared_length
                .unwrap_or_else(|| u64::try_from(body.len()).expect("response body length"));
            let response = format!(
                "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                content_length, body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        }
    });
    (format!("http://{addr}"), handle)
}
