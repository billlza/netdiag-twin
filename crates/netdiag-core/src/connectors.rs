use crate::error::{NetdiagError, Result};
use crate::ingest::{CANONICAL_COLUMNS, build_ingest_result};
use crate::models::{IngestResult, IngestWarning, TraceRecord};
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const REQUIRED_METRICS: [&str; 6] = [
    "latency_ms",
    "jitter_ms",
    "packet_loss_rate",
    "retransmission_rate",
    "throughput_mbps",
    "timestamp",
];

const EVENT_METRICS: [&str; 5] = [
    "timeout_events",
    "retry_events",
    "dns_failure_events",
    "tls_failure_events",
    "quic_blocked_ratio",
];

#[derive(Debug, Clone)]
pub struct ConnectorLoadResult {
    pub ingest: IngestResult,
    pub sample: String,
    pub provenance: BTreeMap<String, String>,
    pub payload: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct HttpJsonConfig {
    pub endpoint: String,
    pub bearer_token: Option<String>,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct PrometheusQueryRangeConfig {
    pub base_url: String,
    pub bearer_token: Option<String>,
    pub timeout: Duration,
    pub lookback_seconds: i64,
    pub step_seconds: u64,
    pub queries: BTreeMap<String, String>,
    pub sample: String,
}

#[derive(Debug, Clone)]
pub struct PrometheusExpositionConfig {
    pub endpoint: String,
    pub bearer_token: Option<String>,
    pub timeout: Duration,
    pub metrics: BTreeMap<String, String>,
    pub sample: String,
}

pub fn default_prometheus_mapping() -> BTreeMap<String, String> {
    [
        ("latency_ms", "netdiag_latency_ms"),
        ("jitter_ms", "netdiag_jitter_ms"),
        ("packet_loss_rate", "netdiag_packet_loss_rate"),
        ("retransmission_rate", "netdiag_retransmission_rate"),
        ("timeout_events", "netdiag_timeout_events_total"),
        ("retry_events", "netdiag_retry_events_total"),
        ("throughput_mbps", "netdiag_throughput_mbps"),
        ("dns_failure_events", "netdiag_dns_failure_events_total"),
        ("tls_failure_events", "netdiag_tls_failure_events_total"),
        ("quic_blocked_ratio", "netdiag_quic_blocked_ratio"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

pub fn load_http_json(config: &HttpJsonConfig) -> Result<ConnectorLoadResult> {
    if config.endpoint.trim().is_empty() {
        return Err(NetdiagError::Connector(
            "HTTP/JSON endpoint is empty".to_string(),
        ));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .build()
        .map_err(|err| NetdiagError::Connector(err.to_string()))?;
    let mut request = client.get(config.endpoint.trim());
    if let Some(token) = config
        .bearer_token
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        request = request.bearer_auth(token);
    }
    let value: Value = request
        .send()
        .map_err(|err| NetdiagError::Connector(format!("HTTP/JSON request failed: {err}")))?
        .error_for_status()
        .map_err(|err| NetdiagError::Connector(format!("HTTP/JSON returned error status: {err}")))?
        .json()
        .map_err(|err| {
            NetdiagError::Connector(format!("HTTP/JSON response is not valid JSON: {err}"))
        })?;
    let records_value = value
        .get("records")
        .cloned()
        .unwrap_or_else(|| value.clone());
    let records: Vec<TraceRecord> = serde_json::from_value(records_value).map_err(|err| {
        NetdiagError::Connector(format!(
            "HTTP/JSON must return TraceRecord[] or {{ records: TraceRecord[] }}: {err}"
        ))
    })?;
    let sample = value
        .get("sample")
        .and_then(Value::as_str)
        .unwrap_or("http_json")
        .to_string();
    let ingest = build_ingest_result(records, sample.clone())?;
    Ok(ConnectorLoadResult {
        ingest,
        sample,
        provenance: BTreeMap::from([("endpoint".to_string(), config.endpoint.clone())]),
        payload: Some(value),
    })
}

pub fn load_prometheus_query_range(
    config: &PrometheusQueryRangeConfig,
) -> Result<ConnectorLoadResult> {
    if config.base_url.trim().is_empty() {
        return Err(NetdiagError::Connector(
            "Prometheus base URL is empty".to_string(),
        ));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .build()
        .map_err(|err| NetdiagError::Connector(err.to_string()))?;
    let endpoint = prometheus_query_endpoint(&config.base_url);
    let end = Utc::now();
    let start = end - chrono::Duration::seconds(config.lookback_seconds.max(1));
    let mut row_values: BTreeMap<i64, BTreeMap<String, f64>> = BTreeMap::new();
    let mapping = merged_mapping(&config.queries);
    let mut warnings = Vec::new();

    for metric in CANONICAL_COLUMNS {
        if metric == "timestamp" {
            continue;
        }
        let Some(query) = mapping.get(metric).filter(|query| !query.trim().is_empty()) else {
            if EVENT_METRICS.contains(&metric) {
                warnings.push(fallback_warning(
                    metric,
                    "Prometheus query is not configured",
                ));
                continue;
            }
            return Err(NetdiagError::Connector(format!(
                "Prometheus query is missing required metric {metric}"
            )));
        };
        let matrix = query_prometheus_matrix(
            &client,
            &endpoint,
            config.bearer_token.as_deref(),
            query,
            start.timestamp(),
            end.timestamp(),
            config.step_seconds.max(1),
        )?;
        if matrix.is_empty() {
            if EVENT_METRICS.contains(&metric) {
                warnings.push(fallback_warning(
                    metric,
                    "Prometheus query returned no data",
                ));
                continue;
            }
            return Err(NetdiagError::Connector(format!(
                "Prometheus query returned no data for required metric {metric}"
            )));
        }
        for (timestamp_ms, value) in matrix {
            row_values
                .entry(timestamp_ms)
                .or_default()
                .insert(metric.to_string(), value);
        }
    }

    let mut dropped_rows = 0usize;
    let mut records = Vec::new();
    for (timestamp_ms, values) in row_values {
        if !required_payload_metrics()
            .iter()
            .all(|metric| values.contains_key(*metric))
        {
            dropped_rows += 1;
            continue;
        }
        records.push(record_from_values(timestamp_ms, &values, &mut warnings)?);
    }
    if dropped_rows > 0 {
        warnings.push(IngestWarning {
            row: None,
            column: "timestamp".to_string(),
            reason: format!(
                "Prometheus rows missing required metrics were dropped: {dropped_rows}"
            ),
            fallback: "drop row".to_string(),
        });
    }
    if records.is_empty() {
        return Err(NetdiagError::Connector(
            "Prometheus query_range produced no complete TraceRecord rows".to_string(),
        ));
    }
    let mut ingest = build_ingest_result(records, config.sample.clone())?;
    ingest.warnings.extend(warnings);
    Ok(ConnectorLoadResult {
        ingest,
        sample: config.sample.clone(),
        provenance: BTreeMap::from([
            ("base_url".to_string(), config.base_url.clone()),
            ("endpoint".to_string(), endpoint),
        ]),
        payload: None,
    })
}

pub fn load_prometheus_exposition(
    config: &PrometheusExpositionConfig,
) -> Result<ConnectorLoadResult> {
    if config.endpoint.trim().is_empty() {
        return Err(NetdiagError::Connector(
            "Prometheus exposition endpoint is empty".to_string(),
        ));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(config.timeout)
        .build()
        .map_err(|err| NetdiagError::Connector(err.to_string()))?;
    let mut request = client.get(config.endpoint.trim());
    if let Some(token) = config
        .bearer_token
        .as_deref()
        .filter(|token| !token.is_empty())
    {
        request = request.bearer_auth(token);
    }
    let body = request
        .send()
        .map_err(|err| NetdiagError::Connector(format!("Prometheus scrape failed: {err}")))?
        .error_for_status()
        .map_err(|err| NetdiagError::Connector(format!("Prometheus scrape status error: {err}")))?
        .text()
        .map_err(|err| NetdiagError::Connector(format!("Prometheus scrape body failed: {err}")))?;
    let values = parse_prometheus_exposition(&body, &merged_mapping(&config.metrics))?;
    let mut warnings = Vec::new();
    for metric in EVENT_METRICS {
        if !values.contains_key(metric) {
            warnings.push(fallback_warning(
                metric,
                "Prometheus exposition metric is missing",
            ));
        }
    }
    for metric in required_payload_metrics() {
        if !values.contains_key(metric) {
            return Err(NetdiagError::Connector(format!(
                "Prometheus exposition missing required metric {metric}"
            )));
        }
    }
    let record = record_from_values(Utc::now().timestamp_millis(), &values, &mut warnings)?;
    let mut ingest = build_ingest_result(vec![record], config.sample.clone())?;
    ingest.warnings.extend(warnings);
    Ok(ConnectorLoadResult {
        ingest,
        sample: config.sample.clone(),
        provenance: BTreeMap::from([("endpoint".to_string(), config.endpoint.clone())]),
        payload: None,
    })
}

fn query_prometheus_matrix(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    bearer_token: Option<&str>,
    query: &str,
    start: i64,
    end: i64,
    step: u64,
) -> Result<Vec<(i64, f64)>> {
    let mut request = client.get(endpoint).query(&[
        ("query", query.to_string()),
        ("start", start.to_string()),
        ("end", end.to_string()),
        ("step", step.to_string()),
    ]);
    if let Some(token) = bearer_token.filter(|token| !token.is_empty()) {
        request = request.bearer_auth(token);
    }
    let envelope: PrometheusEnvelope = request
        .send()
        .map_err(|err| NetdiagError::Connector(format!("Prometheus query_range failed: {err}")))?
        .error_for_status()
        .map_err(|err| {
            NetdiagError::Connector(format!("Prometheus query_range status error: {err}"))
        })?
        .json()
        .map_err(|err| {
            NetdiagError::Connector(format!("Prometheus query_range JSON error: {err}"))
        })?;
    if envelope.status != "success" {
        return Err(NetdiagError::Connector(format!(
            "Prometheus query failed: {} {}",
            envelope.error_type.unwrap_or_default(),
            envelope.error.unwrap_or_default()
        )));
    }
    let mut values = Vec::new();
    let Some(data) = envelope.data else {
        return Ok(values);
    };
    for result in data.result {
        for pair in result.values {
            let Some(timestamp) = pair.first().and_then(Value::as_f64) else {
                continue;
            };
            let Some(value_text) = pair.get(1).and_then(Value::as_str) else {
                continue;
            };
            let Ok(value) = value_text.parse::<f64>() else {
                continue;
            };
            if value.is_finite() && value >= 0.0 {
                values.push(((timestamp * 1000.0).round() as i64, value));
            }
        }
    }
    Ok(values)
}

fn parse_prometheus_exposition(
    body: &str,
    mapping: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, f64>> {
    let wanted: BTreeMap<&str, &str> = mapping
        .iter()
        .map(|(canonical, metric)| (metric.as_str(), canonical.as_str()))
        .collect();
    let mut values = BTreeMap::new();
    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, rest)) = split_metric_line(line) else {
            continue;
        };
        let Some(canonical) = wanted.get(name) else {
            continue;
        };
        let Some(value_text) = rest.split_whitespace().next() else {
            continue;
        };
        let value = value_text.parse::<f64>().map_err(|_| {
            NetdiagError::Connector(format!("Prometheus metric {name} has invalid value"))
        })?;
        if !value.is_finite() || value < 0.0 {
            return Err(NetdiagError::Connector(format!(
                "Prometheus metric {name} is not finite and non-negative"
            )));
        }
        values.insert((*canonical).to_string(), value);
    }
    Ok(values)
}

fn split_metric_line(line: &str) -> Option<(&str, &str)> {
    let name_end = line
        .find(|ch: char| ch == '{' || ch.is_whitespace())
        .unwrap_or(line.len());
    let name = &line[..name_end];
    if name.is_empty() {
        return None;
    }
    let rest = if line.as_bytes().get(name_end) == Some(&b'{') {
        let labels_end = line[name_end..].find('}')? + name_end + 1;
        &line[labels_end..]
    } else {
        &line[name_end..]
    };
    Some((name, rest.trim()))
}

fn record_from_values(
    timestamp_ms: i64,
    values: &BTreeMap<String, f64>,
    _warnings: &mut Vec<IngestWarning>,
) -> Result<TraceRecord> {
    let timestamp = Utc
        .timestamp_millis_opt(timestamp_ms)
        .single()
        .ok_or_else(|| NetdiagError::Connector("invalid Prometheus timestamp".to_string()))?;
    let optional = |name: &str| values.get(name).copied().unwrap_or(0.0);
    Ok(TraceRecord {
        timestamp,
        latency_ms: required_value(values, "latency_ms")?,
        jitter_ms: required_value(values, "jitter_ms")?,
        packet_loss_rate: required_value(values, "packet_loss_rate")?,
        retransmission_rate: required_value(values, "retransmission_rate")?,
        timeout_events: optional("timeout_events"),
        retry_events: optional("retry_events"),
        throughput_mbps: required_value(values, "throughput_mbps")?,
        dns_failure_events: optional("dns_failure_events"),
        tls_failure_events: optional("tls_failure_events"),
        quic_blocked_ratio: optional("quic_blocked_ratio"),
    })
}

fn required_value(values: &BTreeMap<String, f64>, metric: &str) -> Result<f64> {
    values
        .get(metric)
        .copied()
        .ok_or_else(|| NetdiagError::Connector(format!("missing required metric {metric}")))
}

fn merged_mapping(overrides: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut mapping = default_prometheus_mapping();
    for (key, value) in overrides {
        if key != "timestamp" {
            mapping.insert(key.clone(), value.clone());
        }
    }
    mapping
}

fn required_payload_metrics() -> BTreeSet<&'static str> {
    REQUIRED_METRICS
        .iter()
        .copied()
        .filter(|metric| *metric != "timestamp")
        .collect()
}

fn prometheus_query_endpoint(base_url: &str) -> String {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.ends_with("/api/v1/query_range") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/api/v1/query_range")
    }
}

fn fallback_warning(column: &str, reason: impl Into<String>) -> IngestWarning {
    IngestWarning {
        row: None,
        column: column.to_string(),
        reason: reason.into(),
        fallback: "0.0".to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct PrometheusEnvelope {
    status: String,
    data: Option<PrometheusData>,
    #[serde(rename = "errorType")]
    error_type: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrometheusData {
    result: Vec<PrometheusSeries>,
}

#[derive(Debug, Deserialize)]
struct PrometheusSeries {
    values: Vec<Vec<Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

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
        let values = parse_prometheus_exposition(body, &default_prometheus_mapping())
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
        let err = load_prometheus_exposition(&PrometheusExpositionConfig {
            endpoint: url,
            bearer_token: None,
            timeout: Duration::from_secs(2),
            metrics: BTreeMap::new(),
            sample: "prom_text".to_string(),
        })
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
                    "values": [[1.0, "42"], [2.0, "43"]]
                }]
            }
        })
        .to_string();
        let (url, handle) =
            serve_repeated(10, 200, response, Some("authorization: Bearer prom-token"));
        let mut queries = BTreeMap::new();
        for metric in default_prometheus_mapping().keys() {
            queries.insert(metric.clone(), format!("query_{metric}"));
        }
        let result = load_prometheus_query_range(&PrometheusQueryRangeConfig {
            base_url: url,
            bearer_token: Some("prom-token".to_string()),
            timeout: Duration::from_secs(2),
            lookback_seconds: 30,
            step_seconds: 5,
            queries,
            sample: "prom_query".to_string(),
        })
        .expect("query range");
        handle.join().expect("server thread");

        assert_eq!(result.ingest.records.len(), 2);
        assert_eq!(result.ingest.records[0].latency_ms, 42.0);
    }

    #[test]
    fn prometheus_query_range_reports_error_envelope() {
        let response = serde_json::json!({
            "status": "error",
            "errorType": "bad_data",
            "error": "parse failed"
        })
        .to_string();
        let (url, handle) = serve_repeated(1, 200, response, None);
        let err = load_prometheus_query_range(&PrometheusQueryRangeConfig {
            base_url: url,
            bearer_token: None,
            timeout: Duration::from_secs(2),
            lookback_seconds: 30,
            step_seconds: 5,
            queries: BTreeMap::new(),
            sample: "prom_query".to_string(),
        })
        .expect_err("prom error");
        handle.join().expect("server thread");
        assert!(err.to_string().contains("bad_data"));
    }

    fn serve_once(
        status: u16,
        body: String,
        expected_header: Option<&'static str>,
    ) -> (String, thread::JoinHandle<()>) {
        serve_repeated(1, status, body, expected_header)
    }

    fn serve_repeated(
        count: usize,
        status: u16,
        body: String,
        expected_header: Option<&'static str>,
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
}
