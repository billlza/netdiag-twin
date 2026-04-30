use crate::error::{NetdiagError, Result};
use crate::ingest::{CANONICAL_COLUMNS, build_ingest_result};
use crate::models::{IngestResult, IngestWarning, TraceRecord};
use chrono::{TimeZone, Utc};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use opentelemetry_proto::tonic as otlp;
use otlp::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
    metrics_service_server::{MetricsService, MetricsServiceServer},
};
use otlp::metrics::v1::{Metric, metric, number_data_point};
use pcap::Capture;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
use tonic::{Request, Response, Status};

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

#[derive(Debug, Clone)]
pub struct OtlpGrpcReceiverConfig {
    pub bind_addr: String,
    pub timeout: Duration,
    pub metrics: BTreeMap<String, String>,
    pub sample: String,
}

#[derive(Debug, Clone)]
pub enum NativePcapSource {
    File(PathBuf),
    Interface(String),
}

#[derive(Debug, Clone)]
pub struct NativePcapConfig {
    pub source: NativePcapSource,
    pub timeout: Duration,
    pub packet_limit: usize,
    pub sample: String,
}

#[derive(Debug, Clone)]
pub struct SystemCountersConfig {
    pub interface: Option<String>,
    pub interval: Duration,
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

pub fn load_otlp_grpc_receiver(config: &OtlpGrpcReceiverConfig) -> Result<ConnectorLoadResult> {
    let bind_addr: SocketAddr = config
        .bind_addr
        .trim()
        .parse()
        .map_err(|err| NetdiagError::Connector(format!("invalid OTLP bind address: {err}")))?;
    let (export_tx, export_rx) = mpsc::channel::<ExportMetricsServiceRequest>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let service = OtlpMetricsReceiver {
        sender: Arc::new(Mutex::new(Some(export_tx))),
    };
    let server = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|err| err.to_string())?;
        runtime
            .block_on(async move {
                tonic::transport::Server::builder()
                    .add_service(MetricsServiceServer::new(service))
                    .serve_with_shutdown(bind_addr, async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .map_err(|err| err.to_string())
            })
            .map_err(|err| err.to_string())
    });

    let request = match export_rx.recv_timeout(config.timeout) {
        Ok(request) => request,
        Err(_) => {
            let _ = shutdown_tx.send(());
            let _ = server.join();
            return Err(NetdiagError::Connector(format!(
                "OTLP gRPC receiver timed out after {}s waiting for metrics",
                config.timeout.as_secs().max(1)
            )));
        }
    };
    let _ = shutdown_tx.send(());
    let _ = server.join();

    let mapping = merged_mapping(&config.metrics);
    let (values, timestamp_ms) = parse_otlp_metrics_request(&request, &mapping)?;
    let mut warnings = fallback_warnings_for_missing_events(&values, "OTLP metric is missing");
    for metric in required_payload_metrics() {
        if !values.contains_key(metric) {
            return Err(NetdiagError::Connector(format!(
                "OTLP metrics missing required metric {metric}"
            )));
        }
    }
    let mut ingest = build_ingest_result(
        vec![record_from_values(timestamp_ms, &values, &mut warnings)?],
        config.sample.clone(),
    )?;
    ingest.warnings.extend(warnings);
    Ok(ConnectorLoadResult {
        ingest,
        sample: config.sample.clone(),
        provenance: BTreeMap::from([
            ("kind".to_string(), "otlp_grpc_receiver".to_string()),
            ("bind_addr".to_string(), config.bind_addr.clone()),
        ]),
        payload: None,
    })
}

pub fn load_native_pcap(config: &NativePcapConfig) -> Result<ConnectorLoadResult> {
    let mut stats = PacketStats::default();
    match &config.source {
        NativePcapSource::File(path) => {
            let mut capture = Capture::from_file(path).map_err(|err| {
                NetdiagError::Connector(format!(
                    "failed to open pcap file {}: {err}",
                    path.display()
                ))
            })?;
            while let Ok(packet) = capture.next_packet() {
                observe_packet(
                    packet_timestamp_ms(
                        packet.header.ts.tv_sec,
                        i64::from(packet.header.ts.tv_usec),
                    ),
                    packet.header.len as usize,
                    packet.data,
                    &mut stats,
                );
                if stats.packet_count >= config.packet_limit.max(1) {
                    break;
                }
            }
        }
        NativePcapSource::Interface(interface) => {
            let mut capture = Capture::from_device(interface.as_str())
                .map_err(|err| {
                    NetdiagError::Connector(format!(
                        "failed to open capture device {interface}: {err}"
                    ))
                })?
                .timeout(250)
                .promisc(false)
                .open()
                .map_err(|err| {
                    NetdiagError::Connector(format!(
                        "failed to activate capture device {interface}: {err}"
                    ))
                })?;
            let started = Instant::now();
            while started.elapsed() < config.timeout
                && stats.packet_count < config.packet_limit.max(1)
            {
                if let Ok(packet) = capture.next_packet() {
                    observe_packet(
                        packet_timestamp_ms(
                            packet.header.ts.tv_sec,
                            i64::from(packet.header.ts.tv_usec),
                        ),
                        packet.header.len as usize,
                        packet.data,
                        &mut stats,
                    );
                }
            }
        }
    }
    packet_stats_to_result(stats, &config.sample, &config.source)
}

pub fn load_system_counters(config: &SystemCountersConfig) -> Result<ConnectorLoadResult> {
    let before = read_netstat_counters()?;
    std::thread::sleep(config.interval.min(Duration::from_secs(10)));
    let after = read_netstat_counters()?;
    let delta = diff_counters(&before, &after, config.interface.as_deref())?;
    let interval_s = config.interval.as_secs_f64().max(1e-6);
    let throughput_mbps = (delta.bytes as f64 * 8.0) / interval_s / 1_000_000.0;
    let total_packets = delta.packets + delta.errors;
    let drop_rate = if total_packets > 0 {
        (delta.errors as f64 / total_packets as f64) * 100.0
    } else {
        0.0
    };
    let timestamp = Utc::now();
    let mut ingest = build_ingest_result(
        vec![TraceRecord {
            timestamp,
            latency_ms: 0.1,
            jitter_ms: 0.0,
            packet_loss_rate: drop_rate,
            retransmission_rate: 0.0,
            timeout_events: 0.0,
            retry_events: 0.0,
            throughput_mbps,
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 0.0,
        }],
        config.sample.clone(),
    )?;
    ingest.warnings.extend([
        fallback_warning("latency_ms", "system counters do not expose RTT"),
        fallback_warning("jitter_ms", "system counters do not expose jitter"),
        fallback_warning(
            "retransmission_rate",
            "system counters do not expose TCP retransmissions",
        ),
        fallback_warning(
            "quic_blocked_ratio",
            "system counters do not expose QUIC policy state",
        ),
    ]);
    Ok(ConnectorLoadResult {
        ingest,
        sample: config.sample.clone(),
        provenance: BTreeMap::from([
            ("kind".to_string(), "system_counters".to_string()),
            (
                "interface".to_string(),
                config
                    .interface
                    .clone()
                    .unwrap_or_else(|| "all".to_string()),
            ),
        ]),
        payload: Some(serde_json::json!({
            "bytes": delta.bytes,
            "packets": delta.packets,
            "errors": delta.errors,
            "interval_seconds": interval_s,
        })),
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

fn fallback_warnings_for_missing_events(
    values: &BTreeMap<String, f64>,
    reason: &'static str,
) -> Vec<IngestWarning> {
    EVENT_METRICS
        .into_iter()
        .filter(|metric| !values.contains_key(*metric))
        .map(|metric| fallback_warning(metric, reason))
        .collect()
}

#[derive(Debug)]
struct OtlpMetricsReceiver {
    sender: Arc<Mutex<Option<mpsc::Sender<ExportMetricsServiceRequest>>>>,
}

#[tonic::async_trait]
impl MetricsService for OtlpMetricsReceiver {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> std::result::Result<Response<ExportMetricsServiceResponse>, Status> {
        if let Some(sender) = self
            .sender
            .lock()
            .map_err(|_| Status::internal("receiver lock poisoned"))?
            .take()
        {
            let _ = sender.send(request.into_inner());
        }
        Ok(Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

fn parse_otlp_metrics_request(
    request: &ExportMetricsServiceRequest,
    mapping: &BTreeMap<String, String>,
) -> Result<(BTreeMap<String, f64>, i64)> {
    let wanted: BTreeMap<&str, &str> = mapping
        .iter()
        .map(|(canonical, metric)| (metric.as_str(), canonical.as_str()))
        .collect();
    let mut values = BTreeMap::new();
    let mut latest_time_nanos = 0_u64;
    for resource in &request.resource_metrics {
        for scope in &resource.scope_metrics {
            for metric in &scope.metrics {
                let Some(canonical) = wanted.get(metric.name.as_str()) else {
                    continue;
                };
                if let Some((value, timestamp)) = latest_metric_number(metric)
                    && value.is_finite()
                    && value >= 0.0
                {
                    values.insert((*canonical).to_string(), value);
                    latest_time_nanos = latest_time_nanos.max(timestamp);
                }
            }
        }
    }
    if values.is_empty() {
        return Err(NetdiagError::Connector(
            "OTLP export did not contain mapped numeric metrics".to_string(),
        ));
    }
    let timestamp_ms = if latest_time_nanos > 0 {
        (latest_time_nanos / 1_000_000) as i64
    } else {
        Utc::now().timestamp_millis()
    };
    Ok((values, timestamp_ms))
}

fn latest_metric_number(metric: &Metric) -> Option<(f64, u64)> {
    let points = match metric.data.as_ref()? {
        metric::Data::Gauge(gauge) => &gauge.data_points,
        metric::Data::Sum(sum) => &sum.data_points,
        _ => return None,
    };
    points
        .iter()
        .filter_map(number_point_value)
        .max_by(|left, right| {
            left.1
                .cmp(&right.1)
                .then_with(|| left.0.total_cmp(&right.0))
        })
}

fn number_point_value(point: &otlp::metrics::v1::NumberDataPoint) -> Option<(f64, u64)> {
    let value = match point.value.as_ref()? {
        number_data_point::Value::AsDouble(value) => *value,
        number_data_point::Value::AsInt(value) => *value as f64,
    };
    Some((value, point.time_unix_nano))
}

#[derive(Debug, Default)]
struct PacketStats {
    packet_count: usize,
    total_bytes: u64,
    tcp_packets: usize,
    udp_packets: usize,
    dns_packets: usize,
    tls_packets: usize,
    quic_packets: usize,
    retransmissions: usize,
    first_ts_ms: Option<i64>,
    last_ts_ms: Option<i64>,
    seen_tcp_sequences: BTreeSet<String>,
    flows: BTreeMap<String, u64>,
}

fn observe_packet(timestamp_ms: i64, packet_len: usize, data: &[u8], stats: &mut PacketStats) {
    stats.packet_count += 1;
    stats.total_bytes += packet_len as u64;
    stats.first_ts_ms = Some(
        stats
            .first_ts_ms
            .map_or(timestamp_ms, |ts| ts.min(timestamp_ms)),
    );
    stats.last_ts_ms = Some(
        stats
            .last_ts_ms
            .map_or(timestamp_ms, |ts| ts.max(timestamp_ms)),
    );

    let Ok(packet) = SlicedPacket::from_ethernet(data).or_else(|_| SlicedPacket::from_ip(data))
    else {
        return;
    };
    let (source, target) = ip_pair(packet.net.as_ref());
    match packet.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            stats.tcp_packets += 1;
            let flow = format!(
                "{}:{} -> {}:{}",
                source,
                tcp.source_port(),
                target,
                tcp.destination_port()
            );
            *stats.flows.entry(flow.clone()).or_default() += packet_len as u64;
            if tcp.source_port() == 443 || tcp.destination_port() == 443 {
                stats.tls_packets += 1;
            }
            let payload_len = tcp.payload().len();
            if payload_len > 0 {
                let sequence_key = format!("{flow}:{}", tcp.sequence_number());
                if !stats.seen_tcp_sequences.insert(sequence_key) {
                    stats.retransmissions += 1;
                }
            }
        }
        Some(TransportSlice::Udp(udp)) => {
            stats.udp_packets += 1;
            let flow = format!(
                "{}:{} -> {}:{}",
                source,
                udp.source_port(),
                target,
                udp.destination_port()
            );
            *stats.flows.entry(flow).or_default() += packet_len as u64;
            if udp.source_port() == 53 || udp.destination_port() == 53 {
                stats.dns_packets += 1;
            }
            if udp.source_port() == 443 || udp.destination_port() == 443 {
                stats.quic_packets += 1;
            }
        }
        _ => {}
    }
}

fn ip_pair(net: Option<&NetSlice<'_>>) -> (String, String) {
    match net {
        Some(NetSlice::Ipv4(ip)) => (
            ip.header().source_addr().to_string(),
            ip.header().destination_addr().to_string(),
        ),
        Some(NetSlice::Ipv6(ip)) => (
            ip.header().source_addr().to_string(),
            ip.header().destination_addr().to_string(),
        ),
        _ => ("unknown".to_string(), "unknown".to_string()),
    }
}

fn packet_stats_to_result(
    stats: PacketStats,
    sample: &str,
    source: &NativePcapSource,
) -> Result<ConnectorLoadResult> {
    if stats.packet_count == 0 {
        return Err(NetdiagError::Connector(
            "native pcap capture produced no packets".to_string(),
        ));
    }
    let duration_s = stats
        .first_ts_ms
        .zip(stats.last_ts_ms)
        .map(|(start, end)| ((end - start) as f64 / 1000.0).max(1e-3))
        .unwrap_or(1.0);
    let retransmission_rate = if stats.tcp_packets > 0 {
        (stats.retransmissions as f64 / stats.tcp_packets as f64) * 100.0
    } else {
        0.0
    };
    let throughput_mbps = (stats.total_bytes as f64 * 8.0) / duration_s / 1_000_000.0;
    let timestamp = stats
        .last_ts_ms
        .and_then(|ts| Utc.timestamp_millis_opt(ts).single())
        .unwrap_or_else(Utc::now);
    let mut ingest = build_ingest_result(
        vec![TraceRecord {
            timestamp,
            latency_ms: 0.1,
            jitter_ms: 0.0,
            packet_loss_rate: 0.0,
            retransmission_rate,
            timeout_events: 0.0,
            retry_events: 0.0,
            throughput_mbps,
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 0.0,
        }],
        sample.to_string(),
    )?;
    ingest.warnings.extend([
        fallback_warning(
            "latency_ms",
            "pcap capture does not directly expose RTT without request/response correlation",
        ),
        fallback_warning(
            "jitter_ms",
            "pcap capture does not directly expose jitter without RTT correlation",
        ),
        fallback_warning(
            "packet_loss_rate",
            "pcap capture observes packets but cannot infer end-to-end loss alone",
        ),
        fallback_warning(
            "quic_blocked_ratio",
            "pcap capture can observe UDP/443 but cannot prove QUIC policy blocking",
        ),
    ]);
    let mut top_talkers = stats.flows.into_iter().collect::<Vec<_>>();
    top_talkers.sort_by_key(|talker| std::cmp::Reverse(talker.1));
    top_talkers.truncate(5);
    Ok(ConnectorLoadResult {
        ingest,
        sample: sample.to_string(),
        provenance: BTreeMap::from([
            ("kind".to_string(), "native_pcap".to_string()),
            (
                "source".to_string(),
                match source {
                    NativePcapSource::File(path) => path.display().to_string(),
                    NativePcapSource::Interface(name) => format!("interface:{name}"),
                },
            ),
            ("packets".to_string(), stats.packet_count.to_string()),
            ("tcp_packets".to_string(), stats.tcp_packets.to_string()),
            ("udp_packets".to_string(), stats.udp_packets.to_string()),
        ]),
        payload: Some(serde_json::json!({
            "total_bytes": stats.total_bytes,
            "duration_seconds": duration_s,
            "tcp_packets": stats.tcp_packets,
            "udp_packets": stats.udp_packets,
            "dns_packets": stats.dns_packets,
            "tls_packets": stats.tls_packets,
            "quic_packets": stats.quic_packets,
            "retransmissions": stats.retransmissions,
            "top_talkers": top_talkers.into_iter().map(|(label, bytes)| {
                serde_json::json!({ "label": label, "bytes": bytes })
            }).collect::<Vec<_>>(),
        })),
    })
}

fn packet_timestamp_ms(seconds: i64, micros: i64) -> i64 {
    seconds.saturating_mul(1000) + micros.saturating_div(1000)
}

#[derive(Debug, Clone, Copy, Default)]
struct InterfaceCounters {
    bytes: u64,
    packets: u64,
    errors: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct CounterDelta {
    bytes: u64,
    packets: u64,
    errors: u64,
}

fn read_netstat_counters() -> Result<BTreeMap<String, InterfaceCounters>> {
    let output = Command::new("netstat")
        .args(["-ibn"])
        .output()
        .map_err(|err| NetdiagError::Connector(format!("failed to run netstat -ibn: {err}")))?;
    if !output.status.success() {
        return Err(NetdiagError::Connector(format!(
            "netstat -ibn failed with status {}",
            output.status
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_netstat_counters(&text)
}

fn parse_netstat_counters(text: &str) -> Result<BTreeMap<String, InterfaceCounters>> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| NetdiagError::Connector("netstat output is empty".to_string()))?;
    let columns = header.split_whitespace().collect::<Vec<_>>();
    let index = |name: &str| {
        columns
            .iter()
            .position(|column| *column == name)
            .ok_or_else(|| NetdiagError::Connector(format!("netstat missing {name} column")))
    };
    let name_idx = index("Name")?;
    let ipkts_idx = index("Ipkts")?;
    let ierrs_idx = index("Ierrs")?;
    let ibytes_idx = index("Ibytes")?;
    let opkts_idx = index("Opkts")?;
    let oerrs_idx = index("Oerrs")?;
    let obytes_idx = index("Obytes")?;
    let mut counters = BTreeMap::<String, InterfaceCounters>::new();
    for line in lines {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= obytes_idx {
            continue;
        }
        let name = fields[name_idx].to_string();
        let parsed = InterfaceCounters {
            bytes: parse_u64_field(fields[ibytes_idx])? + parse_u64_field(fields[obytes_idx])?,
            packets: parse_u64_field(fields[ipkts_idx])? + parse_u64_field(fields[opkts_idx])?,
            errors: parse_u64_field(fields[ierrs_idx])? + parse_u64_field(fields[oerrs_idx])?,
        };
        counters
            .entry(name)
            .and_modify(|current| {
                current.bytes = current.bytes.max(parsed.bytes);
                current.packets = current.packets.max(parsed.packets);
                current.errors = current.errors.max(parsed.errors);
            })
            .or_insert(parsed);
    }
    if counters.is_empty() {
        return Err(NetdiagError::Connector(
            "netstat output contained no interface counters".to_string(),
        ));
    }
    Ok(counters)
}

fn parse_u64_field(value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| NetdiagError::Connector(format!("invalid netstat counter: {value}")))
}

fn diff_counters(
    before: &BTreeMap<String, InterfaceCounters>,
    after: &BTreeMap<String, InterfaceCounters>,
    interface: Option<&str>,
) -> Result<CounterDelta> {
    let mut delta = CounterDelta::default();
    let mut matched = 0usize;
    for (name, after_value) in after {
        if interface.is_some_and(|wanted| wanted != "all" && wanted != name) {
            continue;
        }
        matched += 1;
        let before_value = before.get(name).copied().unwrap_or_default();
        delta.bytes += after_value.bytes.saturating_sub(before_value.bytes);
        delta.packets += after_value.packets.saturating_sub(before_value.packets);
        delta.errors += after_value.errors.saturating_sub(before_value.errors);
    }
    if matched == 0
        && let Some(wanted) = interface.filter(|wanted| *wanted != "all")
    {
        return Err(NetdiagError::Connector(format!(
            "system counter interface not found: {wanted}"
        )));
    }
    Ok(delta)
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

    #[test]
    fn native_pcap_stats_keep_observed_values_and_warn_on_missing_fields() {
        let mut stats = PacketStats {
            packet_count: 4,
            total_bytes: 4_000,
            tcp_packets: 4,
            retransmissions: 1,
            first_ts_ms: Some(1_000),
            last_ts_ms: Some(2_000),
            ..PacketStats::default()
        };
        stats
            .flows
            .insert("10.0.0.1:443 -> 10.0.0.2:51515".to_string(), 4_000);

        let loaded = packet_stats_to_result(
            stats,
            "pcap_fixture",
            &NativePcapSource::Interface("lo0".to_string()),
        )
        .expect("pcap stats");

        assert_eq!(loaded.ingest.records[0].throughput_mbps, 0.032);
        assert_eq!(loaded.ingest.records[0].retransmission_rate, 25.0);
        assert!(
            loaded
                .ingest
                .warnings
                .iter()
                .any(|warning| warning.column == "packet_loss_rate")
        );
        assert_eq!(
            loaded
                .payload
                .as_ref()
                .and_then(|value| value.get("total_bytes"))
                .and_then(Value::as_u64),
            Some(4_000)
        );
    }

    #[test]
    fn netstat_parser_computes_interface_counter_deltas() {
        let before = parse_netstat_counters(
            "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
             en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n",
        )
        .expect("before");
        let after = parse_netstat_counters(
            "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
             en0 1500 <Link#4> aa 15 1 1600 30 3 2600 0\n",
        )
        .expect("after");

        let delta = diff_counters(&before, &after, Some("en0")).expect("delta");

        assert_eq!(delta.bytes, 1_200);
        assert_eq!(delta.packets, 15);
        assert_eq!(delta.errors, 1);
    }

    #[test]
    fn netstat_counter_delta_allows_quiet_interfaces() {
        let before = parse_netstat_counters(
            "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
             en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n",
        )
        .expect("before");
        let after = parse_netstat_counters(
            "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
             en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n",
        )
        .expect("after");

        let delta = diff_counters(&before, &after, Some("en0")).expect("quiet delta");

        assert_eq!(delta.bytes, 0);
        assert_eq!(delta.packets, 0);
        assert_eq!(delta.errors, 0);
    }

    #[test]
    fn netstat_counter_delta_reports_unknown_interface() {
        let before = parse_netstat_counters(
            "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
             en0 1500 <Link#4> aa 10 1 1000 20 2 2000 0\n",
        )
        .expect("before");
        let after = parse_netstat_counters(
            "Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll\n\
             en0 1500 <Link#4> aa 15 1 1600 30 3 2600 0\n",
        )
        .expect("after");

        let err = diff_counters(&before, &after, Some("utun404")).expect_err("unknown interface");

        assert!(err.to_string().contains("interface not found: utun404"));
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
