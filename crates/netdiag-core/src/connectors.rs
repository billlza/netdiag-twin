use crate::error::{NetdiagError, Result};
use crate::ingest::{
    build_ingest_result, finalize_warning_metric_provenance, measured_metric_provenance,
    set_metric_provenance,
};
use crate::models::{IngestResult, IngestWarning, MetricQuality, TraceRecord};
use crate::resource_limits::MAX_SOURCE_INPUT_BYTES;
use crate::storage::read_stable_regular_file_bounded_with_checkpoint;
use chrono::{DateTime, TimeZone, Utc};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::Capture;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

pub mod authentication;
mod capture_deadline;
mod http_client;
mod http_endpoint;
mod http_json;
mod metric_mapping;
mod otlp;
mod pcap_file;
mod pcap_read_error;
mod pcap_validation;
mod probe;
mod prometheus;
mod prometheus_mapping;
mod prometheus_matrix;
mod resource_budget;
#[cfg(any(target_os = "macos", all(test, unix)))]
mod system_counters_process;
mod validation;
use capture_deadline::CaptureDeadline;
pub(crate) use http_endpoint::parse_http_endpoint;
pub use http_endpoint::{
    HttpEndpointError, validate_http_connector_bearer_endpoint, validate_http_connector_endpoint,
};
pub use http_json::{load_http_json, validate_http_json_metadata};
pub use metric_mapping::{
    MetricMappingError, validate_prometheus_query_mapping, validate_wire_metric_mapping,
};
use metric_mapping::{merge_prometheus_query_mapping, merge_wire_metric_mapping};
pub(crate) use otlp::parse_loopback_bind_addr;
#[cfg(test)]
use otlp::parse_otlp_metrics_request;
pub use otlp::{
    OtlpGrpcReceiverConfig, OtlpReceiverSession, OtlpShutdownOutcome, load_otlp_grpc_receiver,
};
use pcap_file::PcapFileReader;
use pcap_read_error::pcap_device_read_error;
use pcap_validation::validated_capture_window;
pub use probe::{
    LocalProbeConfig, ProbeExecutionOptions, WebsiteProbeConfig, load_local_probe,
    load_local_probe_with_control, load_website_probe, load_website_probe_with_control,
};
pub use prometheus::{load_prometheus_exposition, load_prometheus_query_range};
pub use prometheus_mapping::load_prometheus_mapping_file;
use resource_budget::NetworkSourceBudget;
#[cfg(all(test, target_os = "macos"))]
use system_counters_process::NETSTAT_PROGRAM;
#[cfg(target_os = "macos")]
use system_counters_process::read_netstat_output;
pub use validation::{PrometheusQueryWindowError, validate_prometheus_query_window};
use validation::{validate_native_pcap_config, validate_system_counters_config};

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
    pub resource_usage: ConnectorResourceUsage,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectorResourceUsage {
    pub input_bytes: u64,
    pub records: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureProgress {
    pub stage: String,
    pub message: String,
    pub packets_seen: usize,
    pub bytes_seen: u64,
    pub samples_seen: usize,
    pub elapsed_ms: u64,
    pub timeout_ms: u64,
    pub packet_limit: Option<usize>,
    pub last_sample_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Default)]
pub struct CaptureControl {
    cancel: Arc<AtomicBool>,
    progress: Option<Arc<dyn Fn(CaptureProgress) + Send + Sync + 'static>>,
}

impl std::fmt::Debug for CaptureControl {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureControl")
            .field("cancelled", &self.is_cancelled())
            .field("has_progress_sink", &self.progress.is_some())
            .finish()
    }
}

impl CaptureControl {
    pub fn new(cancel: Arc<AtomicBool>) -> Self {
        Self {
            cancel,
            progress: None,
        }
    }

    pub fn with_progress(
        mut self,
        progress: impl Fn(CaptureProgress) + Send + Sync + 'static,
    ) -> Self {
        self.progress = Some(Arc::new(progress));
        self
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn report(&self, progress: CaptureProgress) {
        if let Some(callback) = &self.progress {
            callback(progress);
        }
    }
}

#[derive(Clone)]
pub struct HttpJsonConfig {
    pub endpoint: String,
    pub timeout: Duration,
}

impl std::fmt::Debug for HttpJsonConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpJsonConfig")
            .field("endpoint", &crate::reliability::redact_url(&self.endpoint))
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Clone)]
pub struct PrometheusQueryRangeConfig {
    pub base_url: String,
    pub timeout: Duration,
    pub lookback_seconds: i64,
    pub step_seconds: u64,
    pub queries: BTreeMap<String, String>,
    pub sample: String,
}

impl std::fmt::Debug for PrometheusQueryRangeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrometheusQueryRangeConfig")
            .field("base_url", &crate::reliability::redact_url(&self.base_url))
            .field("timeout", &self.timeout)
            .field("lookback_seconds", &self.lookback_seconds)
            .field("step_seconds", &self.step_seconds)
            .field("query_entries", &self.queries.len())
            .field("sample", &self.sample)
            .finish()
    }
}

#[derive(Clone)]
pub struct PrometheusExpositionConfig {
    pub endpoint: String,
    pub timeout: Duration,
    pub metrics: BTreeMap<String, String>,
    pub sample: String,
}

impl std::fmt::Debug for PrometheusExpositionConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrometheusExpositionConfig")
            .field("endpoint", &crate::reliability::redact_url(&self.endpoint))
            .field("timeout", &self.timeout)
            .field("metric_entries", &self.metrics.len())
            .field("sample", &self.sample)
            .finish()
    }
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

fn replace_metric_provenance(ingest: &mut IngestResult, source: &str) {
    ingest.metric_provenance = measured_metric_provenance(source);
    finalize_warning_metric_provenance(ingest, source);
}

pub fn load_native_pcap(config: &NativePcapConfig) -> Result<ConnectorLoadResult> {
    load_native_pcap_with_control(config, &CaptureControl::default())
}

pub fn load_native_pcap_with_control(
    config: &NativePcapConfig,
    control: &CaptureControl,
) -> Result<ConnectorLoadResult> {
    validate_native_pcap_config(config)?;
    let deadline = CaptureDeadline::new(config.timeout, "native pcap capture")?;
    deadline.ensure_remaining(control)?;
    let mut stats = PacketStats::default();
    let mut input_budget = NetworkSourceBudget::default();
    report_pcap_progress(
        control,
        &stats,
        deadline.started(),
        deadline.timeout(),
        config.packet_limit,
        "starting",
        "opening capture source",
    );
    match &config.source {
        NativePcapSource::File(path) => {
            load_native_pcap_file(
                path,
                config.packet_limit,
                deadline,
                control,
                &mut stats,
                &mut input_budget,
            )?;
        }
        NativePcapSource::Interface(interface) => {
            deadline.ensure_remaining(control)?;
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
            let mut last_report = Instant::now();
            while !deadline.is_expired() && stats.packet_count < config.packet_limit {
                if control.is_cancelled() {
                    return Err(NetdiagError::CaptureCancelled {
                        context: "native pcap capture",
                    });
                }
                match capture.next_packet() {
                    Ok(packet) => observe_captured_packet(
                        &packet,
                        &mut stats,
                        &mut input_budget,
                        "native pcap interface",
                    )?,
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(err) => return Err(pcap_device_read_error(interface, &err)),
                }
                if should_report_progress(last_report, &stats) {
                    last_report = Instant::now();
                    report_pcap_progress(
                        control,
                        &stats,
                        deadline.started(),
                        deadline.timeout(),
                        config.packet_limit,
                        "capturing",
                        "capturing live packets",
                    );
                }
            }
        }
    }
    report_pcap_progress(
        control,
        &stats,
        deadline.started(),
        deadline.timeout(),
        config.packet_limit,
        "finishing",
        "building capture sample",
    );
    packet_stats_to_result(stats, &config.sample, &config.source)
}

fn load_native_pcap_file(
    path: &Path,
    packet_limit: usize,
    deadline: CaptureDeadline,
    control: &CaptureControl,
    stats: &mut PacketStats,
    input_budget: &mut NetworkSourceBudget,
) -> Result<()> {
    deadline.ensure_remaining(control)?;
    let bytes =
        read_stable_regular_file_bounded_with_checkpoint(path, MAX_SOURCE_INPUT_BYTES, || {
            deadline.ensure_remaining(control)
        })?
        .ok_or_else(|| NetdiagError::Connector("native pcap file does not exist".to_string()))?;
    deadline.ensure_remaining(control)?;
    let mut reader = PcapFileReader::new(&bytes)?;
    let mut last_report = Instant::now();
    while stats.packet_count < packet_limit {
        deadline.ensure_remaining(control)?;
        let Some(packet) = reader.next_packet()? else {
            break;
        };
        observe_captured_packet_parts(
            packet.seconds,
            packet.microseconds,
            packet.original_length,
            packet.data,
            stats,
            input_budget,
            "native pcap file",
        )?;
        if should_report_progress(last_report, stats) {
            last_report = Instant::now();
            report_pcap_progress(
                control,
                stats,
                deadline.started(),
                deadline.timeout(),
                packet_limit,
                "capturing",
                "reading pcap file",
            );
        }
    }
    deadline.ensure_remaining(control)
}

pub fn load_system_counters(config: &SystemCountersConfig) -> Result<ConnectorLoadResult> {
    load_system_counters_with_control(config, &CaptureControl::default())
}

pub fn load_system_counters_with_control(
    config: &SystemCountersConfig,
    control: &CaptureControl,
) -> Result<ConnectorLoadResult> {
    validate_system_counters_config(config)?;
    let started = Instant::now();
    let interval = config.interval;
    report_counter_progress(
        control,
        started,
        interval,
        0,
        None,
        "starting",
        "reading initial interface counters",
    );
    if control.is_cancelled() {
        return Err(NetdiagError::CaptureCancelled {
            context: "system counters capture",
        });
    }
    let before = read_netstat_counters(control)?;
    while started.elapsed() < interval {
        if control.is_cancelled() {
            return Err(NetdiagError::CaptureCancelled {
                context: "system counters capture",
            });
        }
        report_counter_progress(
            control,
            started,
            interval,
            0,
            None,
            "sampling",
            "waiting for counter interval",
        );
        let remaining = interval.saturating_sub(started.elapsed());
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
    }
    let after = read_netstat_counters(control)?;
    let delta = diff_counters(&before, &after, config.interface.as_deref())?;
    report_counter_progress(
        control,
        started,
        interval,
        1,
        Some(Utc::now()),
        "finishing",
        "building counter sample",
    );
    system_counter_delta_to_result(delta, interval, Utc::now(), config)
}

fn system_counter_delta_to_result(
    delta: CounterDelta,
    interval: Duration,
    timestamp: DateTime<Utc>,
    config: &SystemCountersConfig,
) -> Result<ConnectorLoadResult> {
    let interval_s = interval.as_secs_f64().max(1e-6);
    let throughput_mbps = (delta.bytes as f64 * 8.0) / interval_s / 1_000_000.0;
    let total_packets = delta.packets.checked_add(delta.errors).ok_or_else(|| {
        NetdiagError::Connector(
            "system counter packet and error totals exceeded the supported u64 range".to_string(),
        )
    })?;
    let drop_rate = if total_packets > 0 {
        (delta.errors as f64 / total_packets as f64) * 100.0
    } else {
        0.0
    };
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
    replace_metric_provenance(&mut ingest, "system_counters");
    set_metric_provenance(
        &mut ingest,
        "packet_loss_rate",
        MetricQuality::Measured,
        "system_counters",
        "derived from interface error counters",
    );
    set_metric_provenance(
        &mut ingest,
        "throughput_mbps",
        MetricQuality::Measured,
        "system_counters",
        "derived from interface byte counters",
    );
    let resource_usage = ConnectorResourceUsage {
        input_bytes: 0,
        records: ingest.records.len(),
    };
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
        resource_usage,
    })
}

fn record_from_values(timestamp_ms: i64, values: &BTreeMap<String, f64>) -> Result<TraceRecord> {
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

fn required_payload_metrics() -> BTreeSet<&'static str> {
    REQUIRED_METRICS
        .iter()
        .copied()
        .filter(|metric| *metric != "timestamp")
        .collect()
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

fn should_report_progress(last_report: Instant, stats: &PacketStats) -> bool {
    stats.packet_count == 1
        || stats.packet_count.is_multiple_of(64)
        || last_report.elapsed() >= Duration::from_millis(250)
}

fn report_pcap_progress(
    control: &CaptureControl,
    stats: &PacketStats,
    started: Instant,
    timeout: Duration,
    packet_limit: usize,
    stage: &str,
    message: &str,
) {
    control.report(CaptureProgress {
        stage: stage.to_string(),
        message: message.to_string(),
        packets_seen: stats.packet_count,
        bytes_seen: stats.total_bytes,
        samples_seen: usize::from(stats.packet_count > 0),
        elapsed_ms: started.elapsed().as_millis() as u64,
        timeout_ms: timeout.as_millis() as u64,
        packet_limit: Some(packet_limit),
        last_sample_at: stats
            .last_ts_ms
            .and_then(|ts| Utc.timestamp_millis_opt(ts).single()),
    });
}

fn report_counter_progress(
    control: &CaptureControl,
    started: Instant,
    interval: Duration,
    samples_seen: usize,
    last_sample_at: Option<DateTime<Utc>>,
    stage: &str,
    message: &str,
) {
    control.report(CaptureProgress {
        stage: stage.to_string(),
        message: message.to_string(),
        packets_seen: 0,
        bytes_seen: 0,
        samples_seen,
        elapsed_ms: started.elapsed().as_millis() as u64,
        timeout_ms: interval.as_millis() as u64,
        packet_limit: None,
        last_sample_at,
    });
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

fn observe_captured_packet(
    packet: &pcap::Packet<'_>,
    stats: &mut PacketStats,
    input_budget: &mut NetworkSourceBudget,
    context: &str,
) -> Result<()> {
    observe_captured_packet_parts(
        packet_time_component(packet.header.ts.tv_sec, "seconds")?,
        packet_time_component(packet.header.ts.tv_usec, "microseconds")?,
        packet.header.len,
        packet.data,
        stats,
        input_budget,
        context,
    )
}

fn packet_time_component<T>(value: T, component: &str) -> Result<i64>
where
    i64: TryFrom<T>,
{
    i64::try_from(value).map_err(|_| {
        NetdiagError::Connector(format!(
            "native pcap timestamp {component} do not fit the supported i64 range"
        ))
    })
}

fn observe_captured_packet_parts(
    seconds: i64,
    microseconds: i64,
    original_length: u32,
    data: &[u8],
    stats: &mut PacketStats,
    input_budget: &mut NetworkSourceBudget,
    context: &str,
) -> Result<()> {
    input_budget.reserve_input_bytes(u64::from(original_length), context)?;
    let packet_len = usize::try_from(original_length).map_err(|_| {
        NetdiagError::Connector(format!(
            "{context} packet length does not fit the platform address space"
        ))
    })?;
    let timestamp_ms = packet_timestamp_ms(seconds, microseconds)?;
    observe_packet(timestamp_ms, packet_len, data, stats);
    Ok(())
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
    let (last_ts_ms, elapsed_ms) = validated_capture_window(stats.first_ts_ms, stats.last_ts_ms)?;
    let duration_s = (elapsed_ms as f64 / 1000.0).max(1e-3);
    let retransmission_rate = if stats.tcp_packets > 0 {
        (stats.retransmissions as f64 / stats.tcp_packets as f64) * 100.0
    } else {
        0.0
    };
    let throughput_mbps = (stats.total_bytes as f64 * 8.0) / duration_s / 1_000_000.0;
    let timestamp = Utc
        .timestamp_millis_opt(last_ts_ms)
        .single()
        .ok_or_else(|| {
            NetdiagError::Connector(format!(
                "native pcap capture timestamp is outside the supported range: {last_ts_ms}"
            ))
        })?;
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
    replace_metric_provenance(&mut ingest, "native_pcap");
    set_metric_provenance(
        &mut ingest,
        "throughput_mbps",
        MetricQuality::Measured,
        "native_pcap",
        "computed from observed packet bytes over capture duration",
    );
    set_metric_provenance(
        &mut ingest,
        "retransmission_rate",
        MetricQuality::Estimated,
        "native_pcap",
        "estimated from repeated TCP sequence observations",
    );
    let resource_usage = ConnectorResourceUsage {
        input_bytes: stats.total_bytes,
        records: ingest.records.len(),
    };
    let flow_count = u64::try_from(stats.flows.len()).map_err(|_| {
        NetdiagError::Connector(
            "native pcap flow count exceeded the supported u64 range".to_string(),
        )
    })?;
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
            "flow_count": flow_count,
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
        resource_usage,
    })
}

fn packet_timestamp_ms(seconds: i64, micros: i64) -> Result<i64> {
    if !(0..1_000_000).contains(&micros) {
        return Err(NetdiagError::Connector(format!(
            "native pcap timestamp microseconds are outside [0, 1000000): {micros}"
        )));
    }
    seconds
        .checked_mul(1_000)
        .and_then(|millis| millis.checked_add(micros / 1_000))
        .ok_or_else(|| {
            NetdiagError::Connector(
                "native pcap timestamp is outside the supported millisecond range".to_string(),
            )
        })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

#[cfg(target_os = "macos")]
fn read_netstat_counters(control: &CaptureControl) -> Result<BTreeMap<String, InterfaceCounters>> {
    let text = String::from_utf8(read_netstat_output(control)?).map_err(|error| {
        NetdiagError::Connector(format!("netstat -ibn emitted invalid UTF-8: {error}"))
    })?;
    parse_netstat_counters(&text)
}

#[cfg(not(target_os = "macos"))]
fn read_netstat_counters(_control: &CaptureControl) -> Result<BTreeMap<String, InterfaceCounters>> {
    Err(NetdiagError::Connector(
        "system counters are supported only on macOS".to_string(),
    ))
}

#[cfg(any(target_os = "macos", test))]
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
    for (row_index, line) in lines.enumerate() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= obytes_idx {
            return Err(NetdiagError::Connector(format!(
                "netstat row {} is missing required counter columns",
                row_index + 2
            )));
        }
        let name = fields[name_idx].to_string();
        let parsed = InterfaceCounters {
            bytes: checked_counter_pair(
                &name,
                "bytes",
                parse_u64_field(fields[ibytes_idx])?,
                parse_u64_field(fields[obytes_idx])?,
            )?,
            packets: checked_counter_pair(
                &name,
                "packets",
                parse_u64_field(fields[ipkts_idx])?,
                parse_u64_field(fields[opkts_idx])?,
            )?,
            errors: checked_counter_pair(
                &name,
                "errors",
                parse_u64_field(fields[ierrs_idx])?,
                parse_u64_field(fields[oerrs_idx])?,
            )?,
        };
        if let Some(current) = counters.insert(name.clone(), parsed)
            && current != parsed
        {
            return Err(NetdiagError::Connector(format!(
                "netstat emitted inconsistent duplicate counters for interface {name}"
            )));
        }
    }
    if counters.is_empty() {
        return Err(NetdiagError::Connector(
            "netstat output contained no interface counters".to_string(),
        ));
    }
    Ok(counters)
}

#[cfg(any(target_os = "macos", test))]
fn parse_u64_field(value: &str) -> Result<u64> {
    if value == "-" {
        return Err(NetdiagError::Connector(
            "netstat counter is unavailable (`-`)".to_string(),
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| NetdiagError::Connector(format!("invalid netstat counter: {value}")))
}

#[cfg(any(target_os = "macos", test))]
fn checked_counter_pair(interface: &str, kind: &str, incoming: u64, outgoing: u64) -> Result<u64> {
    incoming.checked_add(outgoing).ok_or_else(|| {
        NetdiagError::Connector(format!(
            "netstat {kind} counter overflowed for interface {interface}"
        ))
    })
}

fn diff_counters(
    before: &BTreeMap<String, InterfaceCounters>,
    after: &BTreeMap<String, InterfaceCounters>,
    interface: Option<&str>,
) -> Result<CounterDelta> {
    if let Some(wanted) = interface.filter(|wanted| *wanted != "all") {
        let before_value = before.get(wanted).ok_or_else(|| {
            NetdiagError::Connector(format!(
                "system counter interface not found in initial sample: {wanted}"
            ))
        })?;
        let after_value = after.get(wanted).ok_or_else(|| {
            NetdiagError::Connector(format!(
                "system counter interface disappeared during sampling: {wanted}"
            ))
        })?;
        return counter_delta(wanted, *before_value, *after_value);
    }

    ensure_interface_set_stable(before, after)?;
    let mut delta = CounterDelta::default();
    for (name, before_value) in before {
        let after_value = after.get(name).ok_or_else(|| {
            NetdiagError::Connector(format!(
                "system counter interface disappeared during sampling: {name}"
            ))
        })?;
        delta = checked_delta_sum(delta, counter_delta(name, *before_value, *after_value)?)?;
    }
    Ok(delta)
}

fn ensure_interface_set_stable(
    before: &BTreeMap<String, InterfaceCounters>,
    after: &BTreeMap<String, InterfaceCounters>,
) -> Result<()> {
    if let Some(name) = before.keys().find(|name| !after.contains_key(*name)) {
        return Err(NetdiagError::Connector(format!(
            "system counter interface disappeared during sampling: {name}"
        )));
    }
    if let Some(name) = after.keys().find(|name| !before.contains_key(*name)) {
        return Err(NetdiagError::Connector(format!(
            "system counter interface appeared during sampling: {name}"
        )));
    }
    Ok(())
}

fn counter_delta(
    interface: &str,
    before: InterfaceCounters,
    after: InterfaceCounters,
) -> Result<CounterDelta> {
    Ok(CounterDelta {
        bytes: checked_counter_delta(interface, "bytes", before.bytes, after.bytes)?,
        packets: checked_counter_delta(interface, "packets", before.packets, after.packets)?,
        errors: checked_counter_delta(interface, "errors", before.errors, after.errors)?,
    })
}

fn checked_counter_delta(interface: &str, kind: &str, before: u64, after: u64) -> Result<u64> {
    after.checked_sub(before).ok_or_else(|| {
        NetdiagError::Connector(format!(
            "system counter {kind} decreased during sampling for interface {interface}"
        ))
    })
}

fn checked_delta_sum(left: CounterDelta, right: CounterDelta) -> Result<CounterDelta> {
    Ok(CounterDelta {
        bytes: left.bytes.checked_add(right.bytes).ok_or_else(|| {
            NetdiagError::Connector(
                "aggregate system counter byte delta exceeded the supported u64 range".to_string(),
            )
        })?,
        packets: left.packets.checked_add(right.packets).ok_or_else(|| {
            NetdiagError::Connector(
                "aggregate system counter packet delta exceeded the supported u64 range"
                    .to_string(),
            )
        })?,
        errors: left.errors.checked_add(right.errors).ok_or_else(|| {
            NetdiagError::Connector(
                "aggregate system counter error delta exceeded the supported u64 range".to_string(),
            )
        })?,
    })
}

#[cfg(test)]
mod tests;
