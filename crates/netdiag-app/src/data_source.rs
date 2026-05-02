use crate::settings::{
    ApiConfig, LocalProbeSettings, NativePcapSettings, OtlpGrpcSettings,
    PrometheusExpositionSettings, PrometheusQuerySettings, SystemCountersSettings,
    WebsiteProbeSettings,
};
use anyhow::{Result, bail};
use chrono::{Duration, TimeZone, Utc};
use netdiag_core::connectors::{
    HttpJsonConfig, NativePcapConfig, NativePcapSource, OtlpGrpcReceiverConfig,
    PrometheusExpositionConfig, PrometheusQueryRangeConfig, SystemCountersConfig, load_http_json,
    load_native_pcap, load_otlp_grpc_receiver, load_prometheus_exposition,
    load_prometheus_query_range, load_system_counters,
};
use netdiag_core::ingest::{build_ingest_result, ingest_trace};
use netdiag_core::models::{
    IngestResult, IngestWarning, MetricProvenance, MetricQuality, TraceRecord,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration as StdDuration, Instant};

#[derive(Debug, Clone)]
pub enum SourceMode {
    Simulated(SimScenario),
    File(PathBuf),
    Api(ApiConfig),
    LocalProbe(LocalProbeSettings),
    WebsiteProbe(WebsiteProbeSettings),
    PrometheusQueryRange(PrometheusQuerySettings, Option<String>),
    PrometheusExposition(PrometheusExpositionSettings, Option<String>),
    OtlpGrpcReceiver(OtlpGrpcSettings),
    NativePcap(NativePcapSettings),
    SystemCounters(SystemCountersSettings),
}

impl SourceMode {
    pub fn load(&self) -> Result<SourceSnapshot> {
        match self {
            SourceMode::Simulated(scenario) => SimulatedTraceSource {
                scenario: *scenario,
            }
            .load(),
            SourceMode::File(path) => FileTraceSource { path: path.clone() }.load(),
            SourceMode::Api(config) => ApiTraceSource {
                config: config.clone(),
            }
            .load(),
            SourceMode::LocalProbe(settings) => LocalProbeTraceSource {
                settings: settings.clone(),
            }
            .load(),
            SourceMode::WebsiteProbe(settings) => WebsiteProbeTraceSource {
                settings: settings.clone(),
            }
            .load(),
            SourceMode::PrometheusQueryRange(settings, token) => PrometheusQueryRangeTraceSource {
                settings: settings.clone(),
                bearer_token: token.clone(),
            }
            .load(),
            SourceMode::PrometheusExposition(settings, token) => PrometheusExpositionTraceSource {
                settings: settings.clone(),
                bearer_token: token.clone(),
            }
            .load(),
            SourceMode::OtlpGrpcReceiver(settings) => OtlpGrpcReceiverTraceSource {
                settings: settings.clone(),
            }
            .load(),
            SourceMode::NativePcap(settings) => NativePcapTraceSource {
                settings: settings.clone(),
            }
            .load(),
            SourceMode::SystemCounters(settings) => SystemCountersTraceSource {
                settings: settings.clone(),
            }
            .load(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimScenario {
    Normal,
    #[default]
    Congestion,
    RandomLoss,
    DnsFailure,
    TlsFailure,
    UdpQuicBlocked,
}

impl SimScenario {
    pub const ALL: [SimScenario; 6] = [
        SimScenario::Normal,
        SimScenario::Congestion,
        SimScenario::RandomLoss,
        SimScenario::DnsFailure,
        SimScenario::TlsFailure,
        SimScenario::UdpQuicBlocked,
    ];

    pub fn sample_name(self) -> &'static str {
        match self {
            SimScenario::Normal => "sim_normal",
            SimScenario::Congestion => "sim_congestion",
            SimScenario::RandomLoss => "sim_random_loss",
            SimScenario::DnsFailure => "sim_dns_failure",
            SimScenario::TlsFailure => "sim_tls_failure",
            SimScenario::UdpQuicBlocked => "sim_quic_blocked",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            SimScenario::Normal => "Simulation: normal",
            SimScenario::Congestion => "Simulation: congestion",
            SimScenario::RandomLoss => "Simulation: random loss",
            SimScenario::DnsFailure => "Simulation: DNS failure",
            SimScenario::TlsFailure => "Simulation: TLS failure",
            SimScenario::UdpQuicBlocked => "Simulation: QUIC blocked",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SourceSnapshot {
    pub ingest: IngestResult,
    pub descriptor: SourceDescriptor,
    pub flow_summary: FlowSummary,
}

#[derive(Debug, Clone)]
pub struct SourceDescriptor {
    pub name: String,
    pub kind: String,
    pub captured_label: String,
    pub data_source_label: String,
}

#[derive(Debug, Clone, Default)]
pub struct FlowSummary {
    pub protocol: Option<String>,
    pub flows: Option<usize>,
    pub total_bytes: Option<u64>,
    pub top_talkers: Vec<TopTalker>,
}

#[derive(Debug, Clone)]
pub struct TopTalker {
    pub label: String,
    pub bytes: u64,
}

pub trait TraceSource {
    fn load(&self) -> Result<SourceSnapshot>;
}

struct FileTraceSource {
    path: PathBuf,
}

impl TraceSource for FileTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let ingest = ingest_trace(&self.path)?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("trace")
            .to_string();
        let total_bytes = estimate_bytes_from_records(&ingest.records);
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name,
                kind: "Trace File".to_string(),
                captured_label: format!(
                    "Captured  •  {}",
                    ingest.schema.start_time.format("%H:%M")
                ),
                data_source_label: "Imported trace".to_string(),
            },
            flow_summary: FlowSummary {
                total_bytes,
                ..FlowSummary::default()
            },
            ingest,
        })
    }
}

struct SimulatedTraceSource {
    scenario: SimScenario,
}

impl TraceSource for SimulatedTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let records = simulate_records(self.scenario);
        let ingest = build_ingest_result(records, self.scenario.sample_name())?;
        let total_bytes = estimate_bytes_from_records(&ingest.records).unwrap_or(0);
        let flow_summary = simulated_flow_summary(total_bytes);
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: self.scenario.sample_name().replace('_', "."),
                kind: "Simulation".to_string(),
                captured_label: format!(
                    "Simulated  •  {}",
                    ingest.schema.start_time.format("%H:%M")
                ),
                data_source_label: self.scenario.display_name().to_string(),
            },
            flow_summary,
            ingest,
        })
    }
}

struct ApiTraceSource {
    config: ApiConfig,
}

impl TraceSource for ApiTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let loaded = load_http_json(&HttpJsonConfig {
            endpoint: self.config.endpoint.clone(),
            bearer_token: self.config.bearer_token().map(str::to_owned),
            timeout: self.config.timeout,
        })?;
        let sample = loaded.sample.clone();
        let ingest = loaded.ingest;
        let value: Value = loaded.payload.unwrap_or(Value::Null);
        let protocol = value
            .get("protocol")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let mut flow_summary = parse_api_flow_summary(&value, protocol);
        if flow_summary.total_bytes.is_none() {
            flow_summary.total_bytes = estimate_bytes_from_records(&ingest.records);
        }
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: sample,
                kind: "Live API".to_string(),
                captured_label: format!("Fetched  •  {}", Utc::now().format("%H:%M")),
                data_source_label: "Live API".to_string(),
            },
            flow_summary,
            ingest,
        })
    }
}

struct PrometheusQueryRangeTraceSource {
    settings: PrometheusQuerySettings,
    bearer_token: Option<String>,
}

impl TraceSource for PrometheusQueryRangeTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let loaded = load_prometheus_query_range(&PrometheusQueryRangeConfig {
            base_url: self.settings.base_url.clone(),
            bearer_token: self.bearer_token.clone(),
            timeout: std::time::Duration::from_secs(8),
            lookback_seconds: self.settings.lookback_seconds,
            step_seconds: self.settings.step_seconds,
            queries: self.settings.mapping.clone(),
            sample: "prometheus_query_range".to_string(),
        })?;
        let total_bytes = estimate_bytes_from_records(&loaded.ingest.records);
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: loaded.sample,
                kind: "Prometheus Query".to_string(),
                captured_label: format!("Queried  •  {}", Utc::now().format("%H:%M")),
                data_source_label: self.settings.base_url.clone(),
            },
            flow_summary: FlowSummary {
                protocol: Some("PromQL".to_string()),
                flows: Some(loaded.ingest.records.len()),
                total_bytes,
                top_talkers: Vec::new(),
            },
            ingest: loaded.ingest,
        })
    }
}

struct PrometheusExpositionTraceSource {
    settings: PrometheusExpositionSettings,
    bearer_token: Option<String>,
}

impl TraceSource for PrometheusExpositionTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let loaded = load_prometheus_exposition(&PrometheusExpositionConfig {
            endpoint: self.settings.endpoint.clone(),
            bearer_token: self.bearer_token.clone(),
            timeout: std::time::Duration::from_secs(8),
            metrics: self.settings.mapping.clone(),
            sample: "prometheus_exposition".to_string(),
        })?;
        let total_bytes = estimate_bytes_from_records(&loaded.ingest.records);
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: loaded.sample,
                kind: "Prometheus Metrics".to_string(),
                captured_label: format!("Scraped  •  {}", Utc::now().format("%H:%M")),
                data_source_label: self.settings.endpoint.clone(),
            },
            flow_summary: FlowSummary {
                protocol: Some("Prometheus".to_string()),
                flows: Some(loaded.ingest.records.len()),
                total_bytes,
                top_talkers: Vec::new(),
            },
            ingest: loaded.ingest,
        })
    }
}

struct OtlpGrpcReceiverTraceSource {
    settings: OtlpGrpcSettings,
}

impl TraceSource for OtlpGrpcReceiverTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let loaded = load_otlp_grpc_receiver(&OtlpGrpcReceiverConfig {
            bind_addr: self.settings.bind_addr.clone(),
            timeout: std::time::Duration::from_secs(self.settings.timeout_secs.max(1)),
            metrics: self.settings.mapping.clone(),
            sample: "otlp_grpc".to_string(),
        })?;
        let total_bytes = estimate_bytes_from_records(&loaded.ingest.records);
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: loaded.sample,
                kind: "OTLP gRPC".to_string(),
                captured_label: format!("Received  •  {}", Utc::now().format("%H:%M")),
                data_source_label: self.settings.bind_addr.clone(),
            },
            flow_summary: FlowSummary {
                protocol: Some("OTLP".to_string()),
                flows: Some(loaded.ingest.records.len()),
                total_bytes,
                top_talkers: Vec::new(),
            },
            ingest: loaded.ingest,
        })
    }
}

struct NativePcapTraceSource {
    settings: NativePcapSettings,
}

impl TraceSource for NativePcapTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let source = native_pcap_source(&self.settings.source);
        let loaded = load_native_pcap(&NativePcapConfig {
            source,
            timeout: std::time::Duration::from_secs(self.settings.timeout_secs.max(1)),
            packet_limit: self.settings.packet_limit.max(1),
            sample: "native_pcap".to_string(),
        })?;
        let payload = loaded.payload.unwrap_or(Value::Null);
        let mut flow_summary = parse_api_flow_summary(&payload, Some("PCAP".to_string()));
        if flow_summary.total_bytes.is_none() {
            flow_summary.total_bytes = estimate_bytes_from_records(&loaded.ingest.records);
        }
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: loaded.sample,
                kind: "Native pcap".to_string(),
                captured_label: format!("Captured  •  {}", Utc::now().format("%H:%M")),
                data_source_label: self.settings.source.clone(),
            },
            flow_summary,
            ingest: loaded.ingest,
        })
    }
}

struct SystemCountersTraceSource {
    settings: SystemCountersSettings,
}

impl TraceSource for SystemCountersTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let interface = self.settings.interface.trim().to_string();
        let loaded = load_system_counters(&SystemCountersConfig {
            interface: (!interface.is_empty() && interface != "all").then_some(interface.clone()),
            interval: std::time::Duration::from_secs(self.settings.interval_secs.clamp(1, 10)),
            sample: "system_counters".to_string(),
        })?;
        let total_bytes = loaded
            .payload
            .as_ref()
            .and_then(|value| value.get("bytes"))
            .and_then(Value::as_u64)
            .or_else(|| estimate_bytes_from_records(&loaded.ingest.records));
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: loaded.sample,
                kind: "System counters".to_string(),
                captured_label: format!("Sampled  •  {}", Utc::now().format("%H:%M")),
                data_source_label: if interface.is_empty() {
                    "all interfaces".to_string()
                } else {
                    interface
                },
            },
            flow_summary: FlowSummary {
                protocol: Some("Interface".to_string()),
                flows: Some(loaded.ingest.records.len()),
                total_bytes,
                top_talkers: Vec::new(),
            },
            ingest: loaded.ingest,
        })
    }
}

struct LocalProbeTraceSource {
    settings: LocalProbeSettings,
}

impl TraceSource for LocalProbeTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let samples = self.settings.samples.clamp(1, 20);
        let mut warnings = probe_fallback_warnings("local probe");
        warnings.push(IngestWarning {
            row: None,
            column: "tcp_probe".to_string(),
            reason: "loopback TCP port may be closed; connection refused is treated as local stack reachability".to_string(),
            fallback: "127.0.0.1:9".to_string(),
        });
        let mut records = Vec::with_capacity(samples);
        let start = Utc::now() - Duration::seconds(samples as i64);
        for idx in 0..samples {
            let dns = measure_dns("localhost:80");
            let tcp = measure_tcp("127.0.0.1:9", StdDuration::from_millis(600), true);
            let latency_ms = dns.latency_ms.max(tcp.latency_ms).max(0.1);
            records.push(TraceRecord {
                timestamp: start + Duration::seconds(idx as i64),
                latency_ms,
                jitter_ms: (dns.latency_ms - tcp.latency_ms).abs(),
                packet_loss_rate: if dns.success || tcp.success {
                    0.0
                } else {
                    100.0
                },
                retransmission_rate: 0.0,
                timeout_events: metric_bool(dns.timeout || tcp.timeout),
                retry_events: 0.0,
                throughput_mbps: 0.0,
                dns_failure_events: metric_bool(!dns.success),
                tls_failure_events: 0.0,
                quic_blocked_ratio: 0.0,
            });
        }
        let mut ingest = build_ingest_result(records, "local_probe")?;
        ingest.warnings.extend(warnings);
        apply_probe_metric_quality(&mut ingest, "local_probe");
        let total_bytes = estimate_bytes_from_records(&ingest.records);
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: "local.probe".to_string(),
                kind: "Local Probe".to_string(),
                captured_label: format!("Probed  •  {}", Utc::now().format("%H:%M")),
                data_source_label: "Local host network stack".to_string(),
            },
            flow_summary: FlowSummary {
                protocol: Some("TCP".to_string()),
                flows: Some(1),
                total_bytes,
                top_talkers: Vec::new(),
            },
            ingest,
        })
    }
}

struct WebsiteProbeTraceSource {
    settings: WebsiteProbeSettings,
}

impl TraceSource for WebsiteProbeTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let targets = self
            .settings
            .targets
            .iter()
            .map(|target| target.trim())
            .filter(|target| !target.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if targets.is_empty() {
            bail!("website probe has no targets");
        }
        let samples = self.settings.samples_per_target.clamp(1, 12);
        let total_samples = targets.len() * samples;
        let start = Utc::now() - Duration::seconds(total_samples as i64);
        let mut records = Vec::with_capacity(total_samples);
        let mut row = 0usize;
        for sample_idx in 0..samples {
            for target in &targets {
                let measurement = measure_target(target, StdDuration::from_secs(4));
                records.push(TraceRecord {
                    timestamp: start + Duration::seconds(row as i64),
                    latency_ms: measurement.latency_ms.max(0.1),
                    jitter_ms: measurement.jitter_ms,
                    packet_loss_rate: if measurement.success { 0.0 } else { 100.0 },
                    retransmission_rate: 0.0,
                    timeout_events: metric_bool(measurement.timeout),
                    retry_events: if measurement.success { 0.0 } else { 1.0 },
                    throughput_mbps: 0.0,
                    dns_failure_events: metric_bool(measurement.dns_failure),
                    tls_failure_events: metric_bool(measurement.tls_failure),
                    quic_blocked_ratio: 0.0,
                });
                row += 1;
            }
            if sample_idx + 1 < samples {
                std::thread::sleep(StdDuration::from_millis(20));
            }
        }
        let mut ingest = build_ingest_result(records, "website_probe")?;
        ingest
            .warnings
            .extend(probe_fallback_warnings("website probe"));
        apply_probe_metric_quality(&mut ingest, "website_probe");
        let total_bytes = estimate_bytes_from_records(&ingest.records);
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: "website.probe".to_string(),
                kind: "Website Probe".to_string(),
                captured_label: format!("Probed  •  {}", Utc::now().format("%H:%M")),
                data_source_label: targets.join(", "),
            },
            flow_summary: FlowSummary {
                protocol: Some("HTTP/TCP".to_string()),
                flows: Some(targets.len()),
                total_bytes,
                top_talkers: Vec::new(),
            },
            ingest,
        })
    }
}

fn apply_probe_metric_quality(ingest: &mut IngestResult, source: &str) {
    for (field, quality, reason) in [
        (
            "latency_ms",
            MetricQuality::Estimated,
            "derived from DNS/TCP/HTTP probe timing",
        ),
        (
            "jitter_ms",
            MetricQuality::Estimated,
            "derived from repeated probe timing variation",
        ),
        (
            "packet_loss_rate",
            MetricQuality::Estimated,
            "mapped from probe success/failure ratio",
        ),
        (
            "throughput_mbps",
            MetricQuality::Fallback,
            "active probe does not measure sustained throughput",
        ),
        (
            "retransmission_rate",
            MetricQuality::Fallback,
            "active probe does not observe TCP retransmissions",
        ),
        (
            "quic_blocked_ratio",
            MetricQuality::Fallback,
            "active probe does not prove QUIC policy blocking",
        ),
    ] {
        set_metric_quality(ingest, field, quality, source, reason);
    }
}

fn set_metric_quality(
    ingest: &mut IngestResult,
    field: &str,
    quality: MetricQuality,
    source: &str,
    reason: &str,
) {
    if let Some(item) = ingest
        .metric_provenance
        .iter_mut()
        .find(|item| item.field == field)
    {
        item.quality = quality;
        item.source = source.to_string();
        item.reason = reason.to_string();
        return;
    }
    ingest.metric_provenance.push(MetricProvenance {
        field: field.to_string(),
        quality,
        source: source.to_string(),
        reason: reason.to_string(),
    });
}

fn simulate_records(scenario: SimScenario) -> Vec<TraceRecord> {
    let start = Utc
        .with_ymd_and_hms(2026, 4, 29, 9, 35, 0)
        .single()
        .expect("static timestamp is valid");
    (0..80)
        .map(|idx| {
            let t = idx as f64;
            let wave = (t / 4.0).sin();
            let spike = if idx % 17 == 0 { 1.0 } else { 0.0 };
            let mut record = TraceRecord {
                timestamp: start + Duration::seconds(idx),
                latency_ms: 42.0 + wave * 3.0,
                jitter_ms: 2.4 + wave.abs(),
                packet_loss_rate: 0.05 + spike * 0.06,
                retransmission_rate: 0.08 + spike * 0.08,
                timeout_events: 0.0,
                retry_events: 0.0,
                throughput_mbps: 42.0 + (t / 5.0).cos() * 2.5,
                dns_failure_events: 0.0,
                tls_failure_events: 0.0,
                quic_blocked_ratio: 0.0,
            };
            match scenario {
                SimScenario::Normal => {}
                SimScenario::Congestion => {
                    let congested = idx >= 24;
                    record.latency_ms = if congested {
                        165.0 + (t / 2.0).sin().abs() * 70.0 + spike * 48.0
                    } else {
                        48.0 + wave * 4.0
                    };
                    record.jitter_ms = if congested {
                        18.0 + wave.abs() * 14.0
                    } else {
                        4.0
                    };
                    record.packet_loss_rate = if congested { 1.2 + spike * 2.8 } else { 0.18 };
                    record.retransmission_rate = if congested { 2.0 + spike * 3.2 } else { 0.3 };
                    record.throughput_mbps = if congested {
                        16.0 + (t / 3.0).cos() * 3.0
                    } else {
                        44.0
                    };
                }
                SimScenario::RandomLoss => {
                    record.packet_loss_rate = 2.2 + spike * 5.0 + (t / 6.0).sin().abs();
                    record.retransmission_rate = 0.5 + spike * 1.4;
                    record.retry_events = if spike > 0.0 { 3.0 } else { 0.0 };
                }
                SimScenario::DnsFailure => {
                    record.dns_failure_events = if idx % 9 == 0 { 4.0 } else { 0.0 };
                    record.timeout_events = if idx % 13 == 0 { 2.0 } else { 0.0 };
                    record.latency_ms = 55.0 + wave.abs() * 16.0;
                }
                SimScenario::TlsFailure => {
                    record.tls_failure_events = if idx % 7 == 0 { 3.0 } else { 0.0 };
                    record.retry_events = if idx % 11 == 0 { 2.0 } else { 0.0 };
                    record.latency_ms = 60.0 + wave.abs() * 22.0;
                }
                SimScenario::UdpQuicBlocked => {
                    record.quic_blocked_ratio = if idx > 18 { 0.95 } else { 0.25 };
                    record.retry_events = if idx % 10 == 0 { 2.0 } else { 0.0 };
                    record.latency_ms = 58.0 + wave.abs() * 12.0;
                }
            }
            record
        })
        .collect()
}

#[derive(Debug)]
struct ProbeMeasurement {
    success: bool,
    latency_ms: f64,
    jitter_ms: f64,
    timeout: bool,
    dns_failure: bool,
    tls_failure: bool,
}

fn measure_target(target: &str, timeout: StdDuration) -> ProbeMeasurement {
    if target.starts_with("http://") || target.starts_with("https://") {
        return measure_http(target, timeout);
    }
    measure_tcp(target, timeout, false)
}

fn measure_http(url: &str, timeout: StdDuration) -> ProbeMeasurement {
    let client = match reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
    {
        Ok(client) => client,
        Err(_) => return failed_probe(0.0, false, false, false),
    };
    let started = Instant::now();
    match client.get(url).send() {
        Ok(response) => {
            let latency_ms = elapsed_ms(started);
            ProbeMeasurement {
                success: response.status().is_success(),
                latency_ms,
                jitter_ms: 0.0,
                timeout: false,
                dns_failure: false,
                tls_failure: false,
            }
        }
        Err(err) => {
            let text = err.to_string().to_ascii_lowercase();
            failed_probe(
                elapsed_ms(started).max(timeout.as_millis() as f64),
                err.is_timeout(),
                text.contains("dns") || text.contains("resolve"),
                text.contains("tls") || text.contains("certificate"),
            )
        }
    }
}

fn measure_dns(target: &str) -> ProbeMeasurement {
    let started = Instant::now();
    match target.to_socket_addrs() {
        Ok(addrs) => {
            if addrs.into_iter().next().is_some() {
                ProbeMeasurement {
                    success: true,
                    latency_ms: elapsed_ms(started).max(0.1),
                    jitter_ms: 0.0,
                    timeout: false,
                    dns_failure: false,
                    tls_failure: false,
                }
            } else {
                failed_probe(elapsed_ms(started).max(1.0), false, true, false)
            }
        }
        Err(_) => failed_probe(elapsed_ms(started).max(1.0), false, true, false),
    }
}

fn measure_tcp(target: &str, timeout: StdDuration, refused_is_reachable: bool) -> ProbeMeasurement {
    let started = Instant::now();
    let Ok(mut addrs) = target.to_socket_addrs() else {
        return failed_probe(elapsed_ms(started).max(1.0), false, true, false);
    };
    let Some(addr) = addrs.next() else {
        return failed_probe(elapsed_ms(started).max(1.0), false, true, false);
    };
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => ProbeMeasurement {
            success: true,
            latency_ms: elapsed_ms(started).max(0.1),
            jitter_ms: 0.0,
            timeout: false,
            dns_failure: false,
            tls_failure: false,
        },
        Err(err) if refused_is_reachable && err.kind() == std::io::ErrorKind::ConnectionRefused => {
            ProbeMeasurement {
                success: true,
                latency_ms: elapsed_ms(started).max(0.1),
                jitter_ms: 0.0,
                timeout: false,
                dns_failure: false,
                tls_failure: false,
            }
        }
        Err(err) => failed_probe(
            elapsed_ms(started).max(timeout.as_millis() as f64),
            err.kind() == std::io::ErrorKind::TimedOut,
            false,
            false,
        ),
    }
}

fn failed_probe(
    latency_ms: f64,
    timeout: bool,
    dns_failure: bool,
    tls_failure: bool,
) -> ProbeMeasurement {
    ProbeMeasurement {
        success: false,
        latency_ms: latency_ms.max(1.0),
        jitter_ms: 0.0,
        timeout,
        dns_failure,
        tls_failure,
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn metric_bool(value: bool) -> f64 {
    if value { 1.0 } else { 0.0 }
}

fn probe_fallback_warnings(source: &str) -> Vec<IngestWarning> {
    [
        (
            "throughput_mbps",
            "active probe does not measure payload throughput",
        ),
        (
            "retransmission_rate",
            "active probe does not read TCP retransmission counters",
        ),
        (
            "quic_blocked_ratio",
            "active probe does not perform UDP/QUIC policy probing",
        ),
    ]
    .into_iter()
    .map(|(column, reason)| IngestWarning {
        row: None,
        column: column.to_string(),
        reason: format!("{source}: {reason}"),
        fallback: "0.0".to_string(),
    })
    .collect()
}

pub fn native_pcap_source(raw: &str) -> NativePcapSource {
    let trimmed = raw.trim();
    if let Some(interface) = trimmed.strip_prefix("iface:") {
        return NativePcapSource::Interface(interface.trim().to_string());
    }
    let path = PathBuf::from(trimmed);
    if path.is_file() {
        NativePcapSource::File(path)
    } else {
        NativePcapSource::Interface(if trimmed.is_empty() {
            "lo0".to_string()
        } else {
            trimmed.to_string()
        })
    }
}

fn simulated_flow_summary(total_bytes: u64) -> FlowSummary {
    let shares = [
        ("10.0.0.2 ↔ 10.0.0.3", 0.50),
        ("10.0.0.2 ↔ 10.0.0.4", 0.31),
        ("10.0.0.5 ↔ 10.0.0.3", 0.12),
        ("Others", 0.07),
    ];
    FlowSummary {
        protocol: Some("TCP".to_string()),
        flows: Some(4),
        total_bytes: Some(total_bytes),
        top_talkers: shares
            .into_iter()
            .map(|(label, share)| TopTalker {
                label: label.to_string(),
                bytes: (total_bytes as f64 * share).round() as u64,
            })
            .collect(),
    }
}

#[derive(Debug, Deserialize)]
struct ApiFlow {
    src: Option<String>,
    dst: Option<String>,
    label: Option<String>,
    bytes: Option<u64>,
    protocol: Option<String>,
}

fn parse_api_flow_summary(value: &Value, protocol: Option<String>) -> FlowSummary {
    let flows_value = value
        .get("flows")
        .or_else(|| value.get("top_talkers"))
        .cloned();
    let flows: Vec<ApiFlow> = flows_value
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_default();
    let top_talkers: Vec<TopTalker> = flows
        .iter()
        .filter_map(|flow| {
            let bytes = flow.bytes?;
            let label = flow.label.clone().or_else(|| {
                Some(format!(
                    "{} ↔ {}",
                    flow.src.as_deref().unwrap_or("unknown"),
                    flow.dst.as_deref().unwrap_or("unknown")
                ))
            })?;
            Some(TopTalker { label, bytes })
        })
        .collect();
    let protocol = protocol.or_else(|| flows.iter().find_map(|flow| flow.protocol.clone()));
    let total_bytes = top_talkers.iter().map(|talker| talker.bytes).sum::<u64>();
    FlowSummary {
        protocol,
        flows: if flows.is_empty() {
            value
                .get("flow_count")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
        } else {
            Some(flows.len())
        },
        total_bytes: (total_bytes > 0).then_some(total_bytes),
        top_talkers,
    }
}

fn estimate_bytes_from_records(records: &[TraceRecord]) -> Option<u64> {
    if records.len() < 2 {
        return None;
    }
    let mut bytes = 0.0;
    for pair in records.windows(2) {
        let seconds = (pair[1].timestamp - pair[0].timestamp)
            .num_milliseconds()
            .max(0) as f64
            / 1000.0;
        bytes += pair[0].throughput_mbps.max(0.0) * 1_000_000.0 * seconds / 8.0;
    }
    bytes.is_finite().then_some(bytes.round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{MemorySecretStore, SecretStore};
    use crate::settings::{ApiSettings, AppSettings};
    use chrono::TimeZone;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn http_json_connector_accepts_bare_records_and_bearer_token() {
        let records = vec![record(0, 42.0)];
        let body = serde_json::to_string(&records).expect("records json");
        let (url, handle) = serve_once(200, body, Some("authorization: Bearer secret-token"));
        let secrets = MemorySecretStore::with_token("secret-token");
        let config = api_config(url, &secrets);

        let snapshot = SourceMode::Api(config).load().expect("api source");
        handle.join().expect("server thread");

        assert_eq!(snapshot.ingest.records.len(), 1);
        assert_eq!(snapshot.ingest.records[0].latency_ms, 42.0);
        assert_eq!(snapshot.descriptor.kind, "Live API");
    }

    #[test]
    fn http_json_connector_accepts_metadata_and_flows() {
        let body = serde_json::json!({
            "sample": "lab-router-1",
            "protocol": "TCP",
            "flows": [
                { "src": "10.0.0.2", "dst": "10.0.0.3", "bytes": 2048, "protocol": "TCP" }
            ],
            "records": [record(0, 55.0)]
        })
        .to_string();
        let (url, handle) = serve_once(200, body, None);
        let secrets = MemorySecretStore::new();

        let snapshot = SourceMode::Api(api_config(url, &secrets))
            .load()
            .expect("metadata source");
        handle.join().expect("server thread");

        assert_eq!(snapshot.descriptor.name, "lab-router-1");
        assert_eq!(snapshot.flow_summary.flows, Some(1));
        assert_eq!(snapshot.flow_summary.total_bytes, Some(2048));
        assert_eq!(
            snapshot.flow_summary.top_talkers[0].label,
            "10.0.0.2 ↔ 10.0.0.3"
        );
    }

    #[test]
    fn http_json_connector_rejects_error_status_and_invalid_json() {
        let (error_url, error_handle) = serve_once(500, "boom".to_string(), None);
        let secrets = MemorySecretStore::new();
        let err = SourceMode::Api(api_config(error_url, &secrets))
            .load()
            .expect_err("500 should fail");
        error_handle.join().expect("server thread");
        assert!(err.to_string().contains("error status"));

        let (json_url, json_handle) = serve_once(200, "not-json".to_string(), None);
        let err = SourceMode::Api(api_config(json_url, &secrets))
            .load()
            .expect_err("invalid json should fail");
        json_handle.join().expect("server thread");
        assert!(err.to_string().contains("valid JSON"));
    }

    #[test]
    fn http_json_connector_rejects_empty_records() {
        let (url, handle) = serve_once(200, r#"{"records":[]}"#.to_string(), None);
        let secrets = MemorySecretStore::new();
        let err = SourceMode::Api(api_config(url, &secrets))
            .load()
            .expect_err("empty records should fail");
        handle.join().expect("server thread");
        assert!(err.to_string().contains("trace has no rows"));
    }

    #[test]
    fn probe_sources_emit_fallback_warnings_without_inventing_throughput() {
        let snapshot = SourceMode::LocalProbe(LocalProbeSettings { samples: 2 })
            .load()
            .expect("local probe");

        assert_eq!(snapshot.ingest.records.len(), 2);
        assert!(
            snapshot
                .ingest
                .warnings
                .iter()
                .any(|warning| warning.column == "throughput_mbps")
        );
        assert!(
            snapshot
                .ingest
                .records
                .iter()
                .all(|record| record.throughput_mbps == 0.0)
        );
    }

    #[test]
    #[ignore = "touches public network targets; run manually for release smoke"]
    fn website_probe_can_collect_default_public_targets() {
        let snapshot = SourceMode::WebsiteProbe(WebsiteProbeSettings::default())
            .load()
            .expect("website probe");

        assert!(!snapshot.ingest.records.is_empty());
        assert!(
            snapshot
                .ingest
                .records
                .iter()
                .any(|record| record.latency_ms > 0.0)
        );
    }

    fn api_config(url: String, secrets: &dyn SecretStore) -> ApiConfig {
        AppSettings {
            api: ApiSettings {
                endpoint: url,
                timeout_secs: 2,
            },
            ..AppSettings::default()
        }
        .api_config_with_env(secrets, std::iter::empty::<(&str, &str)>())
        .expect("api config")
    }

    fn serve_once(
        status: u16,
        body: String,
        expected_header: Option<&'static str>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        let handle = thread::spawn(move || {
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
        });
        (format!("http://{addr}/trace"), handle)
    }

    fn record(offset: i64, latency_ms: f64) -> TraceRecord {
        TraceRecord {
            timestamp: Utc
                .with_ymd_and_hms(2026, 4, 30, 12, 0, 0)
                .single()
                .expect("timestamp")
                + Duration::seconds(offset),
            latency_ms,
            jitter_ms: 1.0,
            packet_loss_rate: 0.0,
            retransmission_rate: 0.0,
            timeout_events: 0.0,
            retry_events: 0.0,
            throughput_mbps: 10.0,
            dns_failure_events: 0.0,
            tls_failure_events: 0.0,
            quic_blocked_ratio: 0.0,
        }
    }
}
