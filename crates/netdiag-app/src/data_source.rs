use crate::settings::{
    ApiConfig, LocalProbeSettings, NativePcapSettings, OtlpGrpcSettings,
    PrometheusExpositionSettings, PrometheusQuerySettings, SystemCountersSettings,
    WebsiteProbeSettings,
};
use crate::{
    connector_auth::resolve_bearer_token,
    secrets::{BearerSecretScope, SecretStore},
};
use anyhow::{Result, bail};
use chrono::{Duration, TimeZone, Utc};
use netdiag_core::authentication::{BearerSourceKind, ValidatedBearerToken};
use netdiag_core::connectors::{
    HttpJsonConfig, LocalProbeConfig, NativePcapConfig, OtlpGrpcReceiverConfig,
    PrometheusExpositionConfig, PrometheusQueryRangeConfig, SystemCountersConfig,
    WebsiteProbeConfig, load_http_json, load_local_probe, load_native_pcap,
    load_otlp_grpc_receiver, load_prometheus_exposition, load_prometheus_query_range,
    load_system_counters, load_website_probe,
};
use netdiag_core::ingest::{build_ingest_result, ingest_trace};
use netdiag_core::models::{ConnectorHealthSnapshot, IngestResult, TraceRecord};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

mod debug;
mod flow_summary;
mod native_pcap;
pub use flow_summary::{FlowSummary, TopTalker, estimate_bytes_from_records};
use flow_summary::{parse_api_flow_summary, simulated_flow_summary};
pub use native_pcap::native_pcap_source;

#[derive(Clone, PartialEq, Eq)]
pub enum SourceMode {
    Unavailable { reason: String },
    Simulated(SimScenario),
    File(PathBuf),
    Api(ApiConfig, Option<BearerSecretScope>),
    LocalProbe(LocalProbeSettings),
    WebsiteProbe(WebsiteProbeSettings),
    PrometheusQueryRange(PrometheusQuerySettings, Option<BearerSecretScope>),
    PrometheusExposition(PrometheusExpositionSettings, Option<BearerSecretScope>),
    OtlpGrpcReceiver(OtlpGrpcSettings),
    NativePcap(NativePcapSettings),
    SystemCounters(SystemCountersSettings),
}

impl SourceMode {
    pub fn load(&self, secrets: &dyn SecretStore) -> Result<SourceSnapshot> {
        match self {
            SourceMode::Unavailable { reason } => bail!("{reason}"),
            SourceMode::Simulated(scenario) => SimulatedTraceSource {
                scenario: *scenario,
            }
            .load(),
            SourceMode::File(path) => FileTraceSource { path: path.clone() }.load(),
            SourceMode::Api(config, scope) => ApiTraceSource {
                config: config.clone(),
                bearer_token: resolve_bearer_token(
                    secrets,
                    scope.as_ref(),
                    BearerSourceKind::HttpJson,
                    &config.endpoint,
                )?,
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
            SourceMode::PrometheusQueryRange(settings, scope) => PrometheusQueryRangeTraceSource {
                settings: settings.clone(),
                bearer_token: resolve_bearer_token(
                    secrets,
                    scope.as_ref(),
                    BearerSourceKind::PrometheusQuery,
                    &settings.base_url,
                )?,
            }
            .load(),
            SourceMode::PrometheusExposition(settings, scope) => PrometheusExpositionTraceSource {
                settings: settings.clone(),
                bearer_token: resolve_bearer_token(
                    secrets,
                    scope.as_ref(),
                    BearerSourceKind::PrometheusMetrics,
                    &settings.endpoint,
                )?,
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

impl SourceSnapshot {
    pub fn connector_health(&self) -> ConnectorHealthSnapshot {
        ConnectorHealthSnapshot::from_ingest(
            &self.descriptor.kind,
            &self.descriptor.name,
            &self.descriptor.captured_label,
            &self.ingest,
        )
    }
}

#[derive(Debug, Clone)]
pub struct SourceDescriptor {
    pub name: String,
    pub kind: String,
    pub captured_label: String,
    pub data_source_label: String,
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
        let total_bytes = estimate_bytes_from_records(&ingest.records)?;
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
        let total_bytes = estimate_bytes_from_records(&ingest.records)?.ok_or_else(|| {
            anyhow::anyhow!("simulation requires at least two records to estimate byte traffic")
        })?;
        let flow_summary = simulated_flow_summary(total_bytes)?;
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
    bearer_token: Option<ValidatedBearerToken>,
}

impl TraceSource for ApiTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let loaded = load_http_json(
            &HttpJsonConfig {
                endpoint: self.config.endpoint.clone(),
                timeout: self.config.timeout,
            },
            self.bearer_token.as_ref(),
        )?;
        let sample = loaded.sample.clone();
        let ingest = loaded.ingest;
        let value: Value = loaded.payload.unwrap_or(Value::Null);
        let protocol = value
            .get("protocol")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let mut flow_summary = parse_api_flow_summary(&value, protocol)?;
        if flow_summary.total_bytes.is_none() {
            flow_summary.total_bytes = estimate_bytes_from_records(&ingest.records)?;
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
    bearer_token: Option<ValidatedBearerToken>,
}

impl TraceSource for PrometheusQueryRangeTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        self.settings.validate()?;
        let loaded = load_prometheus_query_range(
            &PrometheusQueryRangeConfig {
                base_url: self.settings.base_url.clone(),
                timeout: std::time::Duration::from_secs(8),
                lookback_seconds: self.settings.lookback_seconds,
                step_seconds: self.settings.step_seconds,
                queries: self.settings.mapping.clone(),
                sample: "prometheus_query_range".to_string(),
            },
            self.bearer_token.as_ref(),
        )?;
        let total_bytes = estimate_bytes_from_records(&loaded.ingest.records)?;
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: loaded.sample,
                kind: "Prometheus Query".to_string(),
                captured_label: format!("Queried  •  {}", Utc::now().format("%H:%M")),
                data_source_label: self.settings.base_url.clone(),
            },
            flow_summary: FlowSummary {
                protocol: Some("PromQL".to_string()),
                flows: Some(
                    u64::try_from(loaded.ingest.records.len())
                        .map_err(|_| anyhow::anyhow!("Prometheus record count exceeds u64::MAX"))?,
                ),
                total_bytes,
                top_talkers: Vec::new(),
            },
            ingest: loaded.ingest,
        })
    }
}

struct PrometheusExpositionTraceSource {
    settings: PrometheusExpositionSettings,
    bearer_token: Option<ValidatedBearerToken>,
}

impl TraceSource for PrometheusExpositionTraceSource {
    fn load(&self) -> Result<SourceSnapshot> {
        let loaded = load_prometheus_exposition(
            &PrometheusExpositionConfig {
                endpoint: self.settings.endpoint.clone(),
                timeout: std::time::Duration::from_secs(8),
                metrics: self.settings.mapping.clone(),
                sample: "prometheus_exposition".to_string(),
            },
            self.bearer_token.as_ref(),
        )?;
        let total_bytes = estimate_bytes_from_records(&loaded.ingest.records)?;
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: loaded.sample,
                kind: "Prometheus Metrics".to_string(),
                captured_label: format!("Scraped  •  {}", Utc::now().format("%H:%M")),
                data_source_label: self.settings.endpoint.clone(),
            },
            flow_summary: FlowSummary {
                protocol: Some("Prometheus".to_string()),
                flows: Some(
                    u64::try_from(loaded.ingest.records.len())
                        .map_err(|_| anyhow::anyhow!("Prometheus record count exceeds u64::MAX"))?,
                ),
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
        self.settings.validate()?;
        let loaded = load_otlp_grpc_receiver(&OtlpGrpcReceiverConfig {
            bind_addr: self.settings.bind_addr.clone(),
            timeout: std::time::Duration::from_secs(self.settings.timeout_secs),
            metrics: self.settings.mapping.clone(),
            sample: "otlp_grpc".to_string(),
        })?;
        let total_bytes = estimate_bytes_from_records(&loaded.ingest.records)?;
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: loaded.sample,
                kind: "OTLP gRPC".to_string(),
                captured_label: format!("Received  •  {}", Utc::now().format("%H:%M")),
                data_source_label: self.settings.bind_addr.clone(),
            },
            flow_summary: FlowSummary {
                protocol: Some("OTLP".to_string()),
                flows: Some(
                    u64::try_from(loaded.ingest.records.len())
                        .map_err(|_| anyhow::anyhow!("OTLP record count exceeds u64::MAX"))?,
                ),
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
        self.settings.validate()?;
        let source = native_pcap_source(&self.settings.source);
        let loaded = load_native_pcap(&NativePcapConfig {
            source,
            timeout: std::time::Duration::from_secs(self.settings.timeout_secs),
            packet_limit: self.settings.packet_limit,
            sample: "native_pcap".to_string(),
        })?;
        let payload = loaded.payload.unwrap_or(Value::Null);
        let mut flow_summary = parse_api_flow_summary(&payload, Some("PCAP".to_string()))?;
        if flow_summary.total_bytes.is_none() {
            flow_summary.total_bytes = estimate_bytes_from_records(&loaded.ingest.records)?;
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
        self.settings.validate()?;
        let interface = self.settings.interface.trim().to_string();
        let loaded = load_system_counters(&SystemCountersConfig {
            interface: (!interface.is_empty() && interface != "all").then_some(interface.clone()),
            interval: std::time::Duration::from_secs(self.settings.interval_secs),
            sample: "system_counters".to_string(),
        })?;
        let reported_total_bytes = loaded
            .payload
            .as_ref()
            .and_then(|value| value.get("bytes"))
            .and_then(Value::as_u64);
        let total_bytes = match reported_total_bytes {
            Some(total_bytes) => Some(total_bytes),
            None => estimate_bytes_from_records(&loaded.ingest.records)?,
        };
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
                flows: Some(u64::try_from(loaded.ingest.records.len()).map_err(|_| {
                    anyhow::anyhow!("system-counter record count exceeds u64::MAX")
                })?),
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
        let loaded = load_local_probe(&LocalProbeConfig {
            samples: self.settings.samples,
        })?;
        let ingest = loaded.ingest;
        let total_bytes = estimate_bytes_from_records(&ingest.records)?;
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
        let config = WebsiteProbeConfig {
            targets: self.settings.targets.clone(),
            samples_per_target: self.settings.samples_per_target,
        };
        let loaded = load_website_probe(&config)?;
        let ingest = loaded.ingest;
        let total_bytes = estimate_bytes_from_records(&ingest.records)?;
        Ok(SourceSnapshot {
            descriptor: SourceDescriptor {
                name: "website.probe".to_string(),
                kind: "Website Probe".to_string(),
                captured_label: format!("Probed  •  {}", Utc::now().format("%H:%M")),
                data_source_label: self.settings.targets.join(", "),
            },
            flow_summary: FlowSummary {
                protocol: Some("HTTP/TCP".to_string()),
                flows: Some(
                    u64::try_from(self.settings.targets.len())
                        .map_err(|_| anyhow::anyhow!("website target count exceeds u64::MAX"))?,
                ),
                total_bytes,
                top_talkers: Vec::new(),
            },
            ingest,
        })
    }
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

#[cfg(test)]
mod tests;
