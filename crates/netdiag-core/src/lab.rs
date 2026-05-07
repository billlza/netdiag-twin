use crate::connectors::{
    ConnectorLoadResult, HttpJsonConfig, NativePcapConfig, NativePcapSource,
    OtlpGrpcReceiverConfig, PrometheusExpositionConfig, PrometheusQueryRangeConfig,
    SystemCountersConfig, default_prometheus_mapping, load_http_json, load_native_pcap,
    load_otlp_grpc_receiver, load_prometheus_exposition, load_prometheus_query_range,
    load_system_counters,
};
use crate::error::{IoContext, NetdiagError, Result};
use crate::evidence_bundle::{
    EvidenceBundleExtraFile, EvidenceBundleManifest, export_evidence_bundle,
};
use crate::ingest::{CANONICAL_COLUMNS, ingest_trace};
use crate::models::{
    ConnectorHealthSnapshot, ConnectorHealthStatus, CorroborationDecision, CorroborationSignal,
    DiagnosisEvent, EvidenceRecord, EvidenceRef, FaultLabel, HilState, IngestResult, MetricQuality,
    MultiSourceEvidenceSummary, RunComparison, Severity, SourceEvidenceSummary, TimeWindow,
};
use crate::pipeline::{WhatIfRequest, diagnose_ingest_with_whatif_and_model_dir};
use crate::recommendation::recommend_actions;
use crate::report::Report;
use crate::report::{compare_rule_ml, render_report};
use crate::storage::{
    connector_health_from_ingest, read_connector_health, read_json, run_artifacts, run_dir,
    save_json, write_connector_health,
};
use crate::twin::{
    TopologyFormat, import_policy_action, import_topology, policy_action, topology_model,
    validate_policy_action_for_topology, validate_policy_action_shape, validate_topology_model,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabScenario {
    pub schema: String,
    pub id: String,
    pub name: String,
    pub expected_label: FaultLabel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology: Option<String>,
    #[serde(default)]
    pub data_sources: Vec<LabDataSource>,
    #[serde(default)]
    pub collection: LabCollection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what_if: Option<LabWhatIf>,
    #[serde(default)]
    pub acceptance: LabAcceptance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabDataSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default)]
    pub role: LabDataSourceRole,
    pub kind: LabDataSourceKind,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabDataSourceRole {
    Primary,
    #[default]
    Corroborating,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabDataSourceKind {
    #[serde(rename = "trace-file")]
    TraceFile,
    #[serde(rename = "http-json")]
    HttpJson,
    #[serde(rename = "prometheus-query")]
    PrometheusQuery,
    #[serde(rename = "prometheus-metrics")]
    PrometheusMetrics,
    #[serde(rename = "native-pcap")]
    NativePcap,
    #[serde(rename = "otlp-grpc")]
    OtlpGrpc,
    #[serde(rename = "system-counters")]
    SystemCounters,
}

impl LabDataSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LabDataSourceKind::TraceFile => "trace-file",
            LabDataSourceKind::HttpJson => "http-json",
            LabDataSourceKind::PrometheusQuery => "prometheus-query",
            LabDataSourceKind::PrometheusMetrics => "prometheus-metrics",
            LabDataSourceKind::NativePcap => "native-pcap",
            LabDataSourceKind::OtlpGrpc => "otlp-grpc",
            LabDataSourceKind::SystemCounters => "system-counters",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabCollection {
    #[serde(default = "default_lookback_secs")]
    pub lookback_secs: i64,
    #[serde(default = "default_step_secs")]
    pub step_secs: u64,
    #[serde(default = "default_packet_limit")]
    pub packet_limit: usize,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
}

impl Default for LabCollection {
    fn default() -> Self {
        Self {
            lookback_secs: default_lookback_secs(),
            step_secs: default_step_secs(),
            packet_limit: default_packet_limit(),
            timeout_secs: default_timeout_secs(),
            interval_secs: default_interval_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabWhatIf {
    pub topology: String,
    pub policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabAcceptance {
    #[serde(default)]
    pub expected_root_cause: Option<FaultLabel>,
    #[serde(default = "default_min_rule_confidence")]
    pub min_rule_confidence: f64,
    #[serde(default = "default_min_ml_probability")]
    pub min_ml_probability: f64,
    #[serde(default)]
    pub allowed_quality: BTreeMap<String, MetricQuality>,
    #[serde(default = "default_allowed_connector_status")]
    pub allowed_connector_status: Vec<ConnectorHealthStatus>,
    #[serde(default = "default_true")]
    pub require_rule_ml_agreement: bool,
    #[serde(default = "default_true")]
    pub require_what_if_improvement: bool,
    #[serde(default = "default_required_artifacts")]
    pub required_artifacts: Vec<String>,
    #[serde(default)]
    pub allow_synthetic_model: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_model_dataset_hash: Option<String>,
    #[serde(default)]
    pub allow_suspected_corroboration: bool,
}

impl Default for LabAcceptance {
    fn default() -> Self {
        Self {
            expected_root_cause: None,
            min_rule_confidence: default_min_rule_confidence(),
            min_ml_probability: default_min_ml_probability(),
            allowed_quality: BTreeMap::new(),
            allowed_connector_status: default_allowed_connector_status(),
            require_rule_ml_agreement: true,
            require_what_if_improvement: true,
            required_artifacts: default_required_artifacts(),
            allow_synthetic_model: false,
            required_model_dataset_hash: None,
            allow_suspected_corroboration: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRunOptions {
    pub artifacts: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabPreflightOptions {
    pub artifacts: PathBuf,
    #[serde(default)]
    pub mode: LabPreflightMode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabPreflightMode {
    #[default]
    Static,
    Live,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabPreflightReport {
    pub schema: String,
    pub scenario_id: String,
    #[serde(default)]
    pub mode: LabPreflightMode,
    pub passed: bool,
    #[serde(default)]
    pub checks: Vec<LabPreflightCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabPreflightCheck {
    pub name: String,
    pub status: LabPreflightCheckStatus,
    pub required: bool,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabPreflightCheckStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRunResult {
    pub schema: String,
    pub scenario_id: String,
    pub scenario_name: String,
    pub run_id: String,
    pub lab_run_dir: String,
    pub pipeline_run_dir: String,
    pub acceptance: LabAcceptanceReport,
    pub comparison: LabRunComparison,
    pub evidence_bundle: EvidenceBundleManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRunIndex {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    #[serde(default)]
    pub runs: Vec<LabRunIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRunIndexEntry {
    pub run_id: String,
    pub scenario_id: String,
    pub scenario_name: String,
    pub created_at: DateTime<Utc>,
    pub lab_run_dir: String,
    pub pipeline_run_dir: String,
    pub acceptance_path: String,
    pub comparison_path: String,
    pub scenario_path: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabValidationContext {
    #[serde(default)]
    pub connector_health: Vec<ConnectorHealthSnapshot>,
    #[serde(default)]
    pub artifact_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabAcceptanceReport {
    pub schema: String,
    pub scenario_id: String,
    pub run_id: String,
    pub expected_label: FaultLabel,
    #[serde(default)]
    pub actual_rule_labels: Vec<String>,
    pub actual_ml_top: String,
    pub actual_ml_probability: f64,
    #[serde(default)]
    pub synthetic_model: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_dataset_hash: Option<String>,
    pub quality_status: ConnectorHealthStatus,
    pub passed: bool,
    #[serde(default)]
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRunComparison {
    pub schema: String,
    pub scenario_id: String,
    pub run_id: String,
    pub expected_label: FaultLabel,
    #[serde(default)]
    pub actual_rule_labels: Vec<String>,
    pub actual_ml_top: String,
    pub rule_ml_agreement: bool,
    pub quality_status: ConnectorHealthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_run_comparison: Option<RunComparison>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabBatchReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub total_scenarios: usize,
    pub passed: usize,
    pub failed: usize,
    #[serde(default)]
    pub results: Vec<LabBatchScenarioResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabBatchScenarioResult {
    pub scenario_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lab_run_dir: Option<String>,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acceptance: Option<LabAcceptanceReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabSummaryReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub artifact_root: String,
    pub total_runs: usize,
    pub passed: usize,
    pub failed: usize,
    #[serde(default)]
    pub by_label: BTreeMap<String, LabSummaryLabelStats>,
    #[serde(default)]
    pub by_scenario: BTreeMap<String, LabSummaryScenarioStats>,
    #[serde(default)]
    pub quality: BTreeMap<String, usize>,
    #[serde(default)]
    pub failures: Vec<LabSummaryFailure>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabSummaryLabelStats {
    pub runs: usize,
    pub passed: usize,
    pub rule_accuracy: f64,
    pub ml_accuracy: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabSummaryScenarioStats {
    pub scenario_name: String,
    pub runs: usize,
    pub passed: usize,
    pub failed: usize,
    pub rule_accuracy: f64,
    pub ml_accuracy: f64,
    pub quality_degraded_rate: f64,
    pub rule_ml_disagreement_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabSummaryFailure {
    pub run_id: String,
    pub scenario_id: String,
    #[serde(default)]
    pub failures: Vec<String>,
}

#[derive(Debug, Clone)]
struct LoadedLabSource {
    source: LabDataSource,
    loaded: ConnectorLoadResult,
    health: ConnectorHealthSnapshot,
}

#[derive(Debug, Clone)]
struct LabRunResolution {
    artifact_root: PathBuf,
    index_entry: Option<LabRunIndexEntry>,
}

pub fn load_lab_scenario(path: impl AsRef<Path>) -> Result<LabScenario> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path).with_path(path)?;
    let scenario: LabScenario = serde_yaml::from_str(&raw)
        .map_err(|err| NetdiagError::InvalidTrace(format!("invalid lab scenario YAML: {err}")))?;
    validate_lab_scenario(&scenario)?;
    Ok(scenario)
}

pub fn validate_lab_scenario(scenario: &LabScenario) -> Result<()> {
    if scenario.schema.trim() != "netdiag-lab-scenario/v1" {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported lab scenario schema: {}",
            scenario.schema
        )));
    }
    if scenario.id.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "lab scenario id is empty".to_string(),
        ));
    }
    if scenario.name.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab scenario {} name is empty",
            scenario.id
        )));
    }
    if scenario.data_sources.is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab scenario {} has no data_sources",
            scenario.id
        )));
    }
    let primary_count = scenario
        .data_sources
        .iter()
        .filter(|source| source.role == LabDataSourceRole::Primary)
        .count();
    if primary_count > 1 {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab scenario {} has more than one primary data source",
            scenario.id
        )));
    }
    for source in &scenario.data_sources {
        if source.endpoint.trim().is_empty() {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab scenario {} data source {:?} endpoint is empty",
                scenario.id, source.kind
            )));
        }
    }
    Ok(())
}

pub fn preflight_lab_scenario(
    path: impl AsRef<Path>,
    options: LabPreflightOptions,
) -> Result<LabPreflightReport> {
    let scenario_path = path.as_ref();
    let fallback_id = scenario_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("lab-scenario")
        .to_string();
    let mut checks = Vec::new();
    let scenario = match load_lab_scenario(scenario_path) {
        Ok(mut scenario) => {
            if !scenario
                .data_sources
                .iter()
                .any(|source| source.role == LabDataSourceRole::Primary)
                && let Some(first) = scenario.data_sources.first_mut()
            {
                first.role = LabDataSourceRole::Primary;
            }
            checks.push(preflight_pass(
                "scenario schema valid",
                true,
                format!("{} uses netdiag-lab-scenario/v1", scenario.id),
            ));
            scenario
        }
        Err(err) => {
            checks.push(preflight_fail(
                "scenario schema valid",
                true,
                err.to_string(),
            ));
            return Ok(preflight_report(fallback_id, options.mode, checks));
        }
    };

    let scenario_dir = scenario_path.parent().unwrap_or_else(|| Path::new("."));
    checks.push(check_artifact_directory_writable(&options.artifacts));
    checks.extend(check_topology_policy_preflight(&scenario, scenario_dir));
    checks.extend(check_source_mapping_preflight(&scenario, scenario_dir));
    checks.extend(check_source_reachability_preflight(
        &scenario,
        scenario_dir,
        options.mode,
    ));

    Ok(preflight_report(scenario.id, options.mode, checks))
}

fn preflight_report(
    scenario_id: String,
    mode: LabPreflightMode,
    checks: Vec<LabPreflightCheck>,
) -> LabPreflightReport {
    let passed = checks
        .iter()
        .all(|check| !check.required || matches!(check.status, LabPreflightCheckStatus::Passed));
    LabPreflightReport {
        schema: "netdiag-lab-preflight/v1".to_string(),
        scenario_id,
        mode,
        passed,
        checks,
    }
}

fn preflight_pass(
    name: impl Into<String>,
    required: bool,
    message: impl Into<String>,
) -> LabPreflightCheck {
    LabPreflightCheck {
        name: name.into(),
        status: LabPreflightCheckStatus::Passed,
        required,
        message: message.into(),
    }
}

fn preflight_fail(
    name: impl Into<String>,
    required: bool,
    message: impl Into<String>,
) -> LabPreflightCheck {
    LabPreflightCheck {
        name: name.into(),
        status: LabPreflightCheckStatus::Failed,
        required,
        message: message.into(),
    }
}

fn preflight_skip(name: impl Into<String>, message: impl Into<String>) -> LabPreflightCheck {
    LabPreflightCheck {
        name: name.into(),
        status: LabPreflightCheckStatus::Skipped,
        required: false,
        message: message.into(),
    }
}

fn preflight_check(
    name: impl Into<String>,
    required: bool,
    result: Result<String>,
) -> LabPreflightCheck {
    let name = name.into();
    match result {
        Ok(message) => preflight_pass(name, required, message),
        Err(err) => preflight_fail(name, required, err.to_string()),
    }
}

fn check_artifact_directory_writable(artifact_root: &Path) -> LabPreflightCheck {
    preflight_check(
        "artifact directory writable",
        true,
        (|| {
            fs::create_dir_all(artifact_root).with_path(artifact_root)?;
            let probe = artifact_root.join(format!(
                ".netdiag-preflight-{}.tmp",
                &Uuid::new_v4().simple().to_string()[..8]
            ));
            fs::write(&probe, b"ok").with_path(&probe)?;
            fs::remove_file(&probe).with_path(&probe)?;
            Ok(format!("{} is writable", artifact_root.display()))
        })(),
    )
}

fn check_topology_policy_preflight(
    scenario: &LabScenario,
    scenario_dir: &Path,
) -> Vec<LabPreflightCheck> {
    let mut checks = Vec::new();
    let what_if_spec = scenario.what_if.clone().or_else(|| {
        scenario.topology.as_ref().map(|topology| LabWhatIf {
            topology: topology.clone(),
            policy: "reroute_path_b".to_string(),
        })
    });
    let Some(what_if) = what_if_spec else {
        checks.push(preflight_skip(
            "topology valid",
            "scenario has no topology or what_if topology",
        ));
        checks.push(preflight_skip(
            "policy valid",
            "scenario has no what_if policy",
        ));
        return checks;
    };

    let topology_result = load_lab_topology(&what_if, scenario_dir).and_then(|topology| {
        validate_topology_model(&topology)?;
        Ok((what_if.clone(), topology))
    });
    match topology_result {
        Ok((what_if, topology)) => {
            checks.push(preflight_pass(
                "topology valid",
                true,
                format!(
                    "{} nodes, {} links",
                    topology.nodes.len(),
                    topology.links.len()
                ),
            ));
            checks.push(preflight_check(
                "policy valid",
                true,
                load_lab_policy(&what_if, scenario_dir).and_then(|action| {
                    validate_policy_action_shape(&action)?;
                    validate_policy_action_for_topology(&action, &topology)?;
                    Ok(format!("{} {:?}", action.id, action.kind))
                }),
            ));
        }
        Err(err) => {
            checks.push(preflight_fail("topology valid", true, err.to_string()));
            checks.push(preflight_skip(
                "policy valid",
                "skipped because topology validation failed",
            ));
        }
    }
    checks
}

fn check_source_mapping_preflight(
    scenario: &LabScenario,
    scenario_dir: &Path,
) -> Vec<LabPreflightCheck> {
    scenario
        .data_sources
        .iter()
        .flat_map(|source| {
            let name = source_label(source);
            let mapping_check = match source.kind {
                LabDataSourceKind::PrometheusQuery
                | LabDataSourceKind::PrometheusMetrics
                | LabDataSourceKind::OtlpGrpc => preflight_check(
                    format!("{name} mapping valid"),
                    true,
                    lab_mapping(source, scenario_dir).and_then(|mapping| {
                        validate_required_metric_mapping(&mapping)?;
                        Ok(format!("{} mapped metrics", mapping.len()))
                    }),
                ),
                _ => preflight_skip(
                    format!("{name} mapping valid"),
                    format!("{} does not use a metric mapping", source.kind.as_str()),
                ),
            };
            let required_check = match source.kind {
                LabDataSourceKind::PrometheusQuery
                | LabDataSourceKind::PrometheusMetrics
                | LabDataSourceKind::OtlpGrpc => preflight_check(
                    format!("{name} required metrics configured"),
                    true,
                    lab_mapping(source, scenario_dir).and_then(|mapping| {
                        validate_required_metric_mapping(&mapping)?;
                        Ok("latency/loss/retransmission/throughput metrics configured".to_string())
                    }),
                ),
                _ => preflight_skip(
                    format!("{name} required metrics configured"),
                    format!(
                        "{} source uses canonical TraceRecord rows",
                        source.kind.as_str()
                    ),
                ),
            };
            [mapping_check, required_check]
        })
        .collect()
}

fn check_source_reachability_preflight(
    scenario: &LabScenario,
    scenario_dir: &Path,
    mode: LabPreflightMode,
) -> Vec<LabPreflightCheck> {
    scenario
        .data_sources
        .iter()
        .map(|source| {
            let name = if source.role == LabDataSourceRole::Primary {
                "primary source reachable".to_string()
            } else {
                format!("{} reachable", source_label(source))
            };
            let result = match mode {
                LabPreflightMode::Static => check_source_static(source, scenario_dir),
                LabPreflightMode::Live => check_source_reachable(source, scenario, scenario_dir),
            };
            preflight_check(name, true, result)
        })
        .collect()
}

fn check_source_static(source: &LabDataSource, scenario_dir: &Path) -> Result<String> {
    match source.kind {
        LabDataSourceKind::TraceFile => {
            let path = resolve_path(scenario_dir, &source.endpoint);
            if !path.is_file() {
                Err(NetdiagError::InvalidTrace(format!(
                    "trace file does not exist: {}",
                    path.display()
                )))
            } else {
                let ingest = ingest_trace(&path)?;
                Ok(format!(
                    "trace file schema valid: {} rows from {}",
                    ingest.schema.rows,
                    path.display()
                ))
            }
        }
        LabDataSourceKind::HttpJson
        | LabDataSourceKind::PrometheusQuery
        | LabDataSourceKind::PrometheusMetrics => {
            validate_http_endpoint(&source.endpoint)?;
            Ok(format!(
                "{} endpoint URL is syntactically valid",
                source.kind.as_str()
            ))
        }
        LabDataSourceKind::NativePcap => match native_pcap_source(&source.endpoint, scenario_dir) {
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
        LabDataSourceKind::OtlpGrpc => {
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
            Ok(format!(
                "OTLP bind address shape valid: {}",
                source.endpoint
            ))
        }
        LabDataSourceKind::SystemCounters => Ok(if source.endpoint.trim().is_empty() {
            "system counters will sample all interfaces".to_string()
        } else {
            format!("system counters interface configured: {}", source.endpoint)
        }),
    }
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

fn check_source_reachable(
    source: &LabDataSource,
    scenario: &LabScenario,
    scenario_dir: &Path,
) -> Result<String> {
    match source.kind {
        LabDataSourceKind::TraceFile => {
            let path = resolve_path(scenario_dir, &source.endpoint);
            let ingest = ingest_trace(&path)?;
            Ok(format!(
                "{} rows from {}",
                ingest.schema.rows,
                path.display()
            ))
        }
        LabDataSourceKind::HttpJson => {
            let loaded = load_http_json(&HttpJsonConfig {
                endpoint: source.endpoint.clone(),
                bearer_token: std::env::var("NETDIAG_API_TOKEN").ok(),
                timeout: Duration::from_secs(scenario.collection.timeout_secs),
            })?;
            Ok(format!(
                "{} rows returned by HTTP/JSON",
                loaded.ingest.schema.rows
            ))
        }
        LabDataSourceKind::PrometheusQuery => {
            let loaded = load_prometheus_query_range(&PrometheusQueryRangeConfig {
                base_url: source.endpoint.clone(),
                bearer_token: std::env::var("NETDIAG_API_TOKEN").ok(),
                timeout: Duration::from_secs(scenario.collection.timeout_secs),
                lookback_seconds: scenario.collection.lookback_secs,
                step_seconds: scenario.collection.step_secs,
                queries: lab_mapping(source, scenario_dir)?,
                sample: scenario.id.clone(),
            })?;
            Ok(format!(
                "Prometheus returned {} canonical rows",
                loaded.ingest.schema.rows
            ))
        }
        LabDataSourceKind::PrometheusMetrics => {
            let loaded = load_prometheus_exposition(&PrometheusExpositionConfig {
                endpoint: source.endpoint.clone(),
                bearer_token: std::env::var("NETDIAG_API_TOKEN").ok(),
                timeout: Duration::from_secs(scenario.collection.timeout_secs),
                metrics: lab_mapping(source, scenario_dir)?,
                sample: scenario.id.clone(),
            })?;
            Ok(format!(
                "Prometheus exposition returned {} canonical rows",
                loaded.ingest.schema.rows
            ))
        }
        LabDataSourceKind::NativePcap => match native_pcap_source(&source.endpoint, scenario_dir) {
            NativePcapSource::File(path) => {
                let loaded = load_native_pcap(&NativePcapConfig {
                    source: NativePcapSource::File(path.clone()),
                    timeout: Duration::from_secs(1),
                    packet_limit: 32,
                    sample: scenario.id.clone(),
                })?;
                Ok(format!(
                    "pcap file parsed: {} canonical rows from {}",
                    loaded.ingest.schema.rows,
                    path.display()
                ))
            }
            NativePcapSource::Interface(interface) => {
                let loaded = load_native_pcap(&NativePcapConfig {
                    source: NativePcapSource::Interface(interface.clone()),
                    timeout: Duration::from_secs(scenario.collection.timeout_secs),
                    packet_limit: scenario.collection.packet_limit.min(64),
                    sample: scenario.id.clone(),
                })?;
                Ok(format!(
                    "pcap interface {interface} captured {} rows",
                    loaded.ingest.schema.rows
                ))
            }
        },
        LabDataSourceKind::OtlpGrpc => {
            let listener = TcpListener::bind(source.endpoint.trim()).map_err(|err| {
                NetdiagError::Connector(format!(
                    "OTLP bind address unavailable at {}: {err}",
                    source.endpoint
                ))
            })?;
            drop(listener);
            Ok(format!("OTLP bind address available: {}", source.endpoint))
        }
        LabDataSourceKind::SystemCounters => {
            let loaded = load_system_counters(&SystemCountersConfig {
                interface: (!source.endpoint.trim().is_empty() && source.endpoint.trim() != "all")
                    .then(|| source.endpoint.trim().to_string()),
                interval: Duration::from_secs(scenario.collection.interval_secs.clamp(1, 3)),
                sample: scenario.id.clone(),
            })?;
            Ok(format!(
                "system counters returned {} rows",
                loaded.ingest.schema.rows
            ))
        }
    }
}

fn validate_required_metric_mapping(mapping: &BTreeMap<String, String>) -> Result<()> {
    for required in required_metric_fields() {
        let Some(value) = mapping.get(required) else {
            return Err(NetdiagError::InvalidTrace(format!(
                "mapping missing required metric {required}"
            )));
        };
        if value.trim().is_empty() {
            return Err(NetdiagError::InvalidTrace(format!(
                "mapping for {required} is empty"
            )));
        }
    }
    Ok(())
}

fn required_metric_fields() -> impl Iterator<Item = &'static str> {
    CANONICAL_COLUMNS.iter().copied().filter(|column| {
        matches!(
            *column,
            "latency_ms"
                | "jitter_ms"
                | "packet_loss_rate"
                | "retransmission_rate"
                | "throughput_mbps"
        )
    })
}

fn source_label(source: &LabDataSource) -> String {
    source
        .name
        .clone()
        .unwrap_or_else(|| source.kind.as_str().to_string())
}

pub fn run_lab_scenario(path: impl AsRef<Path>, options: LabRunOptions) -> Result<LabRunResult> {
    let scenario_path = path.as_ref();
    let mut scenario = load_lab_scenario(scenario_path)?;
    if !scenario
        .data_sources
        .iter()
        .any(|source| source.role == LabDataSourceRole::Primary)
        && let Some(first) = scenario.data_sources.first_mut()
    {
        first.role = LabDataSourceRole::Primary;
    }
    let scenario_dir = scenario_path.parent().unwrap_or_else(|| Path::new("."));
    let created_at = Utc::now();
    let lab_run_dir = options
        .artifacts
        .join("lab-runs")
        .join(&scenario.id)
        .join(lab_timestamp(created_at));
    if let Some(parent) = lab_run_dir.parent() {
        fs::create_dir_all(parent).with_path(parent)?;
    }
    fs::create_dir(&lab_run_dir).with_path(&lab_run_dir)?;

    let scenario_copy = lab_run_dir.join("scenario.yaml");
    fs::copy(scenario_path, &scenario_copy).with_path(&scenario_copy)?;
    let loaded_sources = scenario
        .data_sources
        .iter()
        .map(|source| load_lab_source(source, &scenario, scenario_dir))
        .collect::<Result<Vec<_>>>()?;
    let primary = loaded_sources
        .iter()
        .find(|source| source.source.role == LabDataSourceRole::Primary)
        .ok_or_else(|| NetdiagError::InvalidTrace("missing primary source".to_string()))?;
    let what_if_spec = scenario.what_if.clone().or_else(|| {
        scenario.topology.as_ref().map(|topology| LabWhatIf {
            topology: topology.clone(),
            policy: "reroute_path_b".to_string(),
        })
    });
    let what_if = what_if_spec
        .as_ref()
        .map(|what_if| build_what_if_request(what_if, scenario_dir))
        .transpose()?;

    let model_dir = options.artifacts.join("model");
    let mut pipeline = diagnose_ingest_with_whatif_and_model_dir(
        primary.loaded.ingest.clone(),
        &lab_run_dir,
        &model_dir,
        what_if.clone(),
    )?;
    let primary_health = primary.health.clone();
    write_connector_health(&lab_run_dir, &pipeline.run_id, &primary_health)?;
    let connector_health = loaded_sources
        .iter()
        .map(|source| source.health.clone())
        .collect::<Vec<_>>();
    let corroboration_signals = collect_corroboration_signals(&loaded_sources);
    apply_corroboration_signals(&mut pipeline.diagnosis_events, &corroboration_signals);
    pipeline.comparison = compare_rule_ml(&pipeline.diagnosis_events, &pipeline.ml_result);
    pipeline.recommendations =
        recommend_actions(&pipeline.diagnosis_events, pipeline.what_if.as_ref());
    pipeline.report = render_report(
        &pipeline.run_id,
        &pipeline.telemetry,
        &pipeline.diagnosis_events,
        &pipeline.ml_result,
        pipeline.what_if.clone(),
        &pipeline.recommendations,
    );
    let multi_source_evidence = multi_source_evidence(
        &scenario,
        &pipeline.report,
        &loaded_sources,
        &primary_health,
        &corroboration_signals,
    );
    pipeline.report.multi_source_evidence = Some(multi_source_evidence.clone());
    save_json(
        run_dir(&lab_run_dir, &pipeline.run_id).join("diagnosis_events.json"),
        &pipeline.diagnosis_events,
    )?;
    save_json(
        run_dir(&lab_run_dir, &pipeline.run_id).join("recommendations.json"),
        &pipeline.recommendations,
    )?;
    save_json(
        run_dir(&lab_run_dir, &pipeline.run_id).join("report.json"),
        &pipeline.report,
    )?;

    let validation_context = LabValidationContext {
        connector_health: connector_health.clone(),
        artifact_keys: run_artifacts(&lab_run_dir, &pipeline.run_id)?
            .into_iter()
            .filter(|artifact| artifact.exists)
            .map(|artifact| artifact.key)
            .collect(),
    };
    let acceptance = validate_lab_report(&scenario, &pipeline.report, &validation_context)?;
    fs::write(lab_run_dir.join("run_id.txt"), &pipeline.run_id)
        .with_path(lab_run_dir.join("run_id.txt"))?;
    let comparison = lab_run_comparison(&scenario, &pipeline.report, &acceptance, None);

    save_json(lab_run_dir.join("connector_health.json"), &connector_health)?;
    save_json(lab_run_dir.join("report.json"), &pipeline.report)?;
    save_json(
        lab_run_dir.join("multi_source_evidence.json"),
        &multi_source_evidence,
    )?;
    save_json(lab_run_dir.join("comparison.json"), &comparison)?;
    save_json(lab_run_dir.join("acceptance.json"), &acceptance)?;

    let evidence_bundle = export_evidence_bundle(
        &lab_run_dir,
        &pipeline.run_id,
        lab_run_dir.join(format!("netdiag-evidence-{}.zip", pipeline.run_id)),
        &lab_evidence_bundle_files(&lab_run_dir, &scenario_copy),
    )?;
    save_json(lab_run_dir.join("evidence_bundle.json"), &evidence_bundle)?;
    update_lab_run_index(
        &options.artifacts,
        LabRunIndexEntry {
            run_id: pipeline.run_id.clone(),
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            created_at,
            lab_run_dir: lab_run_dir.display().to_string(),
            pipeline_run_dir: pipeline.run_dir.display().to_string(),
            acceptance_path: lab_run_dir.join("acceptance.json").display().to_string(),
            comparison_path: lab_run_dir.join("comparison.json").display().to_string(),
            scenario_path: scenario_copy.display().to_string(),
            passed: acceptance.passed,
        },
    )?;

    Ok(LabRunResult {
        schema: "netdiag-lab-run/v1".to_string(),
        scenario_id: scenario.id,
        scenario_name: scenario.name,
        run_id: pipeline.run_id,
        lab_run_dir: lab_run_dir.display().to_string(),
        pipeline_run_dir: pipeline.run_dir.display().to_string(),
        acceptance,
        comparison,
        evidence_bundle,
    })
}

pub fn run_lab_batch(scenarios: &[PathBuf], options: LabRunOptions) -> Result<LabBatchReport> {
    let mut results = Vec::new();
    for scenario_path in scenarios {
        let scenario_id = load_lab_scenario(scenario_path)
            .ok()
            .map(|scenario| scenario.id);
        match run_lab_scenario(
            scenario_path,
            LabRunOptions {
                artifacts: options.artifacts.clone(),
            },
        ) {
            Ok(result) => results.push(LabBatchScenarioResult {
                scenario_path: scenario_path.display().to_string(),
                scenario_id: Some(result.scenario_id.clone()),
                run_id: Some(result.run_id.clone()),
                lab_run_dir: Some(result.lab_run_dir.clone()),
                passed: result.acceptance.passed,
                error: None,
                acceptance: Some(result.acceptance),
            }),
            Err(err) => results.push(LabBatchScenarioResult {
                scenario_path: scenario_path.display().to_string(),
                scenario_id,
                run_id: None,
                lab_run_dir: None,
                passed: false,
                error: Some(err.to_string()),
                acceptance: None,
            }),
        }
    }
    let passed = results.iter().filter(|result| result.passed).count();
    Ok(LabBatchReport {
        schema: "netdiag-lab-batch/v1".to_string(),
        generated_at: Utc::now(),
        total_scenarios: scenarios.len(),
        passed,
        failed: results.len().saturating_sub(passed),
        results,
    })
}

pub fn summarize_lab_runs(artifact_root: impl AsRef<Path>) -> Result<LabSummaryReport> {
    let artifact_root = artifact_root.as_ref();
    let index = read_lab_run_index(artifact_root)?.unwrap_or(LabRunIndex {
        schema: "netdiag-lab-run-index/v1".to_string(),
        generated_at: Utc::now(),
        runs: Vec::new(),
    });
    let mut by_label = BTreeMap::<String, LabSummaryAccumulator>::new();
    let mut by_scenario = BTreeMap::<String, LabSummaryAccumulator>::new();
    let mut scenario_names = BTreeMap::<String, String>::new();
    let mut quality = BTreeMap::<String, usize>::new();
    let mut failures = Vec::new();
    let mut passed = 0usize;

    for entry in &index.runs {
        let acceptance_path = PathBuf::from(&entry.acceptance_path);
        let acceptance = match read_json(&acceptance_path).and_then(|value| {
            serde_json::from_value::<LabAcceptanceReport>(value).map_err(Into::into)
        }) {
            Ok(acceptance) => acceptance,
            Err(err) => {
                failures.push(LabSummaryFailure {
                    run_id: entry.run_id.clone(),
                    scenario_id: entry.scenario_id.clone(),
                    failures: vec![format!("acceptance unavailable: {err}")],
                });
                continue;
            }
        };
        let comparison = read_json(&entry.comparison_path)
            .and_then(|value| serde_json::from_value::<LabRunComparison>(value).map_err(Into::into))
            .ok();
        if acceptance.passed {
            passed += 1;
        } else {
            failures.push(LabSummaryFailure {
                run_id: entry.run_id.clone(),
                scenario_id: entry.scenario_id.clone(),
                failures: acceptance.failures.clone(),
            });
        }
        *quality
            .entry(acceptance.quality_status.as_str().to_string())
            .or_default() += 1;
        let expected = acceptance.expected_label.as_str().to_string();
        let rule_correct = acceptance
            .actual_rule_labels
            .iter()
            .any(|label| label == &expected);
        let ml_correct = acceptance.actual_ml_top == expected;
        let rule_ml_agreement = comparison
            .as_ref()
            .map(|comparison| comparison.rule_ml_agreement)
            .unwrap_or_else(|| {
                acceptance
                    .actual_rule_labels
                    .iter()
                    .any(|label| label == &acceptance.actual_ml_top)
            });
        let quality_degraded = acceptance.quality_status != ConnectorHealthStatus::Ok;
        record_summary_sample(
            by_label.entry(expected).or_default(),
            acceptance.passed,
            rule_correct,
            ml_correct,
            quality_degraded,
            !rule_ml_agreement,
        );
        scenario_names.insert(entry.scenario_id.clone(), entry.scenario_name.clone());
        record_summary_sample(
            by_scenario.entry(entry.scenario_id.clone()).or_default(),
            acceptance.passed,
            rule_correct,
            ml_correct,
            quality_degraded,
            !rule_ml_agreement,
        );
    }

    Ok(LabSummaryReport {
        schema: "netdiag-lab-summary/v1".to_string(),
        generated_at: Utc::now(),
        artifact_root: artifact_root.display().to_string(),
        total_runs: index.runs.len(),
        passed,
        failed: index.runs.len().saturating_sub(passed),
        by_label: by_label
            .into_iter()
            .map(|(label, stats)| (label, stats.into_summary()))
            .collect(),
        by_scenario: by_scenario
            .into_iter()
            .map(|(scenario_id, stats)| {
                let name = scenario_names
                    .remove(&scenario_id)
                    .unwrap_or_else(|| scenario_id.clone());
                (scenario_id, stats.into_scenario_summary(name))
            })
            .collect(),
        quality,
        failures,
    })
}

#[derive(Debug, Clone, Default)]
struct LabSummaryAccumulator {
    runs: usize,
    passed: usize,
    rule_correct: usize,
    ml_correct: usize,
    quality_degraded: usize,
    rule_ml_disagreement: usize,
}

impl LabSummaryAccumulator {
    fn into_summary(self) -> LabSummaryLabelStats {
        let denominator = self.runs.max(1) as f64;
        LabSummaryLabelStats {
            runs: self.runs,
            passed: self.passed,
            rule_accuracy: round4(self.rule_correct as f64 / denominator),
            ml_accuracy: round4(self.ml_correct as f64 / denominator),
        }
    }

    fn into_scenario_summary(self, scenario_name: String) -> LabSummaryScenarioStats {
        let denominator = self.runs.max(1) as f64;
        LabSummaryScenarioStats {
            scenario_name,
            runs: self.runs,
            passed: self.passed,
            failed: self.runs.saturating_sub(self.passed),
            rule_accuracy: round4(self.rule_correct as f64 / denominator),
            ml_accuracy: round4(self.ml_correct as f64 / denominator),
            quality_degraded_rate: round4(self.quality_degraded as f64 / denominator),
            rule_ml_disagreement_rate: round4(self.rule_ml_disagreement as f64 / denominator),
        }
    }
}

fn record_summary_sample(
    stats: &mut LabSummaryAccumulator,
    passed: bool,
    rule_correct: bool,
    ml_correct: bool,
    quality_degraded: bool,
    rule_ml_disagreement: bool,
) {
    stats.runs += 1;
    if passed {
        stats.passed += 1;
    }
    if rule_correct {
        stats.rule_correct += 1;
    }
    if ml_correct {
        stats.ml_correct += 1;
    }
    if quality_degraded {
        stats.quality_degraded += 1;
    }
    if rule_ml_disagreement {
        stats.rule_ml_disagreement += 1;
    }
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

pub fn validate_lab_run(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    scenario_path: Option<&Path>,
) -> Result<LabAcceptanceReport> {
    let input_root = artifact_root.as_ref();
    let resolution = resolve_lab_run_artifact_root(input_root, run_id)?;
    let scenario_path = scenario_path
        .map(Path::to_path_buf)
        .or_else(|| {
            resolution
                .index_entry
                .as_ref()
                .map(|entry| PathBuf::from(&entry.scenario_path))
        })
        .or_else(|| {
            let candidate = resolution.artifact_root.join("scenario.yaml");
            candidate.exists().then_some(candidate)
        })
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "lab scenario path is required because run {run_id} has no indexed scenario"
            ))
        })?;
    let scenario = load_lab_scenario(&scenario_path)?;
    let artifact_root = resolution.artifact_root;
    let report: Report = serde_json::from_value(read_json(
        run_dir(&artifact_root, run_id).join("report.json"),
    )?)?;
    validate_lab_report(
        &scenario,
        &report,
        &LabValidationContext {
            connector_health: read_lab_connector_health(&artifact_root, run_id)?,
            artifact_keys: lab_artifact_keys(&artifact_root, run_id)?,
        },
    )
}

fn read_lab_connector_health(
    artifact_root: &Path,
    run_id: &str,
) -> Result<Vec<ConnectorHealthSnapshot>> {
    let top_level = artifact_root.join("connector_health.json");
    if top_level.exists() {
        return serde_json::from_value(read_json(top_level)?).map_err(NetdiagError::from);
    }
    Ok(read_connector_health(artifact_root, run_id)?
        .into_iter()
        .collect())
}

fn lab_artifact_keys(artifact_root: &Path, run_id: &str) -> Result<Vec<String>> {
    let mut keys = run_artifacts(artifact_root, run_id)?
        .into_iter()
        .filter(|artifact| artifact.exists)
        .map(|artifact| artifact.key)
        .collect::<Vec<_>>();
    for (key, file_name) in [
        ("acceptance", "acceptance.json"),
        ("comparison", "comparison.json"),
        ("multi_source_evidence", "multi_source_evidence.json"),
        ("lab_connector_health", "connector_health.json"),
    ] {
        if artifact_root.join(file_name).exists() && !keys.iter().any(|existing| existing == key) {
            keys.push(key.to_string());
        }
    }
    Ok(keys)
}

fn lab_evidence_bundle_files(
    lab_run_dir: &Path,
    scenario_copy: &Path,
) -> Vec<EvidenceBundleExtraFile> {
    [
        ("scenario", scenario_copy.to_path_buf(), "scenario.yaml"),
        (
            "acceptance",
            lab_run_dir.join("acceptance.json"),
            "acceptance.json",
        ),
        (
            "comparison",
            lab_run_dir.join("comparison.json"),
            "comparison.json",
        ),
        (
            "multi_source_evidence",
            lab_run_dir.join("multi_source_evidence.json"),
            "multi_source_evidence.json",
        ),
        (
            "lab_connector_health",
            lab_run_dir.join("connector_health.json"),
            "lab_connector_health.json",
        ),
    ]
    .into_iter()
    .map(|(key, path, zip_path)| EvidenceBundleExtraFile {
        key: key.to_string(),
        path,
        zip_path: zip_path.to_string(),
    })
    .collect()
}

fn update_lab_run_index(artifact_root: &Path, entry: LabRunIndexEntry) -> Result<()> {
    let index_path = artifact_root.join("lab_run_index.json");
    let mut index = if index_path.exists() {
        serde_json::from_value::<LabRunIndex>(read_json(&index_path)?)?
    } else {
        LabRunIndex {
            schema: "netdiag-lab-run-index/v1".to_string(),
            generated_at: Utc::now(),
            runs: Vec::new(),
        }
    };
    index.schema = "netdiag-lab-run-index/v1".to_string();
    index.generated_at = Utc::now();
    index
        .runs
        .retain(|existing| existing.run_id != entry.run_id);
    index.runs.insert(0, entry);
    index.runs.truncate(200);
    save_json(index_path, &index)?;
    Ok(())
}

fn read_lab_run_index(artifact_root: &Path) -> Result<Option<LabRunIndex>> {
    let index_path = artifact_root.join("lab_run_index.json");
    if !index_path.exists() {
        return Ok(None);
    }
    serde_json::from_value(read_json(index_path)?)
        .map(Some)
        .map_err(NetdiagError::from)
}

fn resolve_lab_run_artifact_root(artifact_root: &Path, run_id: &str) -> Result<LabRunResolution> {
    if run_dir(artifact_root, run_id).join("report.json").exists() {
        return Ok(LabRunResolution {
            artifact_root: artifact_root.to_path_buf(),
            index_entry: None,
        });
    }
    if let Some(index) = read_lab_run_index(artifact_root)?
        && let Some(entry) = index.runs.into_iter().find(|entry| entry.run_id == run_id)
    {
        let lab_run_dir = PathBuf::from(&entry.lab_run_dir);
        if run_dir(&lab_run_dir, run_id).join("report.json").exists() {
            return Ok(LabRunResolution {
                artifact_root: lab_run_dir,
                index_entry: Some(entry),
            });
        }
    }
    if let Some(lab_run_dir) = scan_lab_run_dir(artifact_root, run_id)? {
        return Ok(LabRunResolution {
            artifact_root: lab_run_dir,
            index_entry: None,
        });
    }
    Err(NetdiagError::InvalidTrace(format!(
        "unknown lab run id: {run_id}"
    )))
}

fn scan_lab_run_dir(artifact_root: &Path, run_id: &str) -> Result<Option<PathBuf>> {
    let lab_runs_dir = artifact_root.join("lab-runs");
    if !lab_runs_dir.exists() {
        return Ok(None);
    }
    for scenario in fs::read_dir(&lab_runs_dir).with_path(&lab_runs_dir)? {
        let scenario = scenario.with_path(&lab_runs_dir)?;
        let scenario_path = scenario.path();
        if !scenario_path.is_dir() {
            continue;
        }
        for run in fs::read_dir(&scenario_path).with_path(&scenario_path)? {
            let run = run.with_path(&scenario_path)?;
            let candidate = run.path();
            if candidate
                .join("runs")
                .join(run_id)
                .join("report.json")
                .exists()
            {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(None)
}

pub fn validate_lab_report(
    scenario: &LabScenario,
    report: &Report,
    context: &LabValidationContext,
) -> Result<LabAcceptanceReport> {
    let expected = scenario
        .acceptance
        .expected_root_cause
        .unwrap_or(scenario.expected_label);
    let rule_labels = report
        .root_causes
        .iter()
        .map(|root| root.symptom.clone())
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    let synthetic_model = report
        .model_manifest
        .as_ref()
        .map(|manifest| manifest.synthetic_fallback)
        .unwrap_or(false);
    let model_dataset_hash = report
        .model_manifest
        .as_ref()
        .and_then(|manifest| manifest.dataset_hash_sha256.clone());
    match &report.model_manifest {
        Some(manifest) => {
            if manifest.synthetic_fallback && !scenario.acceptance.allow_synthetic_model {
                failures
                    .push("synthetic fallback model is not allowed by lab acceptance".to_string());
            }
            if let Some(required_hash) = scenario.acceptance.required_model_dataset_hash.as_deref()
            {
                match manifest.dataset_hash_sha256.as_deref() {
                    Some(actual_hash) if actual_hash == required_hash => {}
                    Some(actual_hash) => failures.push(format!(
                        "model dataset hash was {actual_hash}, expected {required_hash}"
                    )),
                    None => failures.push(format!(
                        "model dataset hash is missing, expected {required_hash}"
                    )),
                }
            }
        }
        None => failures.push("model manifest is missing from report".to_string()),
    }
    if expected == FaultLabel::Normal {
        let non_normal = rule_labels
            .iter()
            .filter(|label| label.as_str() != FaultLabel::Normal.as_str())
            .cloned()
            .collect::<Vec<_>>();
        if !non_normal.is_empty() {
            failures.push(format!(
                "expected normal but non-normal rule labels were {}",
                non_normal.join(", ")
            ));
        }
        if let Some(root) = report
            .root_causes
            .iter()
            .find(|root| root.symptom == FaultLabel::Normal.as_str())
            && root.confidence < scenario.acceptance.min_rule_confidence
        {
            failures.push(format!(
                "normal rule confidence was {:.3}, below {:.3}",
                root.confidence, scenario.acceptance.min_rule_confidence
            ));
        }
    } else {
        let expected_label = expected.as_str();
        let matching = report
            .root_causes
            .iter()
            .find(|root| root.symptom == expected_label);
        if let Some(root) = matching {
            if root_is_suspected_corroboration(root)
                && !scenario.acceptance.allow_suspected_corroboration
            {
                failures.push(format!(
                        "expected label {expected_label} was raised only as corroboration suspected fault"
                    ));
            }
            if root.confidence < scenario.acceptance.min_rule_confidence {
                failures.push(format!(
                    "rule confidence for {expected_label} was {:.3}, below {:.3}",
                    root.confidence, scenario.acceptance.min_rule_confidence
                ));
            }
        } else {
            failures.push(format!(
                "expected label {expected_label} was absent from rule labels"
            ));
        }
    }
    if report.rule_vs_ml.ml_top != expected.as_str() {
        failures.push(format!(
            "ML top label was {}, expected {}",
            report.rule_vs_ml.ml_top,
            expected.as_str()
        ));
    }
    if report.rule_vs_ml.ml_top_prob < scenario.acceptance.min_ml_probability {
        failures.push(format!(
            "ML probability was {:.3}, below {:.3}",
            report.rule_vs_ml.ml_top_prob, scenario.acceptance.min_ml_probability
        ));
    }
    if scenario.acceptance.require_rule_ml_agreement && !report.rule_vs_ml.agreement {
        failures.push("rule/ML agreement gate failed".to_string());
    }
    for (field, required_quality) in &scenario.acceptance.allowed_quality {
        let actual = report
            .measurement_quality
            .iter()
            .find(|item| item.field == *field)
            .map(|item| item.quality)
            .unwrap_or(MetricQuality::Missing);
        if actual != *required_quality {
            failures.push(format!(
                "{field} quality was {}, expected {}",
                actual.as_str(),
                required_quality.as_str()
            ));
        }
    }
    let quality_status = context
        .connector_health
        .iter()
        .map(|health| health.status)
        .max()
        .unwrap_or(ConnectorHealthStatus::Ok);
    if !context.connector_health.is_empty()
        && !scenario
            .acceptance
            .allowed_connector_status
            .contains(&quality_status)
    {
        failures.push(format!(
            "connector health status {quality_status} is not allowed"
        ));
    }
    if scenario.acceptance.require_what_if_improvement {
        match &report.what_if {
            Some(what_if) => validate_what_if_improvement(what_if, &mut failures),
            None => failures.push(
                "what-if improvement gate requires a what-if result, but report.what_if is missing"
                    .to_string(),
            ),
        }
    }
    let artifact_keys = if context.artifact_keys.is_empty() {
        report_artifact_keys(report)
    } else {
        context.artifact_keys.clone()
    };
    for required in &scenario.acceptance.required_artifacts {
        if !artifact_keys.contains(required) {
            failures.push(format!("required artifact {required} is missing"));
        }
    }

    Ok(LabAcceptanceReport {
        schema: "netdiag-lab-acceptance/v1".to_string(),
        scenario_id: scenario.id.clone(),
        run_id: report.run_id.clone(),
        expected_label: expected,
        actual_rule_labels: rule_labels,
        actual_ml_top: report.rule_vs_ml.ml_top.clone(),
        actual_ml_probability: report.rule_vs_ml.ml_top_prob,
        synthetic_model,
        model_dataset_hash,
        quality_status,
        passed: failures.is_empty(),
        failures,
    })
}

fn root_is_suspected_corroboration(root: &crate::report::RootCause) -> bool {
    root.source == "corroboration" || root.method == "corroboration"
}

fn validate_what_if_improvement(what_if: &crate::models::WhatIfResult, failures: &mut Vec<String>) {
    let mut improved = false;
    for (metric, should_be_positive) in [
        ("latency_pct", false),
        ("loss_pct", false),
        ("throughput_pct", true),
    ] {
        let Some(delta) = what_if.delta.get(metric).copied() else {
            failures.push(format!("what-if delta {metric} is missing"));
            continue;
        };
        if !delta.is_finite() {
            failures.push(format!("what-if delta {metric} is not finite"));
            continue;
        }
        if should_be_positive {
            if delta < 0.0 {
                failures.push(format!("what-if {metric} worsened by {delta:.2}%"));
            }
            if delta > 0.0 {
                improved = true;
            }
        } else {
            if delta > 0.0 {
                failures.push(format!("what-if {metric} worsened by {delta:.2}%"));
            }
            if delta < 0.0 {
                improved = true;
            }
        }
    }
    if !improved {
        failures.push(
            "what-if did not improve latency, loss, or throughput in the expected direction"
                .to_string(),
        );
    }
}

fn load_lab_source(
    source: &LabDataSource,
    scenario: &LabScenario,
    scenario_dir: &Path,
) -> Result<LoadedLabSource> {
    let loaded = match source.kind {
        LabDataSourceKind::TraceFile => load_trace_file_source(source, scenario_dir)?,
        LabDataSourceKind::HttpJson => load_http_json(&HttpJsonConfig {
            endpoint: source.endpoint.clone(),
            bearer_token: std::env::var("NETDIAG_API_TOKEN").ok(),
            timeout: Duration::from_secs(scenario.collection.timeout_secs),
        })?,
        LabDataSourceKind::PrometheusQuery => {
            load_prometheus_query_range(&PrometheusQueryRangeConfig {
                base_url: source.endpoint.clone(),
                bearer_token: std::env::var("NETDIAG_API_TOKEN").ok(),
                timeout: Duration::from_secs(scenario.collection.timeout_secs),
                lookback_seconds: scenario.collection.lookback_secs,
                step_seconds: scenario.collection.step_secs,
                queries: lab_mapping(source, scenario_dir)?,
                sample: scenario.id.clone(),
            })?
        }
        LabDataSourceKind::PrometheusMetrics => {
            load_prometheus_exposition(&PrometheusExpositionConfig {
                endpoint: source.endpoint.clone(),
                bearer_token: std::env::var("NETDIAG_API_TOKEN").ok(),
                timeout: Duration::from_secs(scenario.collection.timeout_secs),
                metrics: lab_mapping(source, scenario_dir)?,
                sample: scenario.id.clone(),
            })?
        }
        LabDataSourceKind::NativePcap => load_native_pcap(&NativePcapConfig {
            source: native_pcap_source(&source.endpoint, scenario_dir),
            timeout: Duration::from_secs(scenario.collection.timeout_secs),
            packet_limit: scenario.collection.packet_limit,
            sample: scenario.id.clone(),
        })?,
        LabDataSourceKind::OtlpGrpc => load_otlp_grpc_receiver(&OtlpGrpcReceiverConfig {
            bind_addr: source.endpoint.clone(),
            timeout: Duration::from_secs(scenario.collection.timeout_secs),
            metrics: lab_mapping(source, scenario_dir)?,
            sample: scenario.id.clone(),
        })?,
        LabDataSourceKind::SystemCounters => load_system_counters(&SystemCountersConfig {
            interface: (!source.endpoint.trim().is_empty() && source.endpoint.trim() != "all")
                .then(|| source.endpoint.trim().to_string()),
            interval: Duration::from_secs(scenario.collection.interval_secs.clamp(1, 10)),
            sample: scenario.id.clone(),
        })?,
    };
    let profile_name = source
        .name
        .clone()
        .unwrap_or_else(|| source.kind.as_str().to_string());
    let health = connector_health_from_ingest(
        source.kind.as_str(),
        &profile_name,
        &loaded.sample,
        &loaded.ingest,
    );
    Ok(LoadedLabSource {
        source: source.clone(),
        loaded,
        health,
    })
}

fn load_trace_file_source(
    source: &LabDataSource,
    scenario_dir: &Path,
) -> Result<ConnectorLoadResult> {
    let path = resolve_path(scenario_dir, &source.endpoint);
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

fn build_what_if_request(what_if: &LabWhatIf, base_dir: &Path) -> Result<WhatIfRequest> {
    let topology = load_lab_topology(what_if, base_dir)?;
    let action = load_lab_policy(what_if, base_dir)?;
    validate_policy_action_for_topology(&action, &topology)?;
    Ok(WhatIfRequest { topology, action })
}

fn load_lab_topology(what_if: &LabWhatIf, base_dir: &Path) -> Result<crate::models::TopologyModel> {
    let topology_ref = resolve_path(base_dir, &what_if.topology);
    if topology_ref.exists() {
        let raw = fs::read_to_string(&topology_ref).with_path(&topology_ref)?;
        import_topology(&raw, format_for_path(&topology_ref))
    } else {
        topology_model(&what_if.topology)
    }
}

fn load_lab_policy(
    what_if: &LabWhatIf,
    base_dir: &Path,
) -> Result<crate::models::TwinPolicyAction> {
    let policy_ref = resolve_path(base_dir, &what_if.policy);
    if policy_ref.exists() {
        let raw = fs::read_to_string(&policy_ref).with_path(&policy_ref)?;
        import_policy_action(&raw, format_for_path(&policy_ref))
    } else {
        policy_action(&what_if.policy)
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SourceSignalMetrics {
    latency_mean: f64,
    packet_loss_rate: f64,
    retransmission_rate: f64,
    throughput_mbps: f64,
    dns_failure_events: f64,
    tls_failure_events: f64,
    quic_blocked_ratio: f64,
}

fn collect_corroboration_signals(loaded_sources: &[LoadedLabSource]) -> Vec<CorroborationSignal> {
    let mut signals = Vec::new();
    for source in loaded_sources
        .iter()
        .filter(|source| source.source.role == LabDataSourceRole::Corroborating)
    {
        let source_kind = source.health.source_kind.clone();
        let Some(metrics) = source_signal_metrics(&source.loaded.ingest) else {
            continue;
        };
        if metrics.latency_mean > 120.0 && metrics.throughput_mbps < 35.0 {
            signals.push(support_signal(
                &source_kind,
                "latency high and throughput low",
                FaultLabel::Congestion,
                0.05,
            ));
        }
        if metrics.dns_failure_events > 0.0 {
            signals.push(support_signal(
                &source_kind,
                "dns failure counter is non-zero",
                FaultLabel::DnsFailure,
                0.05,
            ));
        }
        if metrics.tls_failure_events > 0.0 {
            signals.push(support_signal(
                &source_kind,
                "tls failure counter is non-zero",
                FaultLabel::TlsFailure,
                0.05,
            ));
        }
        if source.source.kind != LabDataSourceKind::NativePcap && metrics.quic_blocked_ratio > 0.5 {
            signals.push(support_signal(
                &source_kind,
                "QUIC blocked ratio is elevated",
                FaultLabel::UdpQuicBlocked,
                0.05,
            ));
        }
        if metrics.packet_loss_rate > 1.0 && metrics.retransmission_rate > 1.0 {
            signals.push(support_signal(
                &source_kind,
                "loss and retransmission counters are elevated",
                FaultLabel::RandomLoss,
                0.04,
            ));
        }
        if source.source.kind == LabDataSourceKind::NativePcap {
            collect_pcap_corroboration_signals(source, &metrics, &mut signals);
        }
    }
    signals
}

fn collect_pcap_corroboration_signals(
    source: &LoadedLabSource,
    metrics: &SourceSignalMetrics,
    signals: &mut Vec<CorroborationSignal>,
) {
    let source_kind = source.health.source_kind.as_str();
    if metrics.retransmission_rate > 1.0 {
        signals.push(support_signal(
            source_kind,
            "TCP retransmission hint observed in pcap",
            FaultLabel::Congestion,
            0.04,
        ));
        signals.push(support_signal(
            source_kind,
            "TCP retransmission hint can also fit random loss",
            FaultLabel::RandomLoss,
            0.02,
        ));
    }
    let Some(payload) = source.loaded.payload.as_ref() else {
        return;
    };
    let udp_packets = payload
        .get("udp_packets")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let dns_packets = payload
        .get("dns_packets")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let quic_packets = payload
        .get("quic_packets")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    if udp_packets > 0 && dns_packets == 0 {
        signals.push(contradict_signal(
            source_kind,
            "pcap observed UDP traffic but no DNS/53 packets",
            FaultLabel::DnsFailure,
            -0.03,
        ));
    }
    if udp_packets > 0 && quic_packets == 0 {
        signals.push(support_signal(
            source_kind,
            "UDP/443 traffic absent in pcap; weak QUIC block hint",
            FaultLabel::UdpQuicBlocked,
            0.02,
        ));
    } else if quic_packets > 0 {
        signals.push(contradict_signal(
            source_kind,
            "pcap observed UDP/443 traffic, so QUIC policy blocking is not proven",
            FaultLabel::UdpQuicBlocked,
            -0.03,
        ));
    }
}

fn source_signal_metrics(ingest: &IngestResult) -> Option<SourceSignalMetrics> {
    let count = ingest.records.len() as f64;
    if count == 0.0 {
        return None;
    }
    let mut metrics = SourceSignalMetrics::default();
    for record in &ingest.records {
        metrics.latency_mean += record.latency_ms;
        metrics.packet_loss_rate += record.packet_loss_rate;
        metrics.retransmission_rate += record.retransmission_rate;
        metrics.throughput_mbps += record.throughput_mbps;
        metrics.dns_failure_events += record.dns_failure_events;
        metrics.tls_failure_events += record.tls_failure_events;
        metrics.quic_blocked_ratio += record.quic_blocked_ratio;
    }
    metrics.latency_mean /= count;
    metrics.packet_loss_rate /= count;
    metrics.retransmission_rate /= count;
    metrics.throughput_mbps /= count;
    metrics.dns_failure_events /= count;
    metrics.tls_failure_events /= count;
    metrics.quic_blocked_ratio /= count;
    Some(metrics)
}

fn support_signal(
    source_kind: &str,
    signal: &str,
    label: FaultLabel,
    confidence_delta: f64,
) -> CorroborationSignal {
    CorroborationSignal {
        source_kind: source_kind.to_string(),
        signal: signal.to_string(),
        supports: Some(label),
        contradicts: None,
        confidence_delta: confidence_delta.abs(),
    }
}

fn contradict_signal(
    source_kind: &str,
    signal: &str,
    label: FaultLabel,
    confidence_delta: f64,
) -> CorroborationSignal {
    CorroborationSignal {
        source_kind: source_kind.to_string(),
        signal: signal.to_string(),
        supports: None,
        contradicts: Some(label),
        confidence_delta: -confidence_delta.abs(),
    }
}

fn apply_corroboration_signals(
    diagnosis_events: &mut Vec<DiagnosisEvent>,
    signals: &[CorroborationSignal],
) {
    if signals.is_empty() {
        return;
    }
    let existing_labels = diagnosis_events
        .iter()
        .map(|event| event.evidence.symptom)
        .collect::<std::collections::BTreeSet<_>>();
    for event in diagnosis_events.iter_mut() {
        let label = event.evidence.symptom;
        let mut confidence_delta = 0.0;
        for signal in signals
            .iter()
            .filter(|signal| signal_affects(signal, label))
        {
            confidence_delta += signal.confidence_delta;
            event
                .evidence
                .raw_evidence_refs
                .push(signal_evidence_ref(signal));
            if signal.contradicts == Some(label) {
                event
                    .evidence
                    .counter_evidence
                    .push(format!("{}: {}", signal.source_kind, signal.signal));
            }
        }
        if confidence_delta.abs() > f64::EPSILON {
            event.evidence.confidence =
                (event.evidence.confidence + confidence_delta).clamp(0.0, 1.0);
            event.evidence.why = format!(
                "{} Multi-source evidence adjusted confidence by {confidence_delta:+.3}.",
                event.evidence.why
            );
        }
    }
    raise_suspected_faults(diagnosis_events, signals, &existing_labels);
}

fn signal_affects(signal: &CorroborationSignal, label: FaultLabel) -> bool {
    signal.supports == Some(label) || signal.contradicts == Some(label)
}

fn signal_evidence_ref(signal: &CorroborationSignal) -> EvidenceRef {
    let decision = if signal.contradicts.is_some() {
        CorroborationDecision::AddCounterEvidence
    } else {
        CorroborationDecision::BoostExisting
    };
    signal_evidence_ref_with_decision(signal, decision)
}

fn signal_evidence_ref_with_decision(
    signal: &CorroborationSignal,
    decision: CorroborationDecision,
) -> EvidenceRef {
    let mut details = BTreeMap::new();
    details.insert(
        "signal".to_string(),
        serde_json::Value::String(signal.signal.clone()),
    );
    details.insert(
        "confidence_delta".to_string(),
        serde_json::json!(signal.confidence_delta),
    );
    details.insert(
        "decision".to_string(),
        serde_json::Value::String(corroboration_decision_name(decision).to_string()),
    );
    if let Some(label) = signal.supports {
        details.insert(
            "supports".to_string(),
            serde_json::Value::String(label.as_str().to_string()),
        );
    }
    if let Some(label) = signal.contradicts {
        details.insert(
            "contradicts".to_string(),
            serde_json::Value::String(label.as_str().to_string()),
        );
    }
    EvidenceRef {
        source: signal.source_kind.clone(),
        artifact: "multi_source_evidence.json".to_string(),
        offset: None,
        details,
    }
}

fn corroboration_decision_name(decision: CorroborationDecision) -> &'static str {
    match decision {
        CorroborationDecision::BoostExisting => "boost_existing",
        CorroborationDecision::AddCounterEvidence => "add_counter_evidence",
        CorroborationDecision::RaisesSuspectedFault => "raises_suspected_fault",
    }
}

fn raise_suspected_faults(
    diagnosis_events: &mut Vec<DiagnosisEvent>,
    signals: &[CorroborationSignal],
    existing_labels: &std::collections::BTreeSet<FaultLabel>,
) {
    let mut by_label = BTreeMap::<FaultLabel, Vec<&CorroborationSignal>>::new();
    for signal in signals
        .iter()
        .filter(|signal| signal.supports.is_some() && signal.confidence_delta > 0.0)
    {
        let label = signal.supports.expect("filtered supports");
        if label == FaultLabel::Normal || existing_labels.contains(&label) {
            continue;
        }
        by_label.entry(label).or_default().push(signal);
    }
    let Some(reference) = diagnosis_events.first() else {
        return;
    };
    let run_id = reference.evidence.run_id.clone();
    let window = reference.evidence.window.clone();
    for (label, supporting_signals) in by_label {
        let total_delta = supporting_signals
            .iter()
            .map(|signal| signal.confidence_delta)
            .sum::<f64>();
        if total_delta < 0.05 {
            continue;
        }
        let source_list = supporting_signals
            .iter()
            .map(|signal| signal.source_kind.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        let signal_text = supporting_signals
            .iter()
            .map(|signal| signal.signal.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        diagnosis_events.push(DiagnosisEvent {
            event_id: format!("corroboration-{}", &Uuid::new_v4().simple().to_string()[..8]),
            evidence: EvidenceRecord {
                run_id: run_id.clone(),
                method: "corroboration".to_string(),
                symptom: label,
                severity: if total_delta >= 0.08 {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                confidence: (0.50 + total_delta).clamp(0.0, 0.70),
                window: TimeWindow {
                    start_ts: window.start_ts,
                    end_ts: window.end_ts,
                    bucket: window.bucket.clone(),
                },
                supporting_metrics: Vec::new(),
                raw_evidence_refs: supporting_signals
                    .iter()
                    .map(|signal| {
                        signal_evidence_ref_with_decision(
                            signal,
                            CorroborationDecision::RaisesSuspectedFault,
                        )
                    })
                    .collect(),
                counter_evidence: vec![
                    "primary diagnosis did not raise this label; human review is required"
                        .to_string(),
                ],
                recommendation_need_approval: true,
                hil_state: HilState::Unreviewed,
                why: format!(
                    "Corroborating source(s) {source_list} raised suspected {} from: {signal_text}.",
                    label.as_str()
                ),
            },
            source: "corroboration".to_string(),
            model_probability: None,
        });
    }
}

fn signal_summary(signal: &CorroborationSignal) -> String {
    let relation = if let Some(label) = signal.supports {
        format!("supports {}", label.as_str())
    } else if let Some(label) = signal.contradicts {
        format!("contradicts {}", label.as_str())
    } else {
        "observed".to_string()
    };
    format!(
        "{}: {} ({relation}, {:+.3})",
        signal.source_kind, signal.signal, signal.confidence_delta
    )
}

fn confidence_delta_by_label(signals: &[CorroborationSignal]) -> BTreeMap<String, f64> {
    let mut deltas = BTreeMap::new();
    for signal in signals {
        if let Some(label) = signal.supports.or(signal.contradicts) {
            *deltas.entry(label.as_str().to_string()).or_default() += signal.confidence_delta;
        }
    }
    deltas
}

fn multi_source_evidence(
    scenario: &LabScenario,
    report: &Report,
    loaded_sources: &[LoadedLabSource],
    primary_health: &ConnectorHealthSnapshot,
    corroboration_signals: &[CorroborationSignal],
) -> MultiSourceEvidenceSummary {
    let expected = scenario
        .acceptance
        .expected_root_cause
        .unwrap_or(scenario.expected_label)
        .as_str()
        .to_string();
    let primary_evidence = if report.root_causes.is_empty() {
        vec!["rules did not find a non-normal root cause".to_string()]
    } else {
        report
            .root_causes
            .iter()
            .map(|root| format!("{}: {}", root.symptom, root.why))
            .collect()
    };
    let primary_ingest = loaded_sources
        .iter()
        .find(|source| source.source.role == LabDataSourceRole::Primary)
        .map(|source| &source.loaded.ingest)
        .unwrap_or(&loaded_sources[0].loaded.ingest);
    let primary = source_summary(
        "primary",
        primary_health,
        primary_ingest,
        corroboration_signals,
    );
    let corroborating_sources = loaded_sources
        .iter()
        .filter(|source| source.source.role == LabDataSourceRole::Corroborating)
        .map(|source| {
            source_summary(
                "corroborating",
                &source.health,
                &source.loaded.ingest,
                corroboration_signals,
            )
        })
        .collect::<Vec<_>>();
    let corroborating_evidence = corroborating_sources
        .iter()
        .flat_map(|source| source.signals.clone())
        .chain(
            corroboration_signals
                .iter()
                .filter(|signal| signal.supports.is_some())
                .map(signal_summary),
        )
        .collect::<Vec<_>>();
    let counter_evidence = loaded_sources
        .iter()
        .flat_map(|source| {
            source
                .loaded
                .ingest
                .warnings
                .iter()
                .map(|warning| format!("{}: {}", source.health.source_kind, warning.reason))
                .collect::<Vec<_>>()
        })
        .chain(
            corroboration_signals
                .iter()
                .filter(|signal| signal.contradicts.is_some())
                .map(signal_summary),
        )
        .collect::<Vec<_>>();
    let confidence_delta_by_label = confidence_delta_by_label(corroboration_signals);
    MultiSourceEvidenceSummary {
        root_cause: expected,
        primary_evidence,
        corroborating_evidence,
        counter_evidence,
        signals: corroboration_signals.to_vec(),
        confidence_delta_by_label,
        primary,
        corroborating_sources,
    }
}

fn source_summary(
    role: &str,
    health: &ConnectorHealthSnapshot,
    ingest: &IngestResult,
    corroboration_signals: &[CorroborationSignal],
) -> SourceEvidenceSummary {
    let signals = ingest
        .metric_provenance
        .iter()
        .filter(|item| item.quality.is_trustworthy())
        .map(|item| format!("{} measured by {}", item.field, item.source))
        .collect::<Vec<_>>();
    let counter_evidence = ingest
        .metric_provenance
        .iter()
        .filter(|item| !item.quality.is_trustworthy())
        .map(|item| format!("{} quality is {}", item.field, item.quality.as_str()))
        .collect::<Vec<_>>();
    SourceEvidenceSummary {
        role: role.to_string(),
        source_kind: health.source_kind.clone(),
        profile_name: health.profile_name.clone(),
        sample: health.sample.clone(),
        status: health.status,
        rows: health.rows,
        warning_count: health.warning_count,
        missing_metrics: health.missing_metrics.clone(),
        quality: health.quality,
        signals,
        counter_evidence,
        corroboration_signals: corroboration_signals
            .iter()
            .filter(|signal| signal.source_kind == health.source_kind)
            .cloned()
            .collect(),
    }
}

fn lab_run_comparison(
    scenario: &LabScenario,
    report: &Report,
    acceptance: &LabAcceptanceReport,
    previous_run_comparison: Option<RunComparison>,
) -> LabRunComparison {
    LabRunComparison {
        schema: "netdiag-lab-comparison/v1".to_string(),
        scenario_id: scenario.id.clone(),
        run_id: report.run_id.clone(),
        expected_label: acceptance.expected_label,
        actual_rule_labels: acceptance.actual_rule_labels.clone(),
        actual_ml_top: acceptance.actual_ml_top.clone(),
        rule_ml_agreement: report.rule_vs_ml.agreement,
        quality_status: acceptance.quality_status,
        previous_run_comparison,
    }
}

fn report_artifact_keys(report: &Report) -> Vec<String> {
    let mut keys = vec![
        "manifest".to_string(),
        "report".to_string(),
        "telemetry_summary".to_string(),
        "diagnosis_events".to_string(),
        "ml_result".to_string(),
        "recommendations".to_string(),
        "connector_health".to_string(),
    ];
    if report.what_if.is_some() {
        keys.push("whatif_default".to_string());
    }
    keys
}

fn lab_mapping(source: &LabDataSource, scenario_dir: &Path) -> Result<BTreeMap<String, String>> {
    let Some(mapping) = source.mapping.as_ref() else {
        return Ok(default_prometheus_mapping());
    };
    let path = resolve_path(scenario_dir, mapping);
    let raw = fs::read_to_string(&path).with_path(&path)?;
    serde_json::from_str(&raw).map_err(NetdiagError::from)
}

fn native_pcap_source(endpoint: &str, scenario_dir: &Path) -> NativePcapSource {
    let trimmed = endpoint.trim();
    if let Some(interface) = trimmed.strip_prefix("iface:") {
        return NativePcapSource::Interface(interface.trim().to_string());
    }
    let path = resolve_path(scenario_dir, trimmed);
    if path.is_file() {
        NativePcapSource::File(path)
    } else {
        NativePcapSource::Interface(trimmed.to_string())
    }
}

fn resolve_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
}

fn format_for_path(path: &Path) -> TopologyFormat {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "yaml" | "yml" => TopologyFormat::Yaml,
        _ => TopologyFormat::Json,
    }
}

fn lab_timestamp(timestamp: DateTime<Utc>) -> String {
    format!(
        "{}-{}",
        timestamp.format("%Y%m%dT%H%M%S%.3fZ"),
        &Uuid::new_v4().simple().to_string()[..8]
    )
}

fn default_lookback_secs() -> i64 {
    300
}

fn default_step_secs() -> u64 {
    15
}

fn default_packet_limit() -> usize {
    5000
}

fn default_timeout_secs() -> u64 {
    20
}

fn default_interval_secs() -> u64 {
    1
}

fn default_min_rule_confidence() -> f64 {
    0.75
}

fn default_min_ml_probability() -> f64 {
    0.70
}

fn default_true() -> bool {
    true
}

fn default_allowed_connector_status() -> Vec<ConnectorHealthStatus> {
    vec![ConnectorHealthStatus::Ok, ConnectorHealthStatus::Degraded]
}

fn default_required_artifacts() -> Vec<String> {
    vec![
        "manifest".to_string(),
        "report".to_string(),
        "telemetry_summary".to_string(),
        "diagnosis_events".to_string(),
        "ml_result".to_string(),
        "recommendations".to_string(),
        "connector_health".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DistributionStats, ModelManifest, OverallTelemetry, ThroughputStats, WhatIfResult,
    };
    use crate::report::{Report, RootCause, RuleMlComparison};
    use std::collections::BTreeSet;

    fn scenario(expected: FaultLabel, require_what_if_improvement: bool) -> LabScenario {
        LabScenario {
            schema: "netdiag-lab-scenario/v1".to_string(),
            id: "test-scenario".to_string(),
            name: "Test Scenario".to_string(),
            expected_label: expected,
            topology: None,
            data_sources: vec![LabDataSource {
                name: Some("primary".to_string()),
                role: LabDataSourceRole::Primary,
                kind: LabDataSourceKind::TraceFile,
                endpoint: "trace.csv".to_string(),
                mapping: None,
            }],
            collection: LabCollection::default(),
            what_if: None,
            acceptance: LabAcceptance {
                expected_root_cause: Some(expected),
                min_rule_confidence: 0.75,
                min_ml_probability: 0.70,
                allowed_quality: BTreeMap::new(),
                allowed_connector_status: default_allowed_connector_status(),
                require_rule_ml_agreement: true,
                require_what_if_improvement,
                required_artifacts: Vec::new(),
                allow_synthetic_model: false,
                required_model_dataset_hash: None,
                allow_suspected_corroboration: false,
            },
        }
    }

    fn report(
        run_id: &str,
        roots: Vec<RootCause>,
        ml_top: FaultLabel,
        what_if: Option<WhatIfResult>,
    ) -> Report {
        let rule_labels = roots
            .iter()
            .map(|root| root.symptom.clone())
            .collect::<Vec<_>>();
        let ml_top_text = ml_top.as_str().to_string();
        Report {
            run_id: run_id.to_string(),
            generated_at: Utc::now(),
            trace_summary: telemetry_summary(),
            measurement_quality: Vec::new(),
            root_causes: roots,
            rule_vs_ml: RuleMlComparison {
                rule_labels: rule_labels.clone(),
                ml_top: ml_top_text.clone(),
                ml_top_prob: 0.95,
                agreement: rule_labels.iter().any(|label| label == &ml_top_text),
                agreement_text: "test".to_string(),
                rule_missing: Vec::new(),
                rule_only: Vec::new(),
            },
            model_manifest: Some(model_manifest(false, Some("dataset-test-hash"))),
            what_if,
            multi_source_evidence: None,
            recommendations: Vec::new(),
            hil_summary: Default::default(),
        }
    }

    fn root(label: FaultLabel, confidence: f64) -> RootCause {
        RootCause {
            symptom: label.as_str().to_string(),
            severity: "low".to_string(),
            confidence,
            why: "test".to_string(),
            source: "rule".to_string(),
            method: "rule".to_string(),
        }
    }

    fn model_manifest(synthetic_fallback: bool, dataset_hash: Option<&str>) -> ModelManifest {
        ModelManifest {
            schema_version: "netdiag-model-manifest/v1".to_string(),
            model_name: "test".to_string(),
            model_kind: "test".to_string(),
            created_at: Utc::now(),
            training_source: if synthetic_fallback {
                "synthetic_fallback".to_string()
            } else {
                "jsonl:test".to_string()
            },
            dataset_hash_sha256: dataset_hash.map(str::to_string),
            dataset_id: None,
            dataset_manifest_hash_sha256: None,
            model_file: "rust_logistic_model.json".to_string(),
            feature_names: Vec::new(),
            labels: FaultLabel::ALL
                .iter()
                .map(|label| label.as_str().to_string())
                .collect(),
            training_examples: 1,
            label_distribution: BTreeMap::new(),
            feature_count: 0,
            synthetic_fallback,
            training_config: None,
            evaluation: None,
            training_gate: None,
        }
    }

    fn diagnosis_event(label: FaultLabel, source: &str, method: &str) -> DiagnosisEvent {
        let now = Utc::now();
        DiagnosisEvent {
            event_id: format!("test-{}", label.as_str()),
            evidence: EvidenceRecord {
                run_id: "run-test".to_string(),
                method: method.to_string(),
                symptom: label,
                severity: Severity::Low,
                confidence: 0.95,
                window: TimeWindow {
                    start_ts: now,
                    end_ts: now,
                    bucket: "test".to_string(),
                },
                supporting_metrics: Vec::new(),
                raw_evidence_refs: Vec::new(),
                counter_evidence: Vec::new(),
                recommendation_need_approval: true,
                hil_state: HilState::Unreviewed,
                why: "test".to_string(),
            },
            source: source.to_string(),
            model_probability: None,
        }
    }

    fn telemetry_summary() -> crate::models::TelemetrySummary {
        crate::models::TelemetrySummary {
            overall: OverallTelemetry {
                duration_s: 1.0,
                samples: 1,
                latency: DistributionStats::default(),
                jitter_ms: DistributionStats::default(),
                packet_loss_rate: 0.0,
                retransmission_rate: 0.0,
                timeout_events: 0.0,
                retry_events: 0.0,
                throughput_mbps: ThroughputStats {
                    mean: 100.0,
                    p95: 100.0,
                    min: Some(100.0),
                },
                dns_failure_events: 0.0,
                tls_failure_events: 0.0,
                quic_blocked_ratio: 0.0,
                window_count: 0,
            },
            windows: Vec::new(),
            metric_provenance: Vec::new(),
        }
    }

    fn improving_what_if() -> WhatIfResult {
        WhatIfResult {
            action_id: "test".to_string(),
            action_notes: "test".to_string(),
            policy_action: None,
            topology: "test".to_string(),
            topology_snapshot: None,
            modified_topology_snapshot: None,
            baseline: BTreeMap::new(),
            proposed: BTreeMap::new(),
            delta: BTreeMap::from([
                ("latency_pct".to_string(), -10.0),
                ("loss_pct".to_string(), -5.0),
                ("throughput_pct".to_string(), 2.0),
            ]),
        }
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf()
    }

    #[test]
    fn validate_lab_report_accepts_normal_rule_label() {
        let scenario = scenario(FaultLabel::Normal, false);
        let report = report(
            "run-normal",
            vec![root(FaultLabel::Normal, 0.95)],
            FaultLabel::Normal,
            None,
        );

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: Vec::new(),
                artifact_keys: Vec::new(),
            },
        )
        .expect("acceptance");

        assert!(acceptance.passed, "{:?}", acceptance.failures);
        assert_eq!(acceptance.actual_rule_labels, vec!["normal"]);
    }

    #[test]
    fn validate_lab_report_rejects_synthetic_model_by_default() {
        let scenario = scenario(FaultLabel::Normal, false);
        let mut report = report(
            "run-normal",
            vec![root(FaultLabel::Normal, 0.95)],
            FaultLabel::Normal,
            None,
        );
        report.model_manifest = Some(model_manifest(true, None));

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: Vec::new(),
                artifact_keys: Vec::new(),
            },
        )
        .expect("acceptance");

        assert!(!acceptance.passed);
        assert!(acceptance.synthetic_model);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure.contains("synthetic fallback model")),
            "{:?}",
            acceptance.failures
        );
    }

    #[test]
    fn validate_lab_report_enforces_required_model_dataset_hash() {
        let mut scenario = scenario(FaultLabel::Normal, false);
        scenario.acceptance.required_model_dataset_hash = Some("expected-hash".to_string());
        let report = report(
            "run-normal",
            vec![root(FaultLabel::Normal, 0.95)],
            FaultLabel::Normal,
            None,
        );

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: Vec::new(),
                artifact_keys: Vec::new(),
            },
        )
        .expect("acceptance");

        assert!(!acceptance.passed);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure.contains("expected expected-hash")),
            "{:?}",
            acceptance.failures
        );
    }

    #[test]
    fn corroboration_can_raise_suspected_fault_without_silently_passing_acceptance() {
        let mut events = vec![diagnosis_event(FaultLabel::Normal, "rule", "rule")];
        let signals = vec![CorroborationSignal {
            source_kind: "prometheus-query".to_string(),
            signal: "latency high and throughput low".to_string(),
            supports: Some(FaultLabel::Congestion),
            contradicts: None,
            confidence_delta: 0.06,
        }];

        apply_corroboration_signals(&mut events, &signals);

        let suspected = events
            .iter()
            .find(|event| event.evidence.symptom == FaultLabel::Congestion)
            .expect("suspected congestion");
        assert_eq!(suspected.source, "corroboration");
        assert_eq!(suspected.evidence.method, "corroboration");

        let scenario = scenario(FaultLabel::Congestion, false);
        let mut report = report(
            "run-test",
            vec![RootCause {
                symptom: FaultLabel::Congestion.as_str().to_string(),
                severity: "low".to_string(),
                confidence: 0.56,
                why: "suspected".to_string(),
                source: "corroboration".to_string(),
                method: "corroboration".to_string(),
            }],
            FaultLabel::Congestion,
            None,
        );
        report.rule_vs_ml.agreement = true;
        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: Vec::new(),
                artifact_keys: Vec::new(),
            },
        )
        .expect("acceptance");
        assert!(!acceptance.passed);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure.contains("suspected fault")),
            "{:?}",
            acceptance.failures
        );
    }

    #[test]
    fn validate_lab_report_requires_what_if_when_gate_true() {
        let scenario = scenario(FaultLabel::Congestion, true);
        let report = report(
            "run-congestion",
            vec![root(FaultLabel::Congestion, 0.86)],
            FaultLabel::Congestion,
            None,
        );

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: Vec::new(),
                artifact_keys: Vec::new(),
            },
        )
        .expect("acceptance");

        assert!(!acceptance.passed);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure.contains("requires a what-if result")),
            "{:?}",
            acceptance.failures
        );
    }

    #[test]
    fn validate_lab_report_rejects_zero_what_if_improvement() {
        let scenario = scenario(FaultLabel::Congestion, true);
        let mut what_if = improving_what_if();
        for value in what_if.delta.values_mut() {
            *value = 0.0;
        }
        let report = report(
            "run-congestion",
            vec![root(FaultLabel::Congestion, 0.86)],
            FaultLabel::Congestion,
            Some(what_if),
        );

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: Vec::new(),
                artifact_keys: Vec::new(),
            },
        )
        .expect("acceptance");

        assert!(!acceptance.passed);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure.contains("did not improve")),
            "{:?}",
            acceptance.failures
        );
    }

    #[test]
    fn lab_run_index_resolves_validation_and_bundle_includes_lab_artifacts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let scenario_path = repo_root()
            .join("examples")
            .join("scenarios")
            .join("lab-congestion-001.yaml");

        let result = run_lab_scenario(
            &scenario_path,
            LabRunOptions {
                artifacts: temp.path().to_path_buf(),
            },
        )
        .expect("lab run");

        assert!(
            temp.path().join("lab_run_index.json").exists(),
            "lab_run_index.json missing"
        );
        let validation =
            validate_lab_run(temp.path(), &result.run_id, None).expect("indexed validate");
        assert!(validation.passed, "{:?}", validation.failures);
        assert!(
            temp.path()
                .join("model")
                .join(crate::ml::MODEL_MANIFEST_FILE_NAME)
                .exists(),
            "lab run should use the shared artifact model directory"
        );
        assert!(
            !PathBuf::from(&result.lab_run_dir).join("model").exists(),
            "lab run should not create a private model directory"
        );
        let evidence =
            crate::storage::run_evidence(temp.path(), &result.run_id).expect("indexed evidence");
        assert_eq!(evidence.report.run_id, result.run_id);

        let keys = result
            .evidence_bundle
            .files
            .iter()
            .map(|file| file.key.as_str())
            .collect::<BTreeSet<_>>();
        for expected in [
            "acceptance",
            "comparison",
            "multi_source_evidence",
            "lab_connector_health",
        ] {
            assert!(keys.contains(expected), "missing {expected}: {keys:?}");
        }

        let report =
            crate::storage::read_report(temp.path(), &result.run_id).expect("indexed report");
        let recommendation = report
            .recommendations
            .iter()
            .find(|recommendation| recommendation.diagnosis_symptom == Some(FaultLabel::Congestion))
            .expect("diagnosis recommendation");
        crate::storage::review_recommendation(
            temp.path(),
            &result.run_id,
            &recommendation.recommendation_id,
            HilState::Accepted,
            "confirmed lab label",
            "tester",
            Some(FaultLabel::Congestion),
        )
        .expect("indexed review");
        let feedback_output = temp.path().join("feedback.jsonl");
        let feedback = crate::ml::export_feedback_training_dataset(temp.path(), &feedback_output)
            .expect("feedback export");
        assert_eq!(feedback.rows, 1);
        let top_report: Report = serde_json::from_value(
            read_json(PathBuf::from(&result.lab_run_dir).join("report.json")).expect("top report"),
        )
        .expect("top report json");
        assert_eq!(top_report.hil_summary.accepted, 1);
    }

    #[test]
    fn lab_timestamp_uses_millis_and_uuid_suffix() {
        let now = Utc::now();
        let left = lab_timestamp(now);
        let right = lab_timestamp(now);
        assert_ne!(left, right);
        assert!(left.contains('.'), "{left}");
        assert!(left.rsplit_once('-').is_some(), "{left}");
    }

    #[test]
    fn lab_multisource_signals_enrich_diagnosis_artifacts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trace = repo_root()
            .join("data")
            .join("samples")
            .join("congestion.csv");
        let scenario_path = temp.path().join("scenario.yaml");
        std::fs::write(
            &scenario_path,
            format!(
                r#"schema: netdiag-lab-scenario/v1
id: lab-multisource-test
name: Multi source test
expected_label: congestion
data_sources:
  - name: primary
    role: primary
    kind: trace-file
    endpoint: "{}"
  - name: prometheus-like-corroborator
    role: corroborating
    kind: trace-file
    endpoint: "{}"
acceptance:
  expected_root_cause: congestion
  min_rule_confidence: 0.75
  min_ml_probability: 0.70
  require_rule_ml_agreement: true
  require_what_if_improvement: false
  allow_synthetic_model: true
"#,
                trace.display(),
                trace.display()
            ),
        )
        .expect("write scenario");

        let result = run_lab_scenario(
            &scenario_path,
            LabRunOptions {
                artifacts: temp.path().join("artifacts"),
            },
        )
        .expect("lab run");

        assert!(result.acceptance.passed, "{:?}", result.acceptance.failures);
        let report: Report = serde_json::from_value(
            read_json(PathBuf::from(&result.pipeline_run_dir).join("report.json"))
                .expect("report json"),
        )
        .expect("report");
        let multi = report.multi_source_evidence.expect("multi source evidence");
        assert!(
            multi
                .signals
                .iter()
                .any(|signal| signal.supports == Some(FaultLabel::Congestion)),
            "{:?}",
            multi.signals
        );
        let events: Vec<DiagnosisEvent> = serde_json::from_value(
            read_json(PathBuf::from(&result.pipeline_run_dir).join("diagnosis_events.json"))
                .expect("events json"),
        )
        .expect("events");
        let congestion = events
            .iter()
            .find(|event| event.evidence.symptom == FaultLabel::Congestion)
            .expect("congestion event");
        assert!(
            congestion
                .evidence
                .raw_evidence_refs
                .iter()
                .any(|reference| reference.artifact == "multi_source_evidence.json")
        );
        assert!(congestion.evidence.why.contains("Multi-source evidence"));
    }

    #[test]
    fn lab_multisource_summary_uses_final_diagnosis_after_corroboration() {
        let temp = tempfile::tempdir().expect("tempdir");
        let normal = repo_root().join("data").join("samples").join("normal.csv");
        let congestion = repo_root()
            .join("data")
            .join("samples")
            .join("congestion.csv");
        let scenario_path = temp.path().join("scenario.yaml");
        std::fs::write(
            &scenario_path,
            format!(
                r#"schema: netdiag-lab-scenario/v1
id: lab-suspected-corroboration-test
name: Suspected corroboration test
expected_label: congestion
data_sources:
  - name: primary-normal
    role: primary
    kind: trace-file
    endpoint: "{}"
  - name: corroborating-congestion
    role: corroborating
    kind: trace-file
    endpoint: "{}"
acceptance:
  expected_root_cause: congestion
  min_rule_confidence: 0.50
  min_ml_probability: 0.0
  require_rule_ml_agreement: false
  require_what_if_improvement: false
  allow_synthetic_model: true
  allow_suspected_corroboration: true
"#,
                normal.display(),
                congestion.display()
            ),
        )
        .expect("write scenario");

        let result = run_lab_scenario(
            &scenario_path,
            LabRunOptions {
                artifacts: temp.path().join("artifacts"),
            },
        )
        .expect("lab run");
        let report: Report = serde_json::from_value(
            read_json(PathBuf::from(&result.pipeline_run_dir).join("report.json"))
                .expect("report json"),
        )
        .expect("report");
        assert!(
            report
                .root_causes
                .iter()
                .any(|root| root.symptom == "congestion" && root.source == "corroboration"),
            "{:?}",
            report.root_causes
        );
        let multi = report.multi_source_evidence.expect("multi source evidence");
        assert!(
            multi
                .primary_evidence
                .iter()
                .any(|evidence| evidence.contains("congestion")),
            "{:?}",
            multi.primary_evidence
        );
    }

    #[test]
    fn static_preflight_parses_trace_file_schema() {
        let temp = tempfile::tempdir().expect("tempdir");
        let bad_trace = temp.path().join("bad.csv");
        std::fs::write(&bad_trace, "timestamp,latency_ms\nnot-a-time,10\n").expect("bad trace");
        let scenario_path = temp.path().join("scenario.yaml");
        std::fs::write(
            &scenario_path,
            format!(
                r#"schema: netdiag-lab-scenario/v1
id: lab-bad-trace-preflight
name: Bad trace preflight
expected_label: normal
data_sources:
  - role: primary
    kind: trace-file
    endpoint: "{}"
"#,
                bad_trace.display()
            ),
        )
        .expect("scenario");

        let report = preflight_lab_scenario(
            &scenario_path,
            LabPreflightOptions {
                artifacts: temp.path().join("artifacts"),
                mode: LabPreflightMode::Static,
            },
        )
        .expect("preflight report");

        assert!(!report.passed);
        assert!(
            report.checks.iter().any(|check| {
                check.name == "primary source reachable"
                    && check.status == LabPreflightCheckStatus::Failed
            }),
            "{:?}",
            report.checks
        );
    }

    #[test]
    fn static_preflight_fails_bad_corroborating_trace_file_schema() {
        let temp = tempfile::tempdir().expect("tempdir");
        let good_trace = temp.path().join("good.csv");
        std::fs::write(
            &good_trace,
            "timestamp,latency_ms,packet_loss_rate,retransmission_rate,throughput_mbps\n2026-04-30T12:00:00Z,10,0,0,100\n",
        )
        .expect("good trace");
        let bad_trace = temp.path().join("bad.csv");
        std::fs::write(
            &bad_trace,
            "timestamp,latency_ms,packet_loss_rate,retransmission_rate,throughput_mbps\n2026-04-30T12:00:00Z,-1,0,0,100\n",
        )
        .expect("bad trace");
        let scenario_path = temp.path().join("scenario.yaml");
        std::fs::write(
            &scenario_path,
            format!(
                r#"schema: netdiag-lab-scenario/v1
id: lab-bad-corroborating-trace-preflight
name: Bad corroborating trace preflight
expected_label: normal
data_sources:
  - role: primary
    kind: trace-file
    endpoint: "{}"
  - name: corroborating
    role: corroborating
    kind: trace-file
    endpoint: "{}"
"#,
                good_trace.display(),
                bad_trace.display()
            ),
        )
        .expect("scenario");

        let report = preflight_lab_scenario(
            &scenario_path,
            LabPreflightOptions {
                artifacts: temp.path().join("artifacts"),
                mode: LabPreflightMode::Static,
            },
        )
        .expect("preflight report");

        assert!(!report.passed);
        assert!(
            report.checks.iter().any(|check| {
                check.name == "corroborating reachable"
                    && check.required
                    && check.status == LabPreflightCheckStatus::Failed
            }),
            "{:?}",
            report.checks
        );
    }

    #[test]
    fn lab_batch_and_summary_use_lab_index() {
        let temp = tempfile::tempdir().expect("tempdir");
        let scenario_path = repo_root()
            .join("examples")
            .join("scenarios")
            .join("lab-congestion-001.yaml");

        let batch = run_lab_batch(
            &[scenario_path],
            LabRunOptions {
                artifacts: temp.path().to_path_buf(),
            },
        )
        .expect("batch");

        assert_eq!(batch.total_scenarios, 1);
        assert_eq!(batch.failed, 0, "{:?}", batch.results);
        let summary = summarize_lab_runs(temp.path()).expect("summary");
        assert_eq!(summary.total_runs, 1);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.by_label["congestion"].runs, 1);
        assert_eq!(summary.by_label["congestion"].rule_accuracy, 1.0);
        assert_eq!(summary.by_scenario["lab-congestion-001"].runs, 1);
        assert_eq!(
            summary.by_scenario["lab-congestion-001"].rule_ml_disagreement_rate,
            0.0
        );
    }
}
