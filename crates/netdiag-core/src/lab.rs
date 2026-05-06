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
use crate::ingest::ingest_trace;
use crate::models::{
    ConnectorHealthSnapshot, ConnectorHealthStatus, FaultLabel, IngestResult, MetricQuality,
    MultiSourceEvidenceSummary, RunComparison, SourceEvidenceSummary,
};
use crate::pipeline::{WhatIfRequest, diagnose_ingest_with_whatif};
use crate::report::Report;
use crate::storage::{
    connector_health_from_ingest, read_connector_health, read_json, run_artifacts, run_dir,
    save_json, write_connector_health,
};
use crate::twin::{
    TopologyFormat, import_policy_action, import_topology, policy_action,
    validate_policy_action_for_topology,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabRunOptions {
    pub artifacts: PathBuf,
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

#[derive(Debug, Clone)]
struct LoadedLabSource {
    source: LabDataSource,
    loaded: ConnectorLoadResult,
    health: ConnectorHealthSnapshot,
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
    let lab_run_dir = options
        .artifacts
        .join("lab-runs")
        .join(&scenario.id)
        .join(lab_timestamp(Utc::now()));
    fs::create_dir_all(&lab_run_dir).with_path(&lab_run_dir)?;

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

    let mut pipeline =
        diagnose_ingest_with_whatif(primary.loaded.ingest.clone(), &lab_run_dir, what_if.clone())?;
    let primary_health = primary.health.clone();
    write_connector_health(&lab_run_dir, &pipeline.run_id, &primary_health)?;
    let connector_health = loaded_sources
        .iter()
        .map(|source| source.health.clone())
        .collect::<Vec<_>>();
    let multi_source_evidence = multi_source_evidence(
        &scenario,
        &pipeline.report,
        &loaded_sources,
        &primary_health,
    );
    pipeline.report.multi_source_evidence = Some(multi_source_evidence.clone());
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
        &[EvidenceBundleExtraFile {
            key: "scenario".to_string(),
            path: scenario_copy,
            zip_path: "scenario.yaml".to_string(),
        }],
    )?;
    save_json(lab_run_dir.join("evidence_bundle.json"), &evidence_bundle)?;

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

pub fn validate_lab_run(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    scenario_path: impl AsRef<Path>,
) -> Result<LabAcceptanceReport> {
    let scenario = load_lab_scenario(scenario_path)?;
    let artifact_root = artifact_root.as_ref();
    let report: Report = serde_json::from_value(read_json(
        run_dir(artifact_root, run_id).join("report.json"),
    )?)?;
    validate_lab_report(
        &scenario,
        &report,
        &LabValidationContext {
            connector_health: read_lab_connector_health(artifact_root, run_id)?,
            artifact_keys: run_artifacts(artifact_root, run_id)?
                .into_iter()
                .filter(|artifact| artifact.exists)
                .map(|artifact| artifact.key)
                .collect(),
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
    if expected == FaultLabel::Normal {
        if !rule_labels.is_empty() {
            failures.push(format!(
                "expected normal but rule labels were {}",
                rule_labels.join(", ")
            ));
        }
    } else {
        let expected_label = expected.as_str();
        let matching = report
            .root_causes
            .iter()
            .find(|root| root.symptom == expected_label);
        if let Some(root) = matching {
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
    if scenario.acceptance.require_what_if_improvement
        && let Some(what_if) = &report.what_if
    {
        for (metric, should_be_positive) in [
            ("latency_pct", false),
            ("loss_pct", false),
            ("throughput_pct", true),
        ] {
            let delta = what_if.delta.get(metric).copied().unwrap_or(0.0);
            if should_be_positive && delta < 0.0 {
                failures.push(format!("what-if {metric} worsened by {delta:.2}%"));
            }
            if !should_be_positive && delta > 0.0 {
                failures.push(format!("what-if {metric} worsened by {delta:.2}%"));
            }
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
        quality_status,
        passed: failures.is_empty(),
        failures,
    })
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
    let topology_ref = resolve_path(base_dir, &what_if.topology);
    let topology = if topology_ref.exists() {
        let raw = fs::read_to_string(&topology_ref).with_path(&topology_ref)?;
        import_topology(&raw, format_for_path(&topology_ref))?
    } else {
        crate::twin::topology_model(&what_if.topology)?
    };
    let policy_ref = resolve_path(base_dir, &what_if.policy);
    let action = if policy_ref.exists() {
        let raw = fs::read_to_string(&policy_ref).with_path(&policy_ref)?;
        import_policy_action(&raw, format_for_path(&policy_ref))?
    } else {
        policy_action(&what_if.policy)?
    };
    validate_policy_action_for_topology(&action, &topology)?;
    Ok(WhatIfRequest { topology, action })
}

fn multi_source_evidence(
    scenario: &LabScenario,
    report: &Report,
    loaded_sources: &[LoadedLabSource],
    primary_health: &ConnectorHealthSnapshot,
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
    let primary = source_summary("primary", primary_health, primary_ingest);
    let corroborating_sources = loaded_sources
        .iter()
        .filter(|source| source.source.role == LabDataSourceRole::Corroborating)
        .map(|source| source_summary("corroborating", &source.health, &source.loaded.ingest))
        .collect::<Vec<_>>();
    let corroborating_evidence = corroborating_sources
        .iter()
        .flat_map(|source| source.signals.clone())
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
        .collect::<Vec<_>>();
    MultiSourceEvidenceSummary {
        root_cause: expected,
        primary_evidence,
        corroborating_evidence,
        counter_evidence,
        primary,
        corroborating_sources,
    }
}

fn source_summary(
    role: &str,
    health: &ConnectorHealthSnapshot,
    ingest: &IngestResult,
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
    timestamp.format("%Y%m%dT%H%M%SZ").to_string()
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
