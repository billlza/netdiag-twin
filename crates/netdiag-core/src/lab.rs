use crate::connectors::authentication::{BearerEnvironmentBindings, ResolvedBearerTokens};
use crate::connectors::{
    ConnectorLoadResult, ConnectorResourceUsage, HttpJsonConfig, NativePcapConfig,
    NativePcapSource, OtlpGrpcReceiverConfig, PrometheusExpositionConfig,
    PrometheusQueryRangeConfig, SystemCountersConfig, default_prometheus_mapping, load_http_json,
    load_native_pcap, load_otlp_grpc_receiver, load_prometheus_exposition,
    load_prometheus_mapping_file, load_prometheus_query_range, load_system_counters,
    parse_http_endpoint,
};
use crate::error::{IoContext, NetdiagError, Result};
use crate::evidence_bundle::{
    EvidenceBundleManifest, EvidenceContext, export_evidence_bundle_from_staged_directory,
};
use crate::ingest::{CANONICAL_COLUMNS, ingest_trace, ingest_trace_with_usage};
use crate::ml::{
    load_existing_model_bundle_snapshot, load_existing_model_bundle_snapshot_if_present,
};
use crate::models::{
    ActionVerification, ConnectorHealthSnapshot, ConnectorHealthStatus, CorroborationDecision,
    CorroborationSignal, DiagnosisEvent, DiagnosisStatus, EvidenceRecord, EvidenceRef, FaultLabel,
    HilState, IngestResult, MetricQuality, MultiSourceEvidenceSummary, RunComparison, Severity,
    SourceEvidenceSummary, TimeWindow,
};
use crate::pipeline::{
    WhatIfRequest,
    diagnose_ingest_with_nested_artifact_root_and_model_snapshot_and_connector_health,
    ensure_run_directory_publication_supported,
};
use crate::recommendation::recommend_actions;
use crate::report::{
    Report, compare_rule_ml, decide_diagnosis, refresh_report_evidence_timeline, render_report,
};
use crate::resource_limits::{
    MAX_SCENARIO_RECORDS, MAX_SCENARIO_RETAINED_BYTES, MAX_SOURCE_INPUT_BYTES, MAX_SOURCE_RECORDS,
};
use crate::storage::typed_json::{
    MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES, MAX_LAB_ACCEPTANCE_BYTES, MAX_LAB_COMPARISON_BYTES,
    MAX_LAB_CONNECTOR_HEALTH_BYTES, MAX_RUN_REPORT_BYTES, read_optional_stable_json_bounded,
    save_json_atomic_bounded,
};
use crate::storage::{
    ArtifactRootCapability, PathStatus, StagedAtomicDirectory, compare_runs,
    create_root_bound_staged_directory, ensure_artifact_root_owned,
    finish_root_bound_staged_directory, path_status, prepare_artifact_root, read_connector_health,
    read_report, resolve_stored_path, run_artifacts, run_artifacts_allow_pending, run_dir,
    save_json, with_artifact_root_capability,
};
use crate::twin::{
    load_policy_action_file, load_topology_file, policy_action, topology_model,
    validate_policy_action_for_topology, validate_policy_action_shape, validate_topology_model,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

const MAX_RUN_ID_FILE_BYTES: usize = 128;

#[cfg(test)]
use crate::evidence_bundle::export_evidence_bundle_with_context;
#[cfg(test)]
use crate::models::{ActionVerificationVerdict, RunManifest, TwinPolicyImpact};
#[cfg(test)]
use crate::storage::read_json;

mod action_verification;
mod action_verification_artifact;
mod bearer;
mod calibration;
mod defaults;
mod evidence_identity;
mod index_contract;
mod index_path;
mod index_update;
mod index_validation;
mod review_sync;
mod run_preparation;
mod scenario_input;
mod source_signal_metrics;
mod summary;
use source_signal_metrics::{
    SourceSignalMetrics, metric_is_trustworthy, metrics_are_trustworthy, source_signal_metrics,
};
mod verification_objective;
use action_verification::{
    action_verification_verdict, observed_delta_pct_map, predicted_action_effect,
    predicted_delta_pct_map, prediction_error_pct_map,
};
use action_verification_artifact::record_action_verification_artifact;
pub use calibration::{
    LabCalibrationDistribution, LabCalibrationHotspot, LabCalibrationLabelStats,
    LabCalibrationOodStats, LabCalibrationReport, calibrate_lab_uncertainty,
};
use defaults::{
    default_allowed_connector_status, default_allowed_diagnosis_statuses, default_interval_secs,
    default_lookback_secs, default_min_ml_probability, default_min_rule_confidence,
    default_packet_limit, default_required_artifacts, default_step_secs, default_timeout_secs,
    default_true,
};
use index_path::stored_lab_index_path;
use index_update::update_lab_run_index_owned;
#[cfg(test)]
use index_update::{update_lab_run_index, update_lab_run_index_passed};
pub use index_validation::read_lab_run_index;
pub(crate) use index_validation::validate_legacy_run_index_artifacts;
pub(crate) use review_sync::{
    LabReviewArtifactPlan, plan_lab_review_artifacts, preflight_lab_review_artifacts,
};
use run_preparation::{
    LabArtifactRootAuthorization, PreparedLabInputs, prepare as prepare_lab_inputs,
};
use scenario_input::{LabScenarioSnapshot, load_lab_scenario_snapshot};
pub use scenario_input::{load_lab_scenario, validate_lab_scenario};
pub use summary::summarize_lab_runs;
use verification_objective::read as read_verification_objective;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabScenario {
    pub schema: String,
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_label: Option<FaultLabel>,
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
    #[serde(default, skip_serializing_if = "LabVerification::is_empty")]
    pub verification: LabVerification,
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
    pub bearer_token_env: Option<String>,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabVerification {
    #[serde(default)]
    pub objective: BTreeMap<String, String>,
    #[serde(default)]
    pub fail_if: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct ActionVerificationOptions {
    pub recommendation_id: Option<String>,
    pub policy_path: Option<PathBuf>,
    pub objective_path: Option<PathBuf>,
}

impl LabVerification {
    fn is_empty(&self) -> bool {
        self.objective.is_empty() && self.fail_if.is_empty()
    }
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
    #[serde(default = "default_allowed_diagnosis_statuses")]
    pub allowed_diagnosis_statuses: Vec<DiagnosisStatus>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_model_manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_model_file_hash: Option<String>,
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
            allowed_diagnosis_statuses: default_allowed_diagnosis_statuses(),
            require_rule_ml_agreement: true,
            require_what_if_improvement: true,
            required_artifacts: default_required_artifacts(),
            allow_synthetic_model: false,
            required_model_dataset_hash: None,
            required_model_manifest_hash: None,
            required_model_file_hash: None,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabValidationContext {
    #[serde(default)]
    pub connector_health: Vec<ConnectorHealthSnapshot>,
    #[serde(default)]
    pub artifact_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_file_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabAcceptanceReport {
    pub schema: String,
    pub scenario_id: String,
    pub run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_label: Option<FaultLabel>,
    #[serde(default)]
    pub actual_rule_labels: Vec<String>,
    pub actual_ml_top: String,
    pub actual_ml_probability: f64,
    #[serde(default)]
    pub actual_diagnosis_status: DiagnosisStatus,
    #[serde(default)]
    pub synthetic_model: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_dataset_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_file_hash: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_label: Option<FaultLabel>,
    #[serde(default)]
    pub actual_rule_labels: Vec<String>,
    pub actual_ml_top: String,
    #[serde(default)]
    pub diagnosis_status: DiagnosisStatus,
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
    pub diagnosis_statuses: BTreeMap<String, usize>,
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

#[derive(Debug, Default, PartialEq, Eq)]
struct LabRetainedResourceBudget {
    input_bytes: u64,
    records: usize,
}

impl LabRetainedResourceBudget {
    fn reserve(&mut self, source: &str, usage: ConnectorResourceUsage) -> Result<()> {
        if usage.input_bytes > MAX_SOURCE_INPUT_BYTES {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab source {source} input size {} exceeds the {MAX_SOURCE_INPUT_BYTES}-byte source limit",
                usage.input_bytes
            )));
        }
        if usage.records > MAX_SOURCE_RECORDS {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab source {source} record count {} exceeds the {MAX_SOURCE_RECORDS}-record source limit",
                usage.records
            )));
        }
        let input_bytes = self
            .input_bytes
            .checked_add(usage.input_bytes)
            .ok_or_else(|| {
                NetdiagError::InvalidTrace("lab retained input byte count overflowed".to_string())
            })?;
        let records = self.records.checked_add(usage.records).ok_or_else(|| {
            NetdiagError::InvalidTrace("lab retained record count overflowed".to_string())
        })?;
        if input_bytes > MAX_SCENARIO_RETAINED_BYTES {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab retained input size {input_bytes} exceeds the {MAX_SCENARIO_RETAINED_BYTES}-byte scenario limit after source {source}"
            )));
        }
        if records > MAX_SCENARIO_RECORDS {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab retained record count {records} exceeds the {MAX_SCENARIO_RECORDS}-record scenario limit after source {source}"
            )));
        }
        self.input_bytes = input_bytes;
        self.records = records;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct LabRunResolution {
    artifact_root: PathBuf,
    index_entry: Option<LabRunIndexEntry>,
}

fn scenario_expected_label(scenario: &LabScenario) -> Option<FaultLabel> {
    scenario
        .acceptance
        .expected_root_cause
        .or(scenario.expected_label)
}

pub fn preflight_lab_scenario(
    path: impl AsRef<Path>,
    options: LabPreflightOptions,
) -> Result<LabPreflightReport> {
    preflight_lab_scenario_with_bearer_bindings(
        path,
        options,
        &BearerEnvironmentBindings::default(),
    )
}

pub fn preflight_lab_scenario_with_bearer_bindings(
    path: impl AsRef<Path>,
    options: LabPreflightOptions,
    bindings: &BearerEnvironmentBindings,
) -> Result<LabPreflightReport> {
    let scenario_path = path.as_ref();
    let fallback_id = scenario_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("lab-scenario")
        .to_string();
    let mut checks = Vec::new();
    let scenario = match load_lab_scenario(scenario_path) {
        Ok(scenario) => {
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

    let declarations = bearer::declarations(&scenario)?;
    let resolved_tokens = match options.mode {
        LabPreflightMode::Static => bindings
            .validate_exact_declarations(&declarations)
            .map(|()| ResolvedBearerTokens::default()),
        LabPreflightMode::Live => bindings.resolve_all(&declarations),
    };
    let resolved_tokens = match resolved_tokens {
        Ok(resolved_tokens) => {
            checks.push(preflight_pass(
                "bearer environment bindings valid",
                true,
                format!(
                    "{} bearer declaration(s) exactly matched external bindings",
                    declarations.len()
                ),
            ));
            resolved_tokens
        }
        Err(error) => {
            checks.push(preflight_fail(
                "bearer environment bindings valid",
                true,
                error.to_string(),
            ));
            return Ok(preflight_report(scenario.id, options.mode, checks));
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
        &resolved_tokens,
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
            ensure_artifact_root_owned(artifact_root)?;
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
    resolved_tokens: &ResolvedBearerTokens,
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
                LabPreflightMode::Live => {
                    check_source_reachable(source, scenario, scenario_dir, resolved_tokens)
                }
            };
            preflight_check(name, true, result)
        })
        .collect()
}

fn check_source_static(source: &LabDataSource, scenario_dir: &Path) -> Result<String> {
    bearer::declaration(source)?;
    match source.kind {
        LabDataSourceKind::TraceFile => {
            let path = resolve_path(scenario_dir, &source.endpoint);
            if path_status(&path)? != PathStatus::RegularFile {
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
        LabDataSourceKind::NativePcap => {
            match native_pcap_source(&source.endpoint, scenario_dir)? {
                NativePcapSource::File(path) => {
                    if path_status(&path)? == PathStatus::RegularFile {
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
            }
        }
        LabDataSourceKind::OtlpGrpc => {
            let bind_addr =
                crate::connectors::parse_loopback_bind_addr(&source.endpoint).map_err(|_| {
                    NetdiagError::InvalidTrace(
                        "OTLP bind address must be a valid loopback host:port value".to_string(),
                    )
                })?;
            Ok(format!("OTLP loopback bind address valid: {bind_addr}"))
        }
        LabDataSourceKind::SystemCounters => Ok(if source.endpoint.trim().is_empty() {
            "system counters will sample all interfaces".to_string()
        } else {
            format!("system counters interface configured: {}", source.endpoint)
        }),
    }
}

fn validate_http_endpoint(endpoint: &str) -> Result<()> {
    parse_http_endpoint(endpoint)
        .map(drop)
        .map_err(|error| NetdiagError::InvalidTrace(error.to_string()))
}

fn check_source_reachable(
    source: &LabDataSource,
    scenario: &LabScenario,
    scenario_dir: &Path,
    resolved_tokens: &ResolvedBearerTokens,
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
            let loaded = load_http_json(
                &HttpJsonConfig {
                    endpoint: source.endpoint.clone(),
                    timeout: Duration::from_secs(scenario.collection.timeout_secs),
                },
                bearer::token_for_source(source, resolved_tokens)?,
            )?;
            Ok(format!(
                "{} rows returned by HTTP/JSON",
                loaded.ingest.schema.rows
            ))
        }
        LabDataSourceKind::PrometheusQuery => {
            let loaded = load_prometheus_query_range(
                &PrometheusQueryRangeConfig {
                    base_url: source.endpoint.clone(),
                    timeout: Duration::from_secs(scenario.collection.timeout_secs),
                    lookback_seconds: scenario.collection.lookback_secs,
                    step_seconds: scenario.collection.step_secs,
                    queries: lab_mapping(source, scenario_dir)?,
                    sample: scenario.id.clone(),
                },
                bearer::token_for_source(source, resolved_tokens)?,
            )?;
            Ok(format!(
                "Prometheus returned {} canonical rows",
                loaded.ingest.schema.rows
            ))
        }
        LabDataSourceKind::PrometheusMetrics => {
            let loaded = load_prometheus_exposition(
                &PrometheusExpositionConfig {
                    endpoint: source.endpoint.clone(),
                    timeout: Duration::from_secs(scenario.collection.timeout_secs),
                    metrics: lab_mapping(source, scenario_dir)?,
                    sample: scenario.id.clone(),
                },
                bearer::token_for_source(source, resolved_tokens)?,
            )?;
            Ok(format!(
                "Prometheus exposition returned {} canonical rows",
                loaded.ingest.schema.rows
            ))
        }
        LabDataSourceKind::NativePcap => {
            match native_pcap_source(&source.endpoint, scenario_dir)? {
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
            }
        }
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
                interval: Duration::from_secs(scenario.collection.interval_secs),
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
    run_lab_scenario_with_bearer_bindings(path, options, &BearerEnvironmentBindings::default())
}

pub fn run_lab_scenario_with_bearer_bindings(
    path: impl AsRef<Path>,
    options: LabRunOptions,
    bindings: &BearerEnvironmentBindings,
) -> Result<LabRunResult> {
    ensure_run_directory_publication_supported(&options.artifacts)?;
    let scenario_path = path.as_ref();
    let snapshot = load_lab_scenario_snapshot(scenario_path)?;
    let declarations = bearer::declarations(snapshot.scenario())?;
    let resolved_tokens = bindings.resolve_all(&declarations)?;
    let prepared = prepare_lab_inputs(scenario_path, snapshot, &resolved_tokens)?;
    let capability = prepare_artifact_root(&options.artifacts)?;
    run_prepared_lab_scenario(prepared, options, &capability)
}

fn run_prepared_lab_scenario(
    prepared: PreparedLabInputs,
    options: LabRunOptions,
    capability: &ArtifactRootCapability,
) -> Result<LabRunResult> {
    let PreparedLabInputs {
        snapshot,
        what_if,
        loaded_sources,
    } = prepared;
    let model_dir = options.artifacts.join("model");
    let model_snapshot = with_artifact_root_capability(capability, |_| {
        load_existing_model_bundle_snapshot(&model_dir)
    })?;

    let created_at = Utc::now();
    let relative_parent = Path::new("lab-runs").join(&snapshot.scenario().id);
    let mut staged = with_artifact_root_capability(capability, |owned| {
        create_root_bound_staged_directory(
            owned,
            &relative_parent,
            lab_timestamp(created_at).into(),
            "lab run staging failed",
        )
    })?;
    let staged_lab_run_dir = staged.staging_path().to_path_buf();
    let published_lab_run_dir = staged.target_path().to_path_buf();
    let operation = (|| {
        let staged_scenario_copy = staged_lab_run_dir.join("scenario.yaml");
        snapshot.publish_to(&staged_scenario_copy)?;
        let scenario = snapshot.into_scenario();
        let primary = loaded_sources
            .iter()
            .find(|source| source.source.role == LabDataSourceRole::Primary)
            .ok_or_else(|| NetdiagError::InvalidTrace("missing primary source".to_string()))?;

        let primary_health = primary.health.clone();
        let mut pipeline =
            diagnose_ingest_with_nested_artifact_root_and_model_snapshot_and_connector_health(
                primary.loaded.ingest.clone(),
                &staged,
                &model_snapshot,
                what_if.clone(),
                primary_health.clone(),
            )?;
        let connector_health = loaded_sources
            .iter()
            .map(|source| source.health.clone())
            .collect::<Vec<_>>();
        let corroboration_signals = collect_corroboration_signals(&loaded_sources);
        apply_corroboration_signals(&mut pipeline.diagnosis_events, &corroboration_signals);
        pipeline.comparison = compare_rule_ml(&pipeline.diagnosis_events, &pipeline.ml_result);
        let diagnosis_decision = decide_diagnosis(&pipeline.diagnosis_events, &pipeline.ml_result);
        pipeline.recommendations = recommend_actions(
            &pipeline.diagnosis_events,
            pipeline.what_if.as_ref(),
            &diagnosis_decision,
        );
        pipeline.report = render_report(
            &pipeline.run_id,
            &pipeline.telemetry,
            &pipeline.diagnosis_events,
            &pipeline.ml_result,
            &diagnosis_decision,
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
        refresh_report_evidence_timeline(&mut pipeline.report);
        save_json(
            run_dir(&staged_lab_run_dir, &pipeline.run_id)?.join("diagnosis_events.json"),
            &pipeline.diagnosis_events,
        )?;
        save_json(
            run_dir(&staged_lab_run_dir, &pipeline.run_id)?.join("recommendations.json"),
            &pipeline.recommendations,
        )?;
        save_json_atomic_bounded(
            run_dir(&staged_lab_run_dir, &pipeline.run_id)?.join("report.json"),
            &pipeline.report,
            MAX_RUN_REPORT_BYTES,
            "run report",
        )?;

        let validation_context = LabValidationContext {
            connector_health: connector_health.clone(),
            artifact_keys: run_artifacts(&staged_lab_run_dir, &pipeline.run_id)?
                .into_iter()
                .filter(|artifact| artifact.exists)
                .map(|artifact| artifact.key)
                .collect(),
            model_manifest_hash: pipeline.report.model_manifest_hash.clone(),
            model_file_hash: pipeline.report.model_file_hash.clone(),
        };
        let acceptance = validate_lab_report(&scenario, &pipeline.report, &validation_context)?;
        persist_lab_run_id(&mut staged, &pipeline.run_id)?;
        let comparison = lab_run_comparison(&scenario, &pipeline.report, &acceptance, None);

        save_json_atomic_bounded(
            staged_lab_run_dir.join("connector_health.json"),
            &connector_health,
            MAX_LAB_CONNECTOR_HEALTH_BYTES,
            "lab connector health",
        )?;
        save_json_atomic_bounded(
            staged_lab_run_dir.join("report.json"),
            &pipeline.report,
            MAX_RUN_REPORT_BYTES,
            "lab report",
        )?;
        save_json(
            staged_lab_run_dir.join("multi_source_evidence.json"),
            &multi_source_evidence,
        )?;
        save_json_atomic_bounded(
            staged_lab_run_dir.join("comparison.json"),
            &comparison,
            MAX_LAB_COMPARISON_BYTES,
            "lab run comparison",
        )?;
        save_json_atomic_bounded(
            staged_lab_run_dir.join("acceptance.json"),
            &acceptance,
            MAX_LAB_ACCEPTANCE_BYTES,
            "lab acceptance report",
        )?;

        let archive_name = format!("netdiag-evidence-{}.zip", pipeline.run_id);
        let evidence_bundle = export_evidence_bundle_from_staged_directory(
            &staged_lab_run_dir,
            &published_lab_run_dir,
            &pipeline.run_id,
            &staged_lab_run_dir.join(&archive_name),
            &published_lab_run_dir.join(archive_name),
            EvidenceContext::Lab,
            &[],
        )?;
        save_json_atomic_bounded(
            staged_lab_run_dir.join("evidence_bundle.json"),
            &evidence_bundle,
            MAX_EVIDENCE_BUNDLE_MANIFEST_BYTES,
            "evidence bundle manifest",
        )?;
        let published_pipeline_run_dir = run_dir(&published_lab_run_dir, &pipeline.run_id)?;
        let index_entry = LabRunIndexEntry {
            run_id: pipeline.run_id.clone(),
            scenario_id: scenario.id.clone(),
            scenario_name: scenario.name.clone(),
            created_at,
            lab_run_dir: stored_lab_index_path(&options.artifacts, &published_lab_run_dir)?,
            pipeline_run_dir: stored_lab_index_path(
                &options.artifacts,
                &published_pipeline_run_dir,
            )?,
            acceptance_path: stored_lab_index_path(
                &options.artifacts,
                &published_lab_run_dir.join("acceptance.json"),
            )?,
            comparison_path: stored_lab_index_path(
                &options.artifacts,
                &published_lab_run_dir.join("comparison.json"),
            )?,
            scenario_path: stored_lab_index_path(
                &options.artifacts,
                &published_lab_run_dir.join("scenario.yaml"),
            )?,
            passed: acceptance.passed,
        };
        let result = LabRunResult {
            schema: "netdiag-lab-run/v1".to_string(),
            scenario_id: scenario.id,
            scenario_name: scenario.name,
            run_id: pipeline.run_id,
            lab_run_dir: published_lab_run_dir.display().to_string(),
            pipeline_run_dir: published_pipeline_run_dir.display().to_string(),
            acceptance,
            comparison,
            evidence_bundle,
        };
        Ok((result, index_entry))
    })();
    let ((result, _), _) = finish_root_bound_staged_directory(
        capability,
        staged,
        operation,
        |owned, (_, index_entry), _| update_lab_run_index_owned(owned, index_entry.clone()),
    )?;
    Ok(result)
}

fn persist_lab_run_id(staged: &mut StagedAtomicDirectory, run_id: &str) -> Result<()> {
    if run_id.len() > MAX_RUN_ID_FILE_BYTES {
        return Err(NetdiagError::InvalidTrace(format!(
            "lab run id exceeds the {MAX_RUN_ID_FILE_BYTES}-byte persistence limit"
        )));
    }
    staged
        .write_file("run_id.txt", "txt", |file, path| {
            file.write_all(run_id.as_bytes()).with_path(path)
        })
        .map(drop)
}

pub fn run_lab_batch(scenarios: &[PathBuf], options: LabRunOptions) -> Result<LabBatchReport> {
    run_lab_batch_with_bearer_bindings(scenarios, options, &BearerEnvironmentBindings::default())
}

pub fn run_lab_batch_with_bearer_bindings(
    scenarios: &[PathBuf],
    options: LabRunOptions,
    bindings: &BearerEnvironmentBindings,
) -> Result<LabBatchReport> {
    ensure_run_directory_publication_supported(&options.artifacts)?;
    let mut declared = BTreeSet::new();
    let mut snapshots = Vec::with_capacity(scenarios.len());
    for scenario_path in scenarios {
        let snapshot = load_lab_scenario_snapshot(scenario_path);
        if let Ok(snapshot) = &snapshot {
            declared.extend(bearer::declarations(snapshot.scenario())?);
        }
        snapshots.push(snapshot);
    }
    let declarations = declared.into_iter().collect::<Vec<_>>();
    let resolved_tokens = bindings.resolve_all(&declarations)?;
    let mut authorization = LabArtifactRootAuthorization::Unclaimed;
    let mut results = Vec::new();
    for (scenario_path, snapshot) in scenarios.iter().zip(snapshots) {
        let (scenario_id, run_result) = match snapshot {
            Ok(snapshot) => {
                let scenario_id = Some(snapshot.scenario().id.clone());
                let result = prepare_lab_inputs(scenario_path, snapshot, &resolved_tokens)
                    .and_then(|prepared| {
                        let capability = authorization.claim(&options.artifacts)?;
                        run_prepared_lab_scenario(
                            prepared,
                            LabRunOptions {
                                artifacts: options.artifacts.clone(),
                            },
                            capability,
                        )
                    });
                (scenario_id, result)
            }
            Err(error) => (None, Err(error)),
        };
        match run_result {
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

fn round4(value: f64) -> f64 {
    crate::twin::round_decimal(value, 10_000.0)
}

pub fn validate_lab_run(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    scenario_path: Option<&Path>,
) -> Result<LabAcceptanceReport> {
    let input_root = artifact_root.as_ref();
    let resolution = resolve_lab_run_artifact_root(input_root, run_id)?;
    let indexed_scenario_path = resolution
        .index_entry
        .as_ref()
        .map(|entry| resolve_stored_path(input_root, &entry.scenario_path))
        .transpose()?;
    let default_scenario_path = resolution.artifact_root.join("scenario.yaml");
    let discovered_scenario_path = path_status(&default_scenario_path)?
        .exists()
        .then_some(default_scenario_path);
    let scenario_path = scenario_path
        .map(Path::to_path_buf)
        .or(indexed_scenario_path)
        .or(discovered_scenario_path)
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "lab scenario path is required because run {run_id} has no indexed scenario"
            ))
        })?;
    let scenario = load_lab_scenario(&scenario_path)?;
    let artifact_root = resolution.artifact_root;
    let report = read_report(&artifact_root, run_id)?;
    let (model_manifest_hash, model_file_hash) = lab_model_hashes(input_root, &report)?;
    validate_lab_report(
        &scenario,
        &report,
        &LabValidationContext {
            connector_health: read_lab_connector_health(&artifact_root, run_id)?,
            artifact_keys: lab_artifact_keys(&artifact_root, run_id)?,
            model_manifest_hash,
            model_file_hash,
        },
    )
}

pub fn verify_action(
    artifact_root: impl AsRef<Path>,
    before_run_id: &str,
    after_run_id: &str,
    recommendation_id: Option<&str>,
) -> Result<ActionVerification> {
    verify_action_with_options(
        artifact_root,
        before_run_id,
        after_run_id,
        ActionVerificationOptions {
            recommendation_id: recommendation_id.map(str::to_string),
            policy_path: None,
            objective_path: None,
        },
    )
}

pub fn verify_action_with_options(
    artifact_root: impl AsRef<Path>,
    before_run_id: &str,
    after_run_id: &str,
    options: ActionVerificationOptions,
) -> Result<ActionVerification> {
    let artifact_root = artifact_root.as_ref();
    let comparison = compare_runs(artifact_root, before_run_id, after_run_id)?;
    let before_location = crate::storage::resolve_run_location(artifact_root, before_run_id)?;
    let before_report = read_report(artifact_root, before_run_id)?;
    let predicted_what_if_effect = if let Some(policy_path) = options.policy_path.as_deref() {
        Some(read_policy_from_path(policy_path)?.impact)
    } else {
        predicted_action_effect(&before_report, options.recommendation_id.as_deref())?
    };
    let verification_policy = if let Some(objective_path) = options.objective_path.as_deref() {
        Some(read_verification_objective(objective_path)?)
    } else {
        verification_policy_for_run(artifact_root, before_run_id)?
    };
    let predicted_deltas_pct = predicted_delta_pct_map(predicted_what_if_effect.as_ref())?;
    let observed_deltas_pct = observed_delta_pct_map(&comparison)?;
    let prediction_error_pct =
        prediction_error_pct_map(&predicted_deltas_pct, &observed_deltas_pct)?;
    let (verdict, reasons) = action_verification_verdict(
        &comparison,
        verification_policy.as_ref(),
        &predicted_deltas_pct,
        &observed_deltas_pct,
    );
    let verification = ActionVerification {
        schema: "netdiag-action-verification/v1".to_string(),
        generated_at: Utc::now(),
        before_run_id: before_run_id.to_string(),
        after_run_id: after_run_id.to_string(),
        recommendation_id: options.recommendation_id,
        predicted_what_if_effect,
        predicted_deltas_pct,
        observed_deltas_pct,
        prediction_error_pct,
        objective: verification_policy
            .as_ref()
            .map(|policy| policy.objective.clone())
            .unwrap_or_default(),
        fail_if: verification_policy
            .as_ref()
            .map(|policy| policy.fail_if.clone())
            .unwrap_or_default(),
        observed_comparison: comparison,
        verdict,
        reasons,
    };
    record_action_verification_artifact(&before_location.run_dir, after_run_id, &verification)?;
    Ok(verification)
}

fn read_policy_from_path(path: &Path) -> Result<crate::models::TwinPolicyAction> {
    load_policy_action_file(path)
}

fn verification_policy_for_run(
    artifact_root: &Path,
    before_run_id: &str,
) -> Result<Option<LabVerification>> {
    let resolution = match resolve_lab_run_artifact_root(artifact_root, before_run_id) {
        Ok(resolution) => resolution,
        Err(error) => match run_has_non_lab_context(artifact_root, before_run_id) {
            Ok(true) => return Ok(None),
            Ok(false) => return Err(error),
            Err(context_resolution) => {
                return Err(NetdiagError::LabContextResolution {
                    run_id: before_run_id.to_string(),
                    lab_resolution: Box::new(error),
                    context_resolution: Box::new(context_resolution),
                });
            }
        },
    };
    let indexed_scenario_path = resolution
        .index_entry
        .as_ref()
        .map(|entry| resolve_stored_path(artifact_root, &entry.scenario_path))
        .transpose()?;
    let scenario_path = if indexed_scenario_path.is_some() {
        indexed_scenario_path
    } else {
        let candidate = resolution.artifact_root.join("scenario.yaml");
        regular_file_exists(&candidate, "lab scenario")?.then_some(candidate)
    };
    let Some(scenario_path) = scenario_path else {
        if resolution.index_entry.is_none() && resolution.artifact_root == artifact_root {
            return Ok(None);
        }
        if run_has_non_lab_context(artifact_root, before_run_id)? {
            return Ok(None);
        }
        return Err(NetdiagError::InvalidTrace(format!(
            "lab run {before_run_id} is missing its scenario verification policy"
        )));
    };
    let scenario = load_lab_scenario(scenario_path)?;
    Ok((!scenario.verification.is_empty()).then_some(scenario.verification))
}

fn run_has_non_lab_context(artifact_root: &Path, run_id: &str) -> Result<bool> {
    let location = crate::storage::resolve_run_location(artifact_root, run_id)?;
    let Some(run_context) = location.lab_run_dir else {
        return Ok(true);
    };
    let pilot_manifest = run_context.join("pilot.yaml");
    regular_file_exists(&pilot_manifest, "pilot run marker")
}

fn regular_file_exists(path: &Path, kind: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(NetdiagError::InvalidTrace(format!(
            "{kind} is not a regular file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(NetdiagError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn lab_model_hashes(
    artifact_root: &Path,
    report: &Report,
) -> Result<(Option<String>, Option<String>)> {
    let model_dir = artifact_root.join("model");
    match load_existing_model_bundle_snapshot_if_present(&model_dir)? {
        Some(snapshot) => Ok((
            Some(snapshot.model_manifest_hash_sha256),
            Some(snapshot.model_file_hash_sha256),
        )),
        None => Ok((
            report.model_manifest_hash.clone(),
            report.model_file_hash.clone(),
        )),
    }
}

fn read_lab_connector_health(
    artifact_root: &Path,
    run_id: &str,
) -> Result<Vec<ConnectorHealthSnapshot>> {
    let top_level = artifact_root.join("connector_health.json");
    if let Some(health) = read_optional_stable_json_bounded(
        &top_level,
        MAX_LAB_CONNECTOR_HEALTH_BYTES,
        "lab connector health",
    )? {
        return Ok(health);
    }
    Ok(read_connector_health(artifact_root, run_id)?
        .into_iter()
        .collect())
}

fn lab_artifact_keys(artifact_root: &Path, run_id: &str) -> Result<Vec<String>> {
    let mut keys = run_artifacts_allow_pending(artifact_root, run_id)?
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
        if path_status(&artifact_root.join(file_name))?.exists()
            && !keys.iter().any(|existing| existing == key)
        {
            keys.push(key.to_string());
        }
    }
    Ok(keys)
}

fn resolve_lab_run_artifact_root(artifact_root: &Path, run_id: &str) -> Result<LabRunResolution> {
    if path_status(&run_dir(artifact_root, run_id)?.join("report.json"))?.exists() {
        return Ok(LabRunResolution {
            artifact_root: artifact_root.to_path_buf(),
            index_entry: None,
        });
    }
    if let Some(index) = read_lab_run_index(artifact_root)?
        && let Some(entry) = index.runs.into_iter().find(|entry| entry.run_id == run_id)
    {
        let lab_run_dir = resolve_stored_path(artifact_root, &entry.lab_run_dir)?;
        if path_status(&run_dir(&lab_run_dir, run_id)?.join("report.json"))?.exists() {
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
    match path_status(&lab_runs_dir)? {
        PathStatus::Missing => return Ok(None),
        PathStatus::Directory => {}
        _ => {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab runs path is not a regular directory: {}",
                lab_runs_dir.display()
            )));
        }
    }
    for scenario in fs::read_dir(&lab_runs_dir).with_path(&lab_runs_dir)? {
        let scenario = scenario.with_path(&lab_runs_dir)?;
        let scenario_path = scenario.path();
        if !optional_lab_discovery_directory(&scenario_path, "lab scenario directory")? {
            continue;
        }
        for run in fs::read_dir(&scenario_path).with_path(&scenario_path)? {
            let run = run.with_path(&scenario_path)?;
            let candidate = run.path();
            if !optional_lab_discovery_directory(&candidate, "lab run directory")? {
                continue;
            }
            let report_path = candidate.join("runs").join(run_id).join("report.json");
            if path_status(&report_path)?.exists() {
                return Ok(Some(candidate));
            }
        }
    }
    Ok(None)
}

fn optional_lab_discovery_directory(path: &Path, kind: &str) -> Result<bool> {
    match path_status(path)? {
        PathStatus::Missing | PathStatus::RegularFile => Ok(false),
        PathStatus::Directory => Ok(true),
        PathStatus::Other => Err(NetdiagError::InvalidTrace(format!(
            "{kind} is not a regular directory: {}",
            path.display()
        ))),
    }
}

pub fn validate_lab_report(
    scenario: &LabScenario,
    report: &Report,
    context: &LabValidationContext,
) -> Result<LabAcceptanceReport> {
    let expected = scenario_expected_label(scenario);
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
    let model_manifest_hash = context
        .model_manifest_hash
        .clone()
        .or_else(|| report.model_manifest_hash.clone());
    let model_file_hash = context
        .model_file_hash
        .clone()
        .or_else(|| report.model_file_hash.clone());
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
            if let Some(required_hash) = scenario.acceptance.required_model_manifest_hash.as_deref()
            {
                match model_manifest_hash.as_deref() {
                    Some(actual_hash) if actual_hash == required_hash => {}
                    Some(actual_hash) => failures.push(format!(
                        "model manifest hash was {actual_hash}, expected {required_hash}"
                    )),
                    None => failures.push(format!(
                        "model manifest hash is missing, expected {required_hash}"
                    )),
                }
            }
            if let Some(required_hash) = scenario.acceptance.required_model_file_hash.as_deref() {
                match model_file_hash.as_deref() {
                    Some(actual_hash) if actual_hash == required_hash => {}
                    Some(actual_hash) => failures.push(format!(
                        "model file hash was {actual_hash}, expected {required_hash}"
                    )),
                    None => failures.push(format!(
                        "model file hash is missing, expected {required_hash}"
                    )),
                }
            }
        }
        None => failures.push("model manifest is missing from report".to_string()),
    }
    if !scenario
        .acceptance
        .allowed_diagnosis_statuses
        .contains(&report.diagnosis_status)
    {
        let allowed = scenario
            .acceptance
            .allowed_diagnosis_statuses
            .iter()
            .map(|status| status.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        failures.push(format!(
            "diagnosis status was {}, allowed statuses are {}",
            report.diagnosis_status, allowed
        ));
    }
    if let Some(expected) = expected {
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
        if report.diagnosis_status == DiagnosisStatus::Known {
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
        }
    } else if report.diagnosis_status == DiagnosisStatus::Known {
        failures.push(
            "known lab acceptance requires expected_label or acceptance.expected_root_cause"
                .to_string(),
        );
    }
    if scenario.acceptance.require_rule_ml_agreement
        && report.diagnosis_status == DiagnosisStatus::Known
        && !report.rule_vs_ml.agreement
    {
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
    let quality_status = match context
        .connector_health
        .iter()
        .map(|health| health.status)
        .max()
    {
        None => {
            failures.push("connector health evidence is missing".to_string());
            ConnectorHealthStatus::Error
        }
        Some(quality_status)
            if !scenario
                .acceptance
                .allowed_connector_status
                .contains(&quality_status) =>
        {
            failures.push(format!(
                "connector health status {quality_status} is not allowed"
            ));
            quality_status
        }
        Some(quality_status) => quality_status,
    };
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
        actual_diagnosis_status: report.diagnosis_status,
        synthetic_model,
        model_dataset_hash,
        model_manifest_hash,
        model_file_hash,
        quality_status,
        passed: failures.is_empty(),
        failures,
    })
}

fn root_is_suspected_corroboration(root: &crate::report::RootCause) -> bool {
    root.suspected_corroboration || root.source == "corroboration" || root.method == "corroboration"
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

fn load_lab_sources_bounded(
    scenario: &LabScenario,
    scenario_dir: &Path,
    resolved_tokens: &ResolvedBearerTokens,
) -> Result<Vec<LoadedLabSource>> {
    let mut retained = LabRetainedResourceBudget::default();
    let mut loaded_sources = Vec::with_capacity(scenario.data_sources.len());
    for source in &scenario.data_sources {
        let loaded = load_lab_source(source, scenario, scenario_dir, resolved_tokens)?;
        let source_name = source_label(source);
        if loaded.loaded.resource_usage.records != loaded.loaded.ingest.schema.rows {
            return Err(NetdiagError::Connector(format!(
                "lab source {source_name} reported {} retained records but produced {} canonical rows",
                loaded.loaded.resource_usage.records, loaded.loaded.ingest.schema.rows
            )));
        }
        retained.reserve(&source_name, loaded.loaded.resource_usage)?;
        loaded_sources.push(loaded);
    }
    Ok(loaded_sources)
}

fn load_lab_source(
    source: &LabDataSource,
    scenario: &LabScenario,
    scenario_dir: &Path,
    resolved_tokens: &ResolvedBearerTokens,
) -> Result<LoadedLabSource> {
    let loaded = match source.kind {
        LabDataSourceKind::TraceFile => load_trace_file_source(source, scenario_dir)?,
        LabDataSourceKind::HttpJson => load_http_json(
            &HttpJsonConfig {
                endpoint: source.endpoint.clone(),
                timeout: Duration::from_secs(scenario.collection.timeout_secs),
            },
            bearer::token_for_source(source, resolved_tokens)?,
        )?,
        LabDataSourceKind::PrometheusQuery => load_prometheus_query_range(
            &PrometheusQueryRangeConfig {
                base_url: source.endpoint.clone(),
                timeout: Duration::from_secs(scenario.collection.timeout_secs),
                lookback_seconds: scenario.collection.lookback_secs,
                step_seconds: scenario.collection.step_secs,
                queries: lab_mapping(source, scenario_dir)?,
                sample: scenario.id.clone(),
            },
            bearer::token_for_source(source, resolved_tokens)?,
        )?,
        LabDataSourceKind::PrometheusMetrics => load_prometheus_exposition(
            &PrometheusExpositionConfig {
                endpoint: source.endpoint.clone(),
                timeout: Duration::from_secs(scenario.collection.timeout_secs),
                metrics: lab_mapping(source, scenario_dir)?,
                sample: scenario.id.clone(),
            },
            bearer::token_for_source(source, resolved_tokens)?,
        )?,
        LabDataSourceKind::NativePcap => load_native_pcap(&NativePcapConfig {
            source: native_pcap_source(&source.endpoint, scenario_dir)?,
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
            interval: Duration::from_secs(scenario.collection.interval_secs),
            sample: scenario.id.clone(),
        })?,
    };
    let profile_name = source
        .name
        .clone()
        .unwrap_or_else(|| source.kind.as_str().to_string());
    let health = ConnectorHealthSnapshot::from_ingest(
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
    let trace = ingest_trace_with_usage(&path)?;
    let records = trace.ingest.schema.rows;
    Ok(ConnectorLoadResult {
        sample: trace.ingest.schema.sample.clone(),
        ingest: trace.ingest,
        provenance: BTreeMap::from([
            ("kind".to_string(), "trace-file".to_string()),
            ("path".to_string(), path.display().to_string()),
        ]),
        payload: None,
        resource_usage: ConnectorResourceUsage {
            input_bytes: trace.input_bytes,
            records,
        },
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
    match path_status(&topology_ref)? {
        PathStatus::Missing => topology_model(&what_if.topology),
        PathStatus::RegularFile | PathStatus::Directory | PathStatus::Other => {
            load_topology_file(&topology_ref)
        }
    }
}

fn load_lab_policy(
    what_if: &LabWhatIf,
    base_dir: &Path,
) -> Result<crate::models::TwinPolicyAction> {
    let policy_ref = resolve_path(base_dir, &what_if.policy);
    match path_status(&policy_ref)? {
        PathStatus::Missing => policy_action(&what_if.policy),
        PathStatus::RegularFile | PathStatus::Directory | PathStatus::Other => {
            load_policy_action_file(&policy_ref)
        }
    }
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
        if metrics_are_trustworthy(&source.loaded.ingest, &["latency_ms", "throughput_mbps"])
            && metrics.latency_mean > 120.0
            && metrics.throughput_mbps < 35.0
        {
            signals.push(support_signal(
                &source_kind,
                "latency high and throughput low",
                FaultLabel::Congestion,
                0.05,
            ));
        }
        if metric_is_trustworthy(&source.loaded.ingest, "dns_failure_events")
            && metrics.dns_failure_events > 0.0
        {
            signals.push(support_signal(
                &source_kind,
                "dns failure counter is non-zero",
                FaultLabel::DnsFailure,
                0.05,
            ));
        }
        if metric_is_trustworthy(&source.loaded.ingest, "tls_failure_events")
            && metrics.tls_failure_events > 0.0
        {
            signals.push(support_signal(
                &source_kind,
                "tls failure counter is non-zero",
                FaultLabel::TlsFailure,
                0.05,
            ));
        }
        if source.source.kind != LabDataSourceKind::NativePcap
            && metric_is_trustworthy(&source.loaded.ingest, "quic_blocked_ratio")
            && metrics.quic_blocked_ratio > 0.5
        {
            signals.push(support_signal(
                &source_kind,
                "QUIC blocked ratio is elevated",
                FaultLabel::UdpQuicBlocked,
                0.05,
            ));
        }
        if metrics_are_trustworthy(
            &source.loaded.ingest,
            &["packet_loss_rate", "retransmission_rate"],
        ) && metrics.packet_loss_rate > 1.0
            && metrics.retransmission_rate > 1.0
        {
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
    if metric_is_trustworthy(&source.loaded.ingest, "retransmission_rate")
        && metrics.retransmission_rate > 1.0
    {
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
    let expected = scenario_expected_label(scenario)
        .or(report.diagnosis_decision.primary_label)
        .map(|label| label.as_str().to_string())
        .unwrap_or_else(|| report.diagnosis_status.as_str().to_string());
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
        diagnosis_status: acceptance.actual_diagnosis_status,
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
    load_prometheus_mapping_file(path)
}

fn native_pcap_source(endpoint: &str, scenario_dir: &Path) -> Result<NativePcapSource> {
    let trimmed = endpoint.trim();
    if let Some(interface) = trimmed.strip_prefix("iface:") {
        return Ok(NativePcapSource::Interface(interface.trim().to_string()));
    }
    let path = resolve_path(scenario_dir, trimmed);
    match path_status(&path)? {
        PathStatus::RegularFile => Ok(NativePcapSource::File(path)),
        PathStatus::Missing => Ok(NativePcapSource::Interface(trimmed.to_string())),
        _ => Err(NetdiagError::InvalidTrace(format!(
            "native pcap source is neither a regular file nor an explicit iface: value: {}",
            path.display()
        ))),
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

fn lab_timestamp(timestamp: DateTime<Utc>) -> String {
    format!(
        "{}-{}",
        timestamp.format("%Y%m%dT%H%M%S%.3fZ"),
        &Uuid::new_v4().simple().to_string()[..8]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::AtomicPublishPhase;
    use crate::models::{
        DistributionStats, EvidenceRecord, MlResult, ModelManifest, OverallTelemetry, Prediction,
        RunHistoryEntry, Severity, ThroughputStats, TimeWindow, UncertaintyAssessment,
        WhatIfResult,
    };
    use crate::report::{Report, RootCause, RuleMlComparison};
    use std::collections::BTreeSet;
    use std::io::Write;
    use std::sync::Mutex;

    static CWD_LOCK: Mutex<()> = Mutex::new(());

    mod metric_quality;

    #[test]
    fn http_endpoint_validation_never_echoes_credentials() {
        let secret = "opaque-lab-endpoint-secret";
        for endpoint in [
            format!("https://operator:{secret}@example.test/metrics"),
            format!("https://invalid host/?access_token={secret}"),
        ] {
            let error = validate_http_endpoint(&endpoint).expect_err("unsafe endpoint must fail");
            assert!(!error.to_string().contains(secret), "{error}");
        }
    }

    #[test]
    fn filesystem_entries_do_not_fall_back_to_named_what_if_presets() {
        let temp = tempfile::tempdir().expect("tempdir");
        let topology_entry = temp.path().join("mesh");
        let policy_entry = temp.path().join("reroute_path_b");
        fs::create_dir(&topology_entry).expect("topology directory");
        fs::create_dir(&policy_entry).expect("policy directory");
        let request = LabWhatIf {
            topology: "mesh".to_string(),
            policy: "reroute_path_b".to_string(),
        };

        let topology_error = load_lab_topology(&request, temp.path())
            .expect_err("an existing non-file topology must not fall back to a preset");
        assert!(
            topology_error.to_string().contains("mesh"),
            "{topology_error}"
        );

        let policy_error = load_lab_policy(&request, temp.path())
            .expect_err("an existing non-file policy must not fall back to a preset");
        assert!(
            policy_error.to_string().contains("reroute_path_b"),
            "{policy_error}"
        );
    }

    fn scenario(expected: FaultLabel, require_what_if_improvement: bool) -> LabScenario {
        LabScenario {
            schema: "netdiag-lab-scenario/v1".to_string(),
            id: "test-scenario".to_string(),
            name: "Test Scenario".to_string(),
            expected_label: Some(expected),
            topology: None,
            data_sources: vec![LabDataSource {
                name: Some("primary".to_string()),
                role: LabDataSourceRole::Primary,
                kind: LabDataSourceKind::TraceFile,
                endpoint: "trace.csv".to_string(),
                bearer_token_env: None,
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
                allowed_diagnosis_statuses: default_allowed_diagnosis_statuses(),
                require_rule_ml_agreement: true,
                require_what_if_improvement,
                required_artifacts: Vec::new(),
                allow_synthetic_model: false,
                required_model_dataset_hash: None,
                required_model_manifest_hash: None,
                required_model_file_hash: None,
                allow_suspected_corroboration: false,
            },
            verification: LabVerification::default(),
        }
    }

    #[test]
    fn lab_scenario_rejects_unbounded_collection_values() {
        let mut invalid = scenario(FaultLabel::Normal, false);
        invalid.collection.timeout_secs = 0;
        assert!(validate_lab_scenario(&invalid).is_err());

        let mut invalid = scenario(FaultLabel::Normal, false);
        invalid.collection.lookback_secs = 86_401;
        assert!(validate_lab_scenario(&invalid).is_err());

        let mut invalid = scenario(FaultLabel::Normal, false);
        invalid.collection.step_secs = 301;
        invalid.collection.lookback_secs = 300;
        assert!(validate_lab_scenario(&invalid).is_err());

        let mut invalid = scenario(FaultLabel::Normal, false);
        invalid.collection.packet_limit = crate::MAX_PCAP_PACKET_LIMIT + 1;
        assert!(validate_lab_scenario(&invalid).is_err());

        let mut invalid = scenario(FaultLabel::Normal, false);
        invalid.collection.interval_secs = 11;
        assert!(validate_lab_scenario(&invalid).is_err());
    }

    #[test]
    fn lab_retained_resource_budget_enforces_source_and_scenario_limits_atomically() {
        let mut budget = LabRetainedResourceBudget::default();
        for (index, records) in [100_000, 100_000, 50_000, 0].into_iter().enumerate() {
            budget
                .reserve(
                    &format!("source-{index}"),
                    ConnectorResourceUsage {
                        input_bytes: MAX_SOURCE_INPUT_BYTES,
                        records,
                    },
                )
                .expect("exact aggregate limit");
        }
        assert_eq!(
            budget,
            LabRetainedResourceBudget {
                input_bytes: MAX_SCENARIO_RETAINED_BYTES,
                records: MAX_SCENARIO_RECORDS,
            }
        );

        let unchanged = LabRetainedResourceBudget {
            input_bytes: budget.input_bytes,
            records: budget.records,
        };
        let byte_error = budget
            .reserve(
                "one-byte-too-many",
                ConnectorResourceUsage {
                    input_bytes: 1,
                    records: 0,
                },
            )
            .expect_err("scenario byte limit");
        assert!(byte_error.to_string().contains("scenario limit"));
        assert_eq!(budget, unchanged, "failed reserve must not mutate budget");

        let mut row_budget = LabRetainedResourceBudget::default();
        for records in [100_000, 100_000, 50_000] {
            row_budget
                .reserve(
                    "row-source",
                    ConnectorResourceUsage {
                        input_bytes: 0,
                        records,
                    },
                )
                .expect("exact scenario row limit");
        }
        let row_error = row_budget
            .reserve(
                "one-row-too-many",
                ConnectorResourceUsage {
                    input_bytes: 0,
                    records: 1,
                },
            )
            .expect_err("scenario row limit");
        assert!(row_error.to_string().contains("record count"));
        assert_eq!(row_budget.records, MAX_SCENARIO_RECORDS);

        let mut source_budget = LabRetainedResourceBudget::default();
        let source_error = source_budget
            .reserve(
                "oversized-source",
                ConnectorResourceUsage {
                    input_bytes: MAX_SOURCE_INPUT_BYTES + 1,
                    records: 1,
                },
            )
            .expect_err("per-source byte limit");
        assert!(source_error.to_string().contains("source limit"));
        assert_eq!(source_budget, LabRetainedResourceBudget::default());
    }

    #[test]
    fn lab_source_validation_precedes_model_and_run_directory_side_effects() {
        let temp = tempfile::tempdir().expect("tempdir");
        let scenario_path = temp.path().join("scenario.yaml");
        let artifacts = temp.path().join("artifacts");
        let mut missing_source = scenario(FaultLabel::Normal, false);
        missing_source.id = "missing-source-budget-check".to_string();
        missing_source.data_sources[0].endpoint = "missing.csv".to_string();
        std::fs::write(
            &scenario_path,
            serde_yaml::to_string(&missing_source).expect("scenario YAML"),
        )
        .expect("scenario");

        let error = run_lab_scenario(
            &scenario_path,
            LabRunOptions {
                artifacts: artifacts.clone(),
            },
        )
        .expect_err("missing trace must fail before model inspection");

        assert!(
            matches!(error, NetdiagError::Io { ref source, .. } if source.kind() == std::io::ErrorKind::NotFound),
            "{error}"
        );
        assert!(
            !artifacts.exists(),
            "source validation must not create artifact, model, or run directories"
        );
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
            diagnosis_status: DiagnosisStatus::Known,
            uncertainty: Default::default(),
            diagnosis_decision: Default::default(),
            root_causes: roots,
            rule_vs_ml: RuleMlComparison {
                rule_labels: rule_labels.clone(),
                ml_top: ml_top_text.clone(),
                ml_top_prob: 0.95,
                diagnosis_status: DiagnosisStatus::Known,
                uncertainty: Default::default(),
                agreement: rule_labels.iter().any(|label| label == &ml_top_text),
                agreement_text: "test".to_string(),
                rule_missing: Vec::new(),
                rule_only: Vec::new(),
            },
            model_manifest: Some(model_manifest(false, Some("dataset-test-hash"))),
            model_manifest_hash: Some("manifest-test-hash".to_string()),
            model_file_hash: Some("file-test-hash".to_string()),
            what_if,
            multi_source_evidence: None,
            evidence_timeline: Vec::new(),
            recommendations: Vec::new(),
            hil_summary: Default::default(),
        }
    }

    fn save_verification_run(root: &Path, run_id: &str, report: &Report) {
        let run_dir = root.join("runs").join(run_id);
        fs::create_dir_all(&run_dir).expect("run directory");
        save_json(run_dir.join("report.json"), report).expect("run report");
        save_json(
            run_dir.join("manifest.json"),
            &RunManifest {
                run_id: run_id.to_string(),
                sample: "action-verification-fixture".to_string(),
                created_at: Utc::now(),
                trace_rows: 1,
                artifact_paths: BTreeMap::from([("report".to_string(), "report.json".to_string())]),
            },
        )
        .expect("run manifest");
    }

    fn root(label: FaultLabel, confidence: f64) -> RootCause {
        RootCause {
            symptom: label.as_str().to_string(),
            severity: "low".to_string(),
            confidence,
            why: "test".to_string(),
            source: "rule".to_string(),
            method: "rule".to_string(),
            suspected_corroboration: false,
            diagnosis_status: DiagnosisStatus::Known,
        }
    }

    fn model_manifest(synthetic_fallback: bool, dataset_hash: Option<&str>) -> ModelManifest {
        ModelManifest {
            schema_version: "netdiag-model-manifest/v2".to_string(),
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
            model_file_hash_sha256: "a".repeat(64),
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
            uncertainty_thresholds: None,
        }
    }

    fn history_entry(run_id: &str, quality_status: ConnectorHealthStatus) -> RunHistoryEntry {
        RunHistoryEntry {
            run_id: run_id.to_string(),
            sample: run_id.to_string(),
            created_at: Utc::now(),
            status: "complete".to_string(),
            run_dir: format!("runs/{run_id}"),
            root_causes: Vec::new(),
            diagnosis_status: DiagnosisStatus::Known,
            uncertainty_reason_codes: Vec::new(),
            ml_top_label: None,
            ml_top_probability: None,
            model_kind: None,
            synthetic_model: false,
            measurement_quality: Vec::new(),
            quality: Default::default(),
            quality_status,
            warning_count: 0,
            hil_summary: Default::default(),
            artifact_count: 0,
        }
    }

    fn calibration_ml_result(
        run_id: &str,
        status: DiagnosisStatus,
        max_probability: f64,
        probability_margin: f64,
        entropy: f64,
        feature_distance: f64,
    ) -> MlResult {
        MlResult {
            method: "test".to_string(),
            run_id: run_id.to_string(),
            top_predictions: vec![Prediction {
                label: FaultLabel::Congestion,
                prob: max_probability,
            }],
            top_features: Vec::new(),
            features: BTreeMap::new(),
            feature_quality: BTreeMap::new(),
            uncertainty: UncertaintyAssessment {
                max_probability,
                probability_margin,
                entropy,
                feature_distance,
                status,
                ..Default::default()
            },
            model_manifest: None,
            model_manifest_hash: None,
            model_file_hash: None,
        }
    }

    fn write_lab_calibration_sample(
        artifact_root: &Path,
        scenario_id: &str,
        run_id: &str,
        expected_label: Option<FaultLabel>,
        status: DiagnosisStatus,
        ml: MlResult,
    ) {
        write_lab_calibration_sample_with_agreement(
            artifact_root,
            scenario_id,
            run_id,
            expected_label,
            status,
            ml,
            true,
        );
    }

    fn write_lab_calibration_sample_with_agreement(
        artifact_root: &Path,
        scenario_id: &str,
        run_id: &str,
        expected_label: Option<FaultLabel>,
        status: DiagnosisStatus,
        mut ml: MlResult,
        rule_ml_agreement: bool,
    ) {
        let identity = calibration_fixture_model_identity(artifact_root);
        ml.model_manifest_hash = Some(identity.model_manifest_hash_sha256.clone());
        ml.model_file_hash = Some(identity.model_file_hash_sha256.clone());
        let lab_run_dir = artifact_root
            .join("lab-runs")
            .join(scenario_id)
            .join(run_id);
        let pipeline_run_dir = run_dir(&lab_run_dir, run_id).expect("valid run id");
        std::fs::create_dir_all(&pipeline_run_dir).expect("lab run dir");
        let acceptance = LabAcceptanceReport {
            schema: "netdiag-lab-acceptance/v1".to_string(),
            scenario_id: scenario_id.to_string(),
            run_id: run_id.to_string(),
            expected_label,
            actual_rule_labels: Vec::new(),
            actual_ml_top: FaultLabel::Congestion.as_str().to_string(),
            actual_ml_probability: ml.uncertainty.max_probability,
            actual_diagnosis_status: status,
            synthetic_model: false,
            model_dataset_hash: Some(identity.dataset_hash_sha256),
            model_manifest_hash: Some(identity.model_manifest_hash_sha256),
            model_file_hash: Some(identity.model_file_hash_sha256),
            quality_status: ConnectorHealthStatus::Ok,
            passed: true,
            failures: Vec::new(),
        };
        save_json(lab_run_dir.join("acceptance.json"), &acceptance).expect("acceptance");
        let comparison = LabRunComparison {
            schema: "netdiag-lab-comparison/v1".to_string(),
            scenario_id: scenario_id.to_string(),
            run_id: run_id.to_string(),
            expected_label,
            actual_rule_labels: acceptance.actual_rule_labels.clone(),
            actual_ml_top: acceptance.actual_ml_top.clone(),
            diagnosis_status: status,
            rule_ml_agreement,
            quality_status: ConnectorHealthStatus::Ok,
            previous_run_comparison: None,
        };
        save_json(lab_run_dir.join("comparison.json"), &comparison).expect("comparison");
        save_json(pipeline_run_dir.join("ml_result.json"), &ml).expect("ml result");
        if let Some(label) = expected_label {
            save_json(
                pipeline_run_dir.join("diagnosis_events.json"),
                &vec![calibration_diagnosis_event(run_id, label)],
            )
            .expect("diagnosis events");
        }
        update_lab_run_index(
            artifact_root,
            LabRunIndexEntry {
                run_id: run_id.to_string(),
                scenario_id: scenario_id.to_string(),
                scenario_name: scenario_id.to_string(),
                created_at: Utc::now(),
                lab_run_dir: stored_lab_index_path(artifact_root, &lab_run_dir)
                    .expect("lab run path"),
                pipeline_run_dir: stored_lab_index_path(artifact_root, &pipeline_run_dir)
                    .expect("pipeline run path"),
                acceptance_path: stored_lab_index_path(
                    artifact_root,
                    &lab_run_dir.join("acceptance.json"),
                )
                .expect("acceptance path"),
                comparison_path: stored_lab_index_path(
                    artifact_root,
                    &lab_run_dir.join("comparison.json"),
                )
                .expect("comparison path"),
                scenario_path: stored_lab_index_path(
                    artifact_root,
                    &lab_run_dir.join("scenario.yaml"),
                )
                .expect("scenario path"),
                passed: true,
            },
        )
        .expect("index");
    }

    #[derive(Debug, Clone)]
    struct CalibrationFixtureModelIdentity {
        dataset_hash_sha256: String,
        model_manifest_hash_sha256: String,
        model_file_hash_sha256: String,
    }

    fn calibration_fixture_model_identity(artifact_root: &Path) -> CalibrationFixtureModelIdentity {
        let model_dir = artifact_root.join("model");
        let snapshot =
            crate::ml::load_existing_model_bundle_snapshot(&model_dir).expect("model snapshot");
        CalibrationFixtureModelIdentity {
            dataset_hash_sha256: snapshot
                .manifest
                .dataset_hash_sha256
                .clone()
                .expect("calibration fixture model dataset hash"),
            model_manifest_hash_sha256: snapshot.model_manifest_hash_sha256,
            model_file_hash_sha256: snapshot.model_file_hash_sha256,
        }
    }

    fn calibration_acceptance_path(
        artifact_root: &Path,
        scenario_id: &str,
        run_id: &str,
    ) -> PathBuf {
        artifact_root
            .join("lab-runs")
            .join(scenario_id)
            .join(run_id)
            .join("acceptance.json")
    }

    fn calibration_events_path(artifact_root: &Path, scenario_id: &str, run_id: &str) -> PathBuf {
        run_dir(
            artifact_root
                .join("lab-runs")
                .join(scenario_id)
                .join(run_id),
            run_id,
        )
        .expect("valid run id")
        .join("diagnosis_events.json")
    }

    fn calibration_diagnosis_event(run_id: &str, label: FaultLabel) -> DiagnosisEvent {
        let now = Utc::now();
        DiagnosisEvent {
            event_id: format!("calibration-{run_id}-{}", label.as_str()),
            evidence: EvidenceRecord {
                run_id: run_id.to_string(),
                method: "test".to_string(),
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
                hil_state: Default::default(),
                why: "calibration fixture".to_string(),
            },
            source: "test".to_string(),
            model_probability: None,
        }
    }

    fn write_lab_grade_calibration_samples(artifact_root: &Path) {
        for (idx, label) in FaultLabel::ALL.iter().enumerate() {
            let run_id = format!("known-run-{idx}");
            write_lab_calibration_sample(
                artifact_root,
                label.as_str(),
                &run_id,
                Some(*label),
                DiagnosisStatus::Known,
                calibration_ml_result(&run_id, DiagnosisStatus::Known, 0.82, 0.18, 0.42, 2.0),
            );
        }
        write_lab_calibration_sample(
            artifact_root,
            "ood",
            "ood-run",
            None,
            DiagnosisStatus::OutOfDistribution,
            calibration_ml_result(
                "ood-run",
                DiagnosisStatus::OutOfDistribution,
                0.90,
                0.30,
                0.20,
                10.0,
            ),
        );
    }

    fn run_comparison(
        latency_p95_delta_pct: Option<f64>,
        loss_delta_pct: Option<f64>,
        throughput_delta_pct: Option<f64>,
        right_quality_status: ConnectorHealthStatus,
    ) -> RunComparison {
        RunComparison {
            left: history_entry("before", ConnectorHealthStatus::Ok),
            right: history_entry("after", right_quality_status),
            latency_p95_delta_pct,
            loss_delta_pct,
            throughput_delta_pct,
            ml_label_changed: false,
            new_root_causes: Vec::new(),
            resolved_root_causes: Vec::new(),
            review_status_changed: false,
            recommendation_state_changes: Vec::new(),
            measurement_quality_changes: Vec::new(),
            quality_status_changed: right_quality_status != ConnectorHealthStatus::Ok,
            warning_count_delta: 0,
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

    fn provision_test_model(artifacts: &Path) {
        crate::storage::ensure_artifact_root_owned(artifacts).expect("owned artifacts dir");
        let dataset_path = artifacts.join("training.jsonl");
        let mut dataset = std::fs::File::create(&dataset_path).expect("training dataset");
        for name in [
            "normal",
            "congestion",
            "random_loss",
            "dns_failure",
            "tls_failure",
            "udp_quic_blocked",
        ] {
            let ingest = ingest_trace(
                repo_root()
                    .join("data")
                    .join("samples")
                    .join(format!("{name}.csv")),
            )
            .expect("sample ingest");
            let row = serde_json::json!({
                "label": name,
                "records": ingest.records,
            });
            writeln!(dataset, "{row}").expect("write training row");
        }
        crate::ml::train_model_from_jsonl(&dataset_path, artifacts.join("model"))
            .expect("train lab test model");
    }

    fn healthy_connector_health() -> Vec<ConnectorHealthSnapshot> {
        vec![ConnectorHealthSnapshot {
            status: ConnectorHealthStatus::Ok,
            source_kind: "trace-file".to_string(),
            profile_name: "primary".to_string(),
            sample: "test".to_string(),
            rows: 1,
            warning_count: 0,
            missing_metrics: Vec::new(),
            quality: Default::default(),
            captured_at: Utc::now(),
        }]
    }

    fn healthy_validation_context() -> LabValidationContext {
        LabValidationContext {
            connector_health: healthy_connector_health(),
            ..LabValidationContext::default()
        }
    }

    #[test]
    fn validate_lab_report_rejects_missing_connector_health_evidence() {
        let scenario = scenario(FaultLabel::Normal, false);
        let report = report(
            "run-normal",
            vec![root(FaultLabel::Normal, 0.95)],
            FaultLabel::Normal,
            None,
        );

        let acceptance = validate_lab_report(&scenario, &report, &LabValidationContext::default())
            .expect("structured acceptance failure");

        assert!(!acceptance.passed);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure == "connector health evidence is missing"),
            "{:?}",
            acceptance.failures
        );
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
                connector_health: healthy_connector_health(),
                artifact_keys: Vec::new(),
                model_manifest_hash: None,
                model_file_hash: None,
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
                connector_health: healthy_connector_health(),
                artifact_keys: Vec::new(),
                model_manifest_hash: None,
                model_file_hash: None,
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
                connector_health: healthy_connector_health(),
                artifact_keys: Vec::new(),
                model_manifest_hash: None,
                model_file_hash: None,
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
    fn validate_lab_report_enforces_required_model_identity_hashes() {
        let mut scenario = scenario(FaultLabel::Normal, false);
        scenario.acceptance.required_model_manifest_hash = Some("manifest-test-hash".to_string());
        scenario.acceptance.required_model_file_hash = Some("file-test-hash".to_string());
        let report = report(
            "run-normal",
            vec![root(FaultLabel::Normal, 0.95)],
            FaultLabel::Normal,
            None,
        );

        let acceptance = validate_lab_report(&scenario, &report, &healthy_validation_context())
            .expect("acceptance");
        assert!(acceptance.passed, "{:?}", acceptance.failures);
        assert_eq!(
            acceptance.model_manifest_hash.as_deref(),
            Some("manifest-test-hash")
        );
        assert_eq!(
            acceptance.model_file_hash.as_deref(),
            Some("file-test-hash")
        );

        let mut wrong = scenario;
        wrong.acceptance.required_model_file_hash = Some("wrong-file-hash".to_string());
        let acceptance = validate_lab_report(&wrong, &report, &healthy_validation_context())
            .expect("acceptance");
        assert!(!acceptance.passed);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure.contains("model file hash")),
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
                suspected_corroboration: true,
                diagnosis_status: DiagnosisStatus::Known,
            }],
            FaultLabel::Congestion,
            None,
        );
        report.rule_vs_ml.agreement = true;
        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: healthy_connector_health(),
                artifact_keys: Vec::new(),
                model_manifest_hash: None,
                model_file_hash: None,
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
    fn lab_acceptance_rejects_uncertain_status_by_default() {
        let mut scenario = scenario(FaultLabel::Congestion, false);
        scenario.acceptance.require_rule_ml_agreement = false;
        let mut report = report(
            "run-test",
            vec![root(FaultLabel::Congestion, 0.95)],
            FaultLabel::Congestion,
            None,
        );
        report.diagnosis_status = DiagnosisStatus::Uncertain;
        report.rule_vs_ml.diagnosis_status = DiagnosisStatus::Uncertain;

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: healthy_connector_health(),
                artifact_keys: default_required_artifacts(),
                model_manifest_hash: Some("manifest-test-hash".to_string()),
                model_file_hash: Some("file-test-hash".to_string()),
            },
        )
        .expect("acceptance");

        assert!(!acceptance.passed);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure.contains("diagnosis status")),
            "{:?}",
            acceptance.failures
        );
    }

    #[test]
    fn lab_acceptance_allows_uncertain_status_when_configured() {
        let mut scenario = scenario(FaultLabel::Congestion, false);
        scenario.acceptance.allowed_diagnosis_statuses =
            vec![DiagnosisStatus::Known, DiagnosisStatus::Uncertain];
        scenario.acceptance.require_rule_ml_agreement = false;
        let mut report = report(
            "run-test",
            vec![root(FaultLabel::Congestion, 0.95)],
            FaultLabel::Congestion,
            None,
        );
        report.diagnosis_status = DiagnosisStatus::Uncertain;
        report.rule_vs_ml.diagnosis_status = DiagnosisStatus::Uncertain;

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: healthy_connector_health(),
                artifact_keys: default_required_artifacts(),
                model_manifest_hash: Some("manifest-test-hash".to_string()),
                model_file_hash: Some("file-test-hash".to_string()),
            },
        )
        .expect("acceptance");

        assert!(acceptance.passed, "{:?}", acceptance.failures);
        assert_eq!(
            acceptance.actual_diagnosis_status,
            DiagnosisStatus::Uncertain
        );
    }

    #[test]
    fn lab_acceptance_allows_ood_without_expected_label() {
        let mut scenario = scenario(FaultLabel::Normal, false);
        scenario.expected_label = None;
        scenario.acceptance.expected_root_cause = None;
        scenario.acceptance.allowed_diagnosis_statuses = vec![DiagnosisStatus::OutOfDistribution];
        scenario.acceptance.require_rule_ml_agreement = false;
        let mut report = report("run-ood", Vec::new(), FaultLabel::Normal, None);
        report.diagnosis_status = DiagnosisStatus::OutOfDistribution;
        report.rule_vs_ml.diagnosis_status = DiagnosisStatus::OutOfDistribution;

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: healthy_connector_health(),
                artifact_keys: default_required_artifacts(),
                model_manifest_hash: Some("manifest-test-hash".to_string()),
                model_file_hash: Some("file-test-hash".to_string()),
            },
        )
        .expect("acceptance");

        assert!(acceptance.passed, "{:?}", acceptance.failures);
        assert_eq!(acceptance.expected_label, None);
    }

    #[test]
    fn lab_acceptance_rejects_known_status_without_expected_label() {
        let mut scenario = scenario(FaultLabel::Normal, false);
        scenario.expected_label = None;
        scenario.acceptance.expected_root_cause = None;
        scenario.acceptance.require_rule_ml_agreement = false;
        let report = report(
            "run-known",
            vec![root(FaultLabel::DnsFailure, 0.95)],
            FaultLabel::DnsFailure,
            None,
        );

        let acceptance = validate_lab_report(
            &scenario,
            &report,
            &LabValidationContext {
                connector_health: healthy_connector_health(),
                artifact_keys: default_required_artifacts(),
                model_manifest_hash: Some("manifest-test-hash".to_string()),
                model_file_hash: Some("file-test-hash".to_string()),
            },
        )
        .expect("acceptance");

        assert!(!acceptance.passed);
        assert!(
            acceptance
                .failures
                .iter()
                .any(|failure| failure.contains("requires expected_label"))
        );
    }

    #[test]
    fn verify_action_verdict_accepts_five_percent_improvement_without_quality_degradation() {
        let comparison =
            run_comparison(Some(-5.2), Some(0.0), Some(0.0), ConnectorHealthStatus::Ok);

        let (verdict, reasons) =
            action_verification_verdict(&comparison, None, &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(verdict, ActionVerificationVerdict::Verified);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("improved by at least 5%")),
            "{reasons:?}"
        );
    }

    #[test]
    fn verify_action_verdict_is_inconclusive_when_quality_degrades() {
        let comparison = run_comparison(
            Some(-10.0),
            Some(0.0),
            Some(0.0),
            ConnectorHealthStatus::Degraded,
        );

        let (verdict, reasons) =
            action_verification_verdict(&comparison, None, &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(verdict, ActionVerificationVerdict::Inconclusive);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("connector quality degraded")),
            "{reasons:?}"
        );
    }

    #[test]
    fn verify_action_verdict_requires_all_objective_conditions() {
        let comparison =
            run_comparison(Some(-6.0), Some(0.0), Some(1.0), ConnectorHealthStatus::Ok);
        let policy = LabVerification {
            objective: BTreeMap::from([
                ("latency_p95_delta_pct".to_string(), "<= -5".to_string()),
                ("throughput_delta_pct".to_string(), ">= 0".to_string()),
                ("packet_loss_delta_pct".to_string(), "<= 0".to_string()),
            ]),
            fail_if: BTreeMap::new(),
        };

        let (verdict, reasons) = action_verification_verdict(
            &comparison,
            Some(&policy),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );

        assert_eq!(verdict, ActionVerificationVerdict::Verified);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("verification objective"))
        );
    }

    #[test]
    fn verify_action_verdict_fails_on_policy_tradeoff() {
        let comparison = run_comparison(
            Some(-6.0),
            Some(0.0),
            Some(-30.0),
            ConnectorHealthStatus::Ok,
        );
        let policy = LabVerification {
            objective: BTreeMap::from([("latency_p95_delta_pct".to_string(), "<= -5".to_string())]),
            fail_if: BTreeMap::from([("throughput_delta_pct".to_string(), "< -10".to_string())]),
        };

        let (verdict, reasons) = action_verification_verdict(
            &comparison,
            Some(&policy),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );

        assert_eq!(verdict, ActionVerificationVerdict::NotVerified);
        assert!(reasons.iter().any(|reason| reason.contains("fail_if")));
    }

    #[test]
    fn verify_action_verdict_is_inconclusive_when_objective_metric_is_missing() {
        let comparison = run_comparison(None, Some(0.0), Some(0.0), ConnectorHealthStatus::Ok);
        let policy = LabVerification {
            objective: BTreeMap::from([("latency_p95_delta_pct".to_string(), "<= -5".to_string())]),
            fail_if: BTreeMap::new(),
        };

        let (verdict, reasons) = action_verification_verdict(
            &comparison,
            Some(&policy),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );

        assert_eq!(verdict, ActionVerificationVerdict::Inconclusive);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("metric latency_p95_delta_pct is missing"))
        );
    }

    #[test]
    fn verify_action_default_verdict_rejects_large_tradeoff() {
        let comparison = run_comparison(
            Some(-8.0),
            Some(0.0),
            Some(-12.0),
            ConnectorHealthStatus::Ok,
        );

        let (verdict, reasons) =
            action_verification_verdict(&comparison, None, &BTreeMap::new(), &BTreeMap::new());

        assert_eq!(verdict, ActionVerificationVerdict::NotVerified);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("throughput_delta_pct regressed")),
            "{reasons:?}"
        );
    }

    #[test]
    fn verify_action_fail_if_missing_metric_is_inconclusive() {
        let comparison = run_comparison(Some(-8.0), None, Some(1.0), ConnectorHealthStatus::Ok);
        let policy = LabVerification {
            objective: BTreeMap::new(),
            fail_if: BTreeMap::from([("packet_loss_delta_pct".to_string(), "> 1".to_string())]),
        };

        let (verdict, reasons) = action_verification_verdict(
            &comparison,
            Some(&policy),
            &BTreeMap::new(),
            &BTreeMap::new(),
        );

        assert_eq!(verdict, ActionVerificationVerdict::Inconclusive);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("fail_if metric packet_loss_delta_pct is missing")),
            "{reasons:?}"
        );
    }

    #[test]
    fn verify_action_prediction_error_uses_percentage_units() {
        let effect = TwinPolicyImpact {
            latency_delta_pct: -0.18,
            loss_delta_pct: -0.06,
            throughput_delta_pct: 0.12,
        };
        let predicted = predicted_delta_pct_map(Some(&effect)).expect("predicted deltas");
        let observed = observed_delta_pct_map(&run_comparison(
            Some(-14.0),
            Some(-4.0),
            Some(10.0),
            ConnectorHealthStatus::Ok,
        ))
        .expect("observed deltas");
        let error = prediction_error_pct_map(&predicted, &observed).expect("prediction errors");

        assert_eq!(predicted["latency_p95_delta_pct"], -18.0);
        assert_eq!(error["latency_p95_delta_pct"], 4.0);
        assert_eq!(error["throughput_delta_pct"], -2.0);
    }

    #[test]
    fn verify_action_rejects_incomplete_legacy_prediction_before_publication() {
        let temp = tempfile::tempdir().expect("tempdir");
        let before = report(
            "before",
            Vec::new(),
            FaultLabel::Normal,
            Some(WhatIfResult {
                action_id: "action-1".to_string(),
                action_notes: String::new(),
                policy_action: None,
                topology: "fixture".to_string(),
                topology_snapshot: None,
                modified_topology_snapshot: None,
                baseline: BTreeMap::new(),
                proposed: BTreeMap::new(),
                delta: BTreeMap::from([
                    ("latency_pct".to_string(), -5.0),
                    ("loss_pct".to_string(), -1.0),
                ]),
            }),
        );
        let after = report("after", Vec::new(), FaultLabel::Normal, None);
        save_verification_run(temp.path(), "before", &before);
        save_verification_run(temp.path(), "after", &after);

        let error = verify_action(temp.path(), "before", "after", None)
            .expect_err("missing prediction delta must fail before publication");

        assert!(error.to_string().contains("throughput_pct"), "{error}");
        let run_dir = temp.path().join("runs").join("before");
        assert!(!run_dir.join("action_verification_after.json").exists());
        let manifest: RunManifest =
            serde_json::from_value(read_json(run_dir.join("manifest.json")).expect("manifest"))
                .expect("manifest shape");
        assert!(
            !manifest
                .artifact_paths
                .contains_key("action_verification_after")
        );
    }

    #[test]
    fn verify_action_artifact_is_recorded_in_manifest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let run_dir = temp.path().join("runs").join("before");
        std::fs::create_dir_all(&run_dir).expect("run dir");
        let mut artifact_paths = BTreeMap::new();
        artifact_paths.insert("report".to_string(), "report.json".to_string());
        save_json(
            run_dir.join("manifest.json"),
            &RunManifest {
                run_id: "before".to_string(),
                sample: "sample".to_string(),
                created_at: Utc::now(),
                trace_rows: 1,
                artifact_paths,
            },
        )
        .expect("manifest");
        let verification = ActionVerification {
            schema: "netdiag-action-verification/v1".to_string(),
            generated_at: Utc::now(),
            before_run_id: "before".to_string(),
            after_run_id: "after".to_string(),
            recommendation_id: None,
            predicted_what_if_effect: None,
            predicted_deltas_pct: BTreeMap::new(),
            observed_deltas_pct: BTreeMap::new(),
            prediction_error_pct: BTreeMap::new(),
            objective: BTreeMap::new(),
            fail_if: BTreeMap::new(),
            observed_comparison: run_comparison(None, None, None, ConnectorHealthStatus::Ok),
            verdict: ActionVerificationVerdict::Inconclusive,
            reasons: Vec::new(),
        };

        record_action_verification_artifact(&run_dir, "after", &verification).expect("record");

        let manifest: RunManifest =
            serde_json::from_value(read_json(run_dir.join("manifest.json")).expect("read"))
                .expect("manifest");
        assert_eq!(
            manifest
                .artifact_paths
                .get("action_verification_after")
                .map(String::as_str),
            Some("action_verification_after.json")
        );
    }

    #[test]
    fn lab_calibration_updates_model_manifest_thresholds_from_accepted_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        let source_identity = calibration_fixture_model_identity(temp.path());
        write_lab_grade_calibration_samples(temp.path());

        let report = calibrate_lab_uncertainty(temp.path(), false).expect("calibration");

        assert!(report.applied);
        assert_eq!(report.evaluated_runs, FaultLabel::ALL.len() + 1);
        assert_eq!(report.known_runs, FaultLabel::ALL.len());
        assert_eq!(report.out_of_distribution_runs, 1);
        assert_eq!(report.ood.expected_ood_runs, 1);
        assert!(report.feature_distance_distribution.p95 >= 2.0);
        assert!(report.per_label.contains_key("congestion"));
        assert_eq!(
            report
                .per_label
                .get("congestion")
                .expect("congestion")
                .accepted_known_runs,
            1
        );
        assert_eq!(
            report.source_model_manifest_hash_sha256,
            source_identity.model_manifest_hash_sha256
        );
        assert_eq!(
            report.model_file_hash_sha256.as_deref(),
            Some(source_identity.model_file_hash_sha256.as_str())
        );
        assert_eq!(
            report.dataset_hash_sha256.as_deref(),
            Some(source_identity.dataset_hash_sha256.as_str())
        );
        let final_snapshot =
            crate::ml::load_existing_model_bundle_snapshot(&temp.path().join("model"))
                .expect("final model snapshot");
        let final_manifest_hash = final_snapshot.model_manifest_hash_sha256.clone();
        assert_eq!(
            report.model_manifest_hash_sha256.as_deref(),
            Some(final_manifest_hash.as_str())
        );
        assert!(report.calibrated_thresholds.max_feature_distance > 2.0);
        assert!(report.calibrated_thresholds.max_feature_distance < 10.0);
        let persisted: LabCalibrationReport = serde_json::from_value(
            read_json(temp.path().join("lab_calibration_report.json")).expect("report"),
        )
        .expect("calibration report");
        assert_eq!(persisted.schema, "netdiag-lab-calibration/v2");
        assert!(persisted.applied);
        assert_eq!(
            persisted.source_model_manifest_hash_sha256,
            report.source_model_manifest_hash_sha256
        );
        assert_eq!(
            persisted.model_manifest_hash_sha256.as_deref(),
            Some(final_manifest_hash.as_str())
        );
        let mut legacy_value = serde_json::to_value(&persisted).expect("legacy report value");
        legacy_value
            .as_object_mut()
            .expect("report object")
            .remove("source_model_manifest_hash_sha256");
        assert!(
            serde_json::from_value::<LabCalibrationReport>(legacy_value).is_err(),
            "v2 reports must fail closed without the source model identity"
        );
        let manifest = final_snapshot.manifest;
        assert_eq!(
            manifest
                .uncertainty_thresholds
                .expect("thresholds")
                .max_feature_distance,
            report.calibrated_thresholds.max_feature_distance
        );
    }

    #[test]
    fn lab_calibration_rejects_missing_indexed_model_identity_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        write_lab_grade_calibration_samples(temp.path());
        let acceptance_path =
            calibration_acceptance_path(temp.path(), FaultLabel::Normal.as_str(), "known-run-0");
        let original: LabAcceptanceReport =
            serde_json::from_value(read_json(&acceptance_path).expect("acceptance"))
                .expect("acceptance json");

        for field in [
            "model_dataset_hash",
            "model_manifest_hash",
            "model_file_hash",
        ] {
            let mut acceptance = original.clone();
            match field {
                "model_dataset_hash" => acceptance.model_dataset_hash = None,
                "model_manifest_hash" => acceptance.model_manifest_hash = None,
                "model_file_hash" => acceptance.model_file_hash = None,
                _ => unreachable!("covered identity fields"),
            }
            save_json(&acceptance_path, &acceptance).expect("mutated acceptance");

            let err = calibrate_lab_uncertainty(temp.path(), false)
                .expect_err("missing indexed model identity must fail calibration");
            assert!(err.to_string().contains("known-run-0"), "{field}: {err}");
            assert!(err.to_string().contains(field), "{field}: {err}");
            assert!(err.to_string().contains("missing"), "{field}: {err}");
        }
    }

    #[test]
    fn lab_calibration_rejects_mismatched_indexed_model_identity_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        write_lab_grade_calibration_samples(temp.path());
        let acceptance_path =
            calibration_acceptance_path(temp.path(), FaultLabel::Normal.as_str(), "known-run-0");
        let original: LabAcceptanceReport =
            serde_json::from_value(read_json(&acceptance_path).expect("acceptance"))
                .expect("acceptance json");

        for field in [
            "model_dataset_hash",
            "model_manifest_hash",
            "model_file_hash",
        ] {
            let mut acceptance = original.clone();
            match field {
                "model_dataset_hash" => {
                    acceptance.model_dataset_hash = Some("stale-dataset".to_string())
                }
                "model_manifest_hash" => {
                    acceptance.model_manifest_hash = Some("stale-manifest".to_string())
                }
                "model_file_hash" => acceptance.model_file_hash = Some("stale-model".to_string()),
                _ => unreachable!("covered identity fields"),
            }
            save_json(&acceptance_path, &acceptance).expect("mutated acceptance");

            let err = calibrate_lab_uncertainty(temp.path(), false)
                .expect_err("mismatched indexed model identity must fail calibration");
            assert!(err.to_string().contains("known-run-0"), "{field}: {err}");
            assert!(err.to_string().contains(field), "{field}: {err}");
            assert!(err.to_string().contains("mismatch"), "{field}: {err}");
        }
    }

    #[test]
    fn lab_calibration_fails_when_indexed_ml_result_is_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        write_lab_grade_calibration_samples(temp.path());
        std::fs::remove_file(
            temp.path()
                .join("lab-runs")
                .join(FaultLabel::Normal.as_str())
                .join("known-run-0")
                .join("runs")
                .join("known-run-0")
                .join("ml_result.json"),
        )
        .expect("remove ml result");

        let err = calibrate_lab_uncertainty(temp.path(), false)
            .expect_err("missing indexed ml_result.json must fail calibration");

        assert!(err.to_string().contains("ml_result.json"), "{err}");
    }

    #[test]
    fn lab_calibration_fails_when_indexed_comparison_is_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        write_lab_grade_calibration_samples(temp.path());
        std::fs::remove_file(
            temp.path()
                .join("lab-runs")
                .join(FaultLabel::Normal.as_str())
                .join("known-run-0")
                .join("comparison.json"),
        )
        .expect("remove comparison");

        let err = calibrate_lab_uncertainty(temp.path(), false)
            .expect_err("missing indexed comparison.json must fail calibration");

        assert!(err.to_string().contains("comparison.json"), "{err}");
    }

    #[test]
    fn lab_calibration_fails_when_accepted_known_diagnosis_events_are_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        write_lab_grade_calibration_samples(temp.path());
        std::fs::remove_file(
            temp.path()
                .join("lab-runs")
                .join(FaultLabel::Normal.as_str())
                .join("known-run-0")
                .join("runs")
                .join("known-run-0")
                .join("diagnosis_events.json"),
        )
        .expect("remove diagnosis events");

        let err = calibrate_lab_uncertainty(temp.path(), false)
            .expect_err("missing accepted known diagnosis_events.json must fail calibration");

        assert!(err.to_string().contains("diagnosis_events.json"), "{err}");
        assert!(err.to_string().contains("accepted known"), "{err}");
    }

    #[test]
    fn lab_calibration_fails_when_accepted_known_diagnosis_events_are_empty() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        write_lab_grade_calibration_samples(temp.path());
        let events_path =
            calibration_events_path(temp.path(), FaultLabel::Normal.as_str(), "known-run-0");
        save_json(&events_path, &Vec::<DiagnosisEvent>::new()).expect("empty diagnosis events");

        let err = calibrate_lab_uncertainty(temp.path(), false)
            .expect_err("empty accepted known diagnosis events must fail calibration");

        assert!(err.to_string().contains("diagnosis_events.json"), "{err}");
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn lab_calibration_fails_when_diagnosis_events_omit_expected_label() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        write_lab_grade_calibration_samples(temp.path());
        let events_path =
            calibration_events_path(temp.path(), FaultLabel::Normal.as_str(), "known-run-0");
        save_json(
            &events_path,
            &vec![calibration_diagnosis_event(
                "known-run-0",
                FaultLabel::Congestion,
            )],
        )
        .expect("wrong-label diagnosis events");

        let err = calibrate_lab_uncertainty(temp.path(), false)
            .expect_err("accepted known diagnosis events must contain expected label");

        assert!(err.to_string().contains("diagnosis_events.json"), "{err}");
        assert!(err.to_string().contains("expected label normal"), "{err}");
    }

    #[test]
    fn lab_calibration_reports_ood_behavior_and_disagreement_hotspots() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        write_lab_calibration_sample(
            temp.path(),
            "known",
            "known-run",
            Some(FaultLabel::Congestion),
            DiagnosisStatus::Known,
            calibration_ml_result("known-run", DiagnosisStatus::Known, 0.82, 0.18, 0.42, 2.0),
        );
        write_lab_calibration_sample_with_agreement(
            temp.path(),
            "false-positive",
            "fp-run",
            Some(FaultLabel::DnsFailure),
            DiagnosisStatus::OutOfDistribution,
            calibration_ml_result(
                "fp-run",
                DiagnosisStatus::OutOfDistribution,
                0.40,
                0.02,
                0.90,
                12.0,
            ),
            false,
        );
        write_lab_calibration_sample_with_agreement(
            temp.path(),
            "false-negative",
            "fn-run",
            None,
            DiagnosisStatus::Known,
            calibration_ml_result("fn-run", DiagnosisStatus::Known, 0.95, 0.44, 0.10, 1.0),
            false,
        );

        let report = calibrate_lab_uncertainty(temp.path(), false).expect("calibration");

        assert!(!report.applied);
        assert_eq!(report.ood.false_positive_runs, 1);
        assert_eq!(report.ood.false_negative_runs, 1);
        assert_eq!(report.ood.false_positive_rate, 0.5);
        assert_eq!(report.ood.false_negative_rate, 1.0);
        assert!(
            report
                .rule_ml_disagreement_hotspots
                .iter()
                .any(|hotspot| hotspot.scenario_id == "false-positive" && hotspot.rate == 1.0)
        );
        assert!(
            report
                .rule_ml_disagreement_hotspots
                .iter()
                .all(|hotspot| hotspot.scenario_id != "false-negative")
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
                connector_health: healthy_connector_health(),
                artifact_keys: Vec::new(),
                model_manifest_hash: None,
                model_file_hash: None,
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
                connector_health: healthy_connector_health(),
                artifact_keys: Vec::new(),
                model_manifest_hash: None,
                model_file_hash: None,
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
        provision_test_model(temp.path());
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

        assert!(!result.lab_run_dir.contains(".staged-"));
        assert!(!result.pipeline_run_dir.contains(".staged-"));
        assert!(!result.evidence_bundle.output.contains(".staged-"));
        assert!(
            result
                .evidence_bundle
                .files
                .iter()
                .all(|file| !file.source_path.contains(".staged-"))
        );
        let scenario_parent = temp.path().join("lab-runs/lab-congestion-001");
        assert!(
            std::fs::read_dir(&scenario_parent)
                .expect("scenario run parent")
                .all(|entry| !entry
                    .expect("scenario run entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.')),
            "successful lab run leaked a hidden stage"
        );

        assert!(
            temp.path().join("lab_run_index.json").exists(),
            "lab_run_index.json missing"
        );
        let validation = validate_lab_run(temp.path(), &result.run_id, None)
            .expect("indexed validate before cwd change");
        assert!(validation.passed, "{:?}", validation.failures);
        assert!(validation.model_manifest_hash.is_some());
        assert!(validation.model_file_hash.is_some());

        let _guard = CWD_LOCK.lock().expect("cwd lock");
        let previous_cwd = std::env::current_dir().expect("current dir");
        let other_cwd = tempfile::tempdir().expect("other cwd");
        std::env::set_current_dir(other_cwd.path()).expect("switch cwd");
        let validation_from_other_cwd = validate_lab_run(temp.path(), &result.run_id, None);
        let evidence_from_other_cwd = crate::storage::run_evidence(temp.path(), &result.run_id);
        std::env::set_current_dir(previous_cwd).expect("restore cwd");
        let validation_from_other_cwd =
            validation_from_other_cwd.expect("indexed validate from another cwd");
        assert!(
            validation_from_other_cwd.passed,
            "{:?}",
            validation_from_other_cwd.failures
        );
        let evidence_from_other_cwd = evidence_from_other_cwd.expect("evidence from another cwd");
        assert_eq!(evidence_from_other_cwd.report.run_id, result.run_id);
        assert!(
            temp.path()
                .join("model")
                .join(crate::ml::MODEL_CURRENT_FILE_NAME)
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

        let extra_path = temp.path().join("operator-note.txt");
        std::fs::write(&extra_path, "review note").expect("extra file");
        let explicit_bundle = export_evidence_bundle_with_context(
            PathBuf::from(&result.lab_run_dir),
            &result.run_id,
            temp.path().join("explicit-extra.zip"),
            EvidenceContext::Lab,
            &[crate::evidence_bundle::EvidenceBundleExtraFile {
                key: "operator_note".to_string(),
                path: extra_path,
                zip_path: "operator-note.txt".to_string(),
            }],
        )
        .expect("explicit bundle");
        let explicit_keys = explicit_bundle
            .files
            .iter()
            .map(|file| file.key.as_str())
            .collect::<BTreeSet<_>>();
        assert!(explicit_keys.contains("operator_note"));
        assert!(explicit_keys.contains("acceptance"));
        assert!(explicit_keys.contains("comparison"));

        let report =
            crate::storage::read_report(temp.path(), &result.run_id).expect("indexed report");
        let recommendation = report
            .recommendations
            .iter()
            .find(|recommendation| recommendation.diagnosis_symptom == Some(FaultLabel::Congestion))
            .expect("diagnosis recommendation");
        crate::hil_review::fail_before_publishing("lab_evidence_manifest");
        let interrupted = crate::hil_review::review_recommendation(
            temp.path(),
            &result.run_id,
            &recommendation.recommendation_id,
            HilState::Accepted,
            "confirmed lab label",
            "tester",
            Some(FaultLabel::Congestion),
        )
        .expect_err("injected lab review interruption");
        assert!(
            interrupted
                .to_string()
                .contains("injected HIL transaction failure"),
            "{interrupted}"
        );
        let pending_read = crate::storage::read_report(temp.path(), &result.run_id)
            .expect_err("pending lab review must fail closed");
        assert!(pending_read.to_string().contains("pending HIL transaction"));
        let pending_validation = validate_lab_run(temp.path(), &result.run_id, None)
            .expect_err("lab validation must reject a pending review transaction");
        assert!(
            pending_validation
                .to_string()
                .contains("pending HIL transaction")
        );
        let pending_index = read_lab_run_index(temp.path())
            .expect_err("lab index reads must reject a pending review transaction");
        assert!(
            pending_index
                .to_string()
                .contains("pending HIL transaction")
        );
        let pending_summary = summarize_lab_runs(temp.path())
            .expect_err("lab summaries must reject a pending review transaction");
        assert!(
            pending_summary
                .to_string()
                .contains("pending HIL transaction")
        );
        crate::hil_review::review_recommendation(
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
        let top_acceptance: LabAcceptanceReport = serde_json::from_value(
            read_json(PathBuf::from(&result.lab_run_dir).join("acceptance.json"))
                .expect("top acceptance"),
        )
        .expect("top acceptance json");
        assert!(top_acceptance.passed, "{:?}", top_acceptance.failures);
        let synced_bundle: EvidenceBundleManifest = serde_json::from_value(
            read_json(PathBuf::from(&result.lab_run_dir).join("evidence_bundle.json"))
                .expect("bundle manifest"),
        )
        .expect("bundle manifest json");
        assert!(
            synced_bundle
                .files
                .iter()
                .any(|file| file.key == "hil_feedback"),
            "{:?}",
            synced_bundle.files
        );
    }

    #[test]
    fn lab_first_then_standard_diagnosis_uses_one_owned_artifact_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        let scenario_path = repo_root().join("examples/scenarios/lab-congestion-001.yaml");

        run_lab_scenario(
            scenario_path,
            LabRunOptions {
                artifacts: temp.path().to_path_buf(),
            },
        )
        .expect("lab run");
        let standard = crate::diagnose_file(
            repo_root().join("data/samples/normal.csv"),
            temp.path(),
            None,
        )
        .expect("standard diagnosis after lab run");

        let expected_runs = std::fs::canonicalize(temp.path())
            .expect("canonical artifact root")
            .join("runs");
        assert!(
            standard.run_dir.starts_with(&expected_runs),
            "{} is outside {}",
            standard.run_dir.display(),
            expected_runs.display()
        );
        assert!(temp.path().join(".netdiag-artifact-root.json").is_file());
    }

    #[test]
    fn lab_index_failure_reports_published_and_preserves_final_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        let scenario_path = repo_root()
            .join("examples")
            .join("scenarios")
            .join("lab-congestion-001.yaml");
        let index_path = temp.path().join("lab_run_index.json");
        std::fs::create_dir(&index_path).expect("invalid index target fixture");
        let canonical_index_path =
            std::fs::canonicalize(&index_path).expect("canonical invalid index fixture");

        let error = run_lab_scenario(
            &scenario_path,
            LabRunOptions {
                artifacts: temp.path().to_path_buf(),
            },
        )
        .expect_err("invalid index target must fail");

        let NetdiagError::AtomicPublish {
            path,
            phase,
            source,
        } = error
        else {
            panic!("expected typed lab publication failure");
        };
        assert_eq!(phase, AtomicPublishPhase::Published);
        assert!(path.is_dir(), "published lab run must be retained");
        assert!(!path.display().to_string().contains(".staged-"));
        assert!(matches!(
            source.as_ref(),
            NetdiagError::Io {
                path,
                source: io_source,
            } if path == &canonical_index_path
                && io_source.kind() == std::io::ErrorKind::InvalidInput
                && io_source.to_string().contains("not a regular file")
        ));
        assert!(
            index_path.is_dir(),
            "invalid index target must be preserved"
        );
        let manifest: EvidenceBundleManifest = serde_json::from_value(
            read_json(path.join("evidence_bundle.json")).expect("evidence manifest"),
        )
        .expect("evidence manifest shape");
        assert!(!manifest.output.contains(".staged-"));
        assert!(
            manifest
                .files
                .iter()
                .all(|file| !file.source_path.contains(".staged-"))
        );
        let parent = path.parent().expect("lab scenario parent");
        assert!(
            std::fs::read_dir(parent)
                .expect("lab scenario entries")
                .all(|entry| !entry
                    .expect("lab scenario entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.')),
            "published index failure leaked a hidden stage"
        );
    }

    #[test]
    fn lab_run_fails_fast_when_shared_model_is_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let scenario_path = repo_root()
            .join("examples")
            .join("scenarios")
            .join("lab-congestion-001.yaml");

        let err = run_lab_scenario(
            &scenario_path,
            LabRunOptions {
                artifacts: temp.path().to_path_buf(),
            },
        )
        .expect_err("missing model should fail before lab run creation");

        let message = err.to_string();
        assert!(
            message.contains("model bundle is missing")
                && message.contains("current.json")
                && message.contains("complete legacy pair")
                && message.contains("train or explicitly rebuild"),
            "{err}"
        );
        assert!(!temp.path().join("model").exists());
        assert!(!temp.path().join("lab-runs").exists());
    }

    #[test]
    fn lab_run_executes_and_archives_one_scenario_generation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let artifacts = temp.path().join("artifacts");
        provision_test_model(&artifacts);
        let scenario_path = temp.path().join("scenario.yaml");
        let mut generation_a = scenario(FaultLabel::Normal, false);
        generation_a.id = "scenario-generation-a".to_string();
        generation_a.name = "Scenario generation A".to_string();
        generation_a.data_sources[0].endpoint = repo_root()
            .join("data")
            .join("samples")
            .join("normal.csv")
            .display()
            .to_string();
        generation_a.acceptance.allow_synthetic_model = true;
        let bytes_a = serde_yaml::to_string(&generation_a)
            .expect("serialize generation A")
            .into_bytes();
        std::fs::write(&scenario_path, &bytes_a).expect("write generation A");
        let snapshot =
            load_lab_scenario_snapshot(&scenario_path).expect("load generation A snapshot");

        let mut generation_b = generation_a.clone();
        generation_b.id = "scenario-generation-b".to_string();
        generation_b.name = "Scenario generation B".to_string();
        generation_b.data_sources[0].endpoint = "missing-generation-b.csv".to_string();
        let bytes_b = serde_yaml::to_string(&generation_b)
            .expect("serialize generation B")
            .into_bytes();
        std::fs::write(&scenario_path, &bytes_b).expect("replace source with generation B");

        let prepared =
            prepare_lab_inputs(&scenario_path, snapshot, &ResolvedBearerTokens::default())
                .expect("prepare generation A inputs");
        let capability = prepare_artifact_root(&artifacts).expect("artifact capability");
        let result = run_prepared_lab_scenario(
            prepared,
            LabRunOptions {
                artifacts: artifacts.clone(),
            },
            &capability,
        )
        .expect("run loaded generation A");

        assert_eq!(result.scenario_id, "scenario-generation-a");
        assert_eq!(
            std::fs::read(PathBuf::from(&result.lab_run_dir).join("scenario.yaml"))
                .expect("archived scenario"),
            bytes_a
        );
        assert_eq!(
            std::fs::read(&scenario_path).expect("current source generation"),
            bytes_b
        );
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
        let artifacts = temp.path().join("artifacts");
        provision_test_model(&artifacts);
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

        let result =
            run_lab_scenario(&scenario_path, LabRunOptions { artifacts }).expect("lab run");

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
        let artifacts = temp.path().join("artifacts");
        provision_test_model(&artifacts);
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

        let result =
            run_lab_scenario(&scenario_path, LabRunOptions { artifacts }).expect("lab run");
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
    fn lab_batch_and_summary_use_lab_index() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
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

        let lab_run_dir = PathBuf::from(
            batch.results[0]
                .lab_run_dir
                .as_deref()
                .expect("lab run directory"),
        );
        std::fs::write(lab_run_dir.join("comparison.json"), b"{")
            .expect("corrupt comparison fixture");
        let summary = summarize_lab_runs(temp.path()).expect("summary with corrupt comparison");
        assert_eq!(
            (summary.total_runs, summary.passed, summary.failed),
            (1, 0, 1)
        );
        assert!(summary.by_label.is_empty());
        assert!(summary.by_scenario.is_empty());
        assert!(summary.quality.is_empty());
        assert!(summary.diagnosis_statuses.is_empty());
        assert_eq!(summary.failures.len(), 1);
        assert!(summary.failures[0].failures[0].contains("comparison unavailable"));
    }
}

#[cfg(test)]
mod config_input_tests;
#[cfg(test)]
mod index_update_tests;
#[cfg(test)]
mod preflight_tests;
#[cfg(test)]
mod run_preparation_tests;
#[cfg(test)]
mod verification_policy_tests;
