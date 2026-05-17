use crate::evidence_bundle::EvidenceBundleManifest;
use crate::models::{ActionVerification, ConnectorHealthSnapshot, ConnectorHealthStatus};
use crate::reliability::ReliabilityCheck;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotManifest {
    pub schema: String,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub safety: PilotSafety,
    #[serde(default)]
    pub sources: Vec<PilotSource>,
    #[serde(default)]
    pub gates: PilotGates,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PilotSafety {
    #[serde(default)]
    pub allow_active: bool,
    #[serde(default)]
    pub retention_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotGates {
    #[serde(default = "default_allowed_connector_status")]
    pub allowed_connector_status: Vec<ConnectorHealthStatus>,
}

impl Default for PilotGates {
    fn default() -> Self {
        Self {
            allowed_connector_status: default_allowed_connector_status(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotSource {
    pub name: String,
    pub kind: PilotSourceKind,
    pub endpoint: String,
    #[serde(default)]
    pub role: PilotSourceRole,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub bearer_token_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapping: Option<String>,
    #[serde(default)]
    pub collection: PilotCollection,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotSourceKind {
    #[serde(alias = "trace-file")]
    TraceFile,
    #[serde(alias = "adapter-sample")]
    AdapterSample,
    #[serde(alias = "http-json")]
    HttpJson,
    #[serde(alias = "prometheus-query")]
    PrometheusQuery,
    #[serde(alias = "prometheus-metrics")]
    PrometheusMetrics,
    #[serde(alias = "otlp-grpc")]
    OtlpGrpc,
    #[serde(alias = "native-pcap")]
    NativePcap,
    #[serde(alias = "system-counters")]
    SystemCounters,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotSourceRole {
    #[default]
    Primary,
    Corroborating,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotCollection {
    #[serde(default = "default_pilot_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_pilot_lookback_secs")]
    pub lookback_secs: i64,
    #[serde(default = "default_pilot_step_secs")]
    pub step_secs: u64,
    #[serde(default = "default_pilot_packet_limit")]
    pub packet_limit: usize,
    #[serde(default = "default_pilot_interval_secs")]
    pub interval_secs: u64,
}

impl Default for PilotCollection {
    fn default() -> Self {
        Self {
            timeout_secs: default_pilot_timeout_secs(),
            lookback_secs: default_pilot_lookback_secs(),
            step_secs: default_pilot_step_secs(),
            packet_limit: default_pilot_packet_limit(),
            interval_secs: default_pilot_interval_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotOptions {
    pub artifacts: PathBuf,
    #[serde(default)]
    pub allow_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotPreflightReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub pilot_id: String,
    pub passed: bool,
    #[serde(default)]
    pub source_inventory: Vec<PilotSourceInventory>,
    #[serde(default)]
    pub checks: Vec<ReliabilityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub pilot_id: String,
    pub pilot_name: String,
    pub read_only: bool,
    pub passed: bool,
    pub run_id: String,
    pub pilot_run_dir: String,
    #[serde(default)]
    pub source_inventory: Vec<PilotSourceInventory>,
    #[serde(default)]
    pub connector_health: Vec<ConnectorHealthSnapshot>,
    pub diagnosis_summary: PilotDiagnosisSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_bundle: Option<EvidenceBundleManifest>,
    #[serde(default)]
    pub checks: Vec<ReliabilityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotSourceInventory {
    pub name: String,
    pub kind: PilotSourceKind,
    pub role: PilotSourceRole,
    pub endpoint: String,
    pub active: bool,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotDiagnosisSummary {
    pub diagnosis_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_label: Option<String>,
    pub root_causes: Vec<String>,
    pub recommendation_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PilotWorkflowOptions {
    pub artifacts: PathBuf,
    #[serde(default)]
    pub allow_active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<PilotWorkflowVerificationOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotWorkflowVerificationOptions {
    pub after_run_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotWorkflowReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub pilot_id: String,
    pub passed: bool,
    #[serde(default)]
    pub phases: Vec<PilotWorkflowPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight: Option<PilotPreflightReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pilot_run: Option<PilotReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<ActionVerification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotWorkflowPhase {
    pub name: String,
    pub status: PilotWorkflowPhaseStatus,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotWorkflowPhaseStatus {
    Passed,
    Failed,
    Pending,
    Skipped,
}

fn default_allowed_connector_status() -> Vec<ConnectorHealthStatus> {
    vec![ConnectorHealthStatus::Ok, ConnectorHealthStatus::Degraded]
}

fn default_pilot_timeout_secs() -> u64 {
    10
}

fn default_pilot_lookback_secs() -> i64 {
    300
}

fn default_pilot_step_secs() -> u64 {
    15
}

fn default_pilot_packet_limit() -> usize {
    256
}

fn default_pilot_interval_secs() -> u64 {
    1
}
