use crate::evidence_bundle::EvidenceBundleManifest;
use crate::models::{ConnectorHealthSnapshot, ConnectorHealthStatus};
use crate::reliability::ReliabilityCheck;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

mod collection;
mod source_options;
mod workflow;
pub use collection::*;
pub use source_options::*;
pub use workflow::*;

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
    /// Manifest-relative directory containing trusted adapter code.
    ///
    /// Adapter endpoints are canonicalized and must remain inside this root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_execution_root: Option<String>,
    /// Absolute Python executable explicitly trusted for adapter execution.
    ///
    /// Required on Windows, where inherited PATH ACLs are not assumed safe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_python_interpreter: Option<String>,
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
    pub adapter: PilotAdapterOptions,
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
pub struct PilotOptions {
    pub artifacts: PathBuf,
    #[serde(default)]
    pub allow_active: bool,
    /// Explicitly authorizes execution of trusted adapter code for this call.
    #[serde(default)]
    pub allow_adapter_execution: bool,
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

fn default_allowed_connector_status() -> Vec<ConnectorHealthStatus> {
    vec![ConnectorHealthStatus::Ok, ConnectorHealthStatus::Degraded]
}
