use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultLabel {
    Normal,
    Congestion,
    RandomLoss,
    DnsFailure,
    TlsFailure,
    UdpQuicBlocked,
}

impl FaultLabel {
    pub const ALL: [FaultLabel; 6] = [
        FaultLabel::Normal,
        FaultLabel::Congestion,
        FaultLabel::RandomLoss,
        FaultLabel::DnsFailure,
        FaultLabel::TlsFailure,
        FaultLabel::UdpQuicBlocked,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            FaultLabel::Normal => "normal",
            FaultLabel::Congestion => "congestion",
            FaultLabel::RandomLoss => "random_loss",
            FaultLabel::DnsFailure => "dns_failure",
            FaultLabel::TlsFailure => "tls_failure",
            FaultLabel::UdpQuicBlocked => "udp_quic_blocked",
        }
    }

    pub fn from_index(index: usize) -> FaultLabel {
        Self::ALL.get(index).copied().unwrap_or(FaultLabel::Normal)
    }

    pub fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|label| *label == self)
            .unwrap_or(0)
    }
}

impl fmt::Display for FaultLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FaultLabel {
    type Err = ();

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "normal" => Ok(FaultLabel::Normal),
            "congestion" => Ok(FaultLabel::Congestion),
            "random_loss" => Ok(FaultLabel::RandomLoss),
            "dns_failure" => Ok(FaultLabel::DnsFailure),
            "tls_failure" => Ok(FaultLabel::TlsFailure),
            "udp_quic_blocked" => Ok(FaultLabel::UdpQuicBlocked),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HilState {
    #[default]
    Unreviewed,
    Accepted,
    Rejected,
    Uncertain,
    RequiresRerun,
}

impl HilState {
    pub fn as_str(self) -> &'static str {
        match self {
            HilState::Unreviewed => "unreviewed",
            HilState::Accepted => "accepted",
            HilState::Rejected => "rejected",
            HilState::Uncertain => "uncertain",
            HilState::RequiresRerun => "requires_rerun",
        }
    }
}

impl fmt::Display for HilState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HilState {
    type Err = ();

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "unreviewed" | "pending" | "pending_review" => Ok(HilState::Unreviewed),
            "accepted" | "accept" | "approved" | "approve" => Ok(HilState::Accepted),
            "rejected" | "reject" | "denied" | "deny" => Ok(HilState::Rejected),
            "uncertain" | "unsure" => Ok(HilState::Uncertain),
            "requires_rerun" | "requires-rerun" | "rerun" => Ok(HilState::RequiresRerun),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRecord {
    pub timestamp: DateTime<Utc>,
    pub latency_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_rate: f64,
    pub retransmission_rate: f64,
    pub timeout_events: f64,
    pub retry_events: f64,
    pub throughput_mbps: f64,
    pub dns_failure_events: f64,
    pub tls_failure_events: f64,
    pub quic_blocked_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSchema {
    pub columns: Vec<String>,
    pub rows: usize,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub sample: String,
    pub ingested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestWarning {
    pub row: Option<usize>,
    pub column: String,
    pub reason: String,
    pub fallback: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricQuality {
    #[default]
    Measured,
    Estimated,
    Fallback,
    Missing,
}

impl MetricQuality {
    pub fn as_str(self) -> &'static str {
        match self {
            MetricQuality::Measured => "measured",
            MetricQuality::Estimated => "estimated",
            MetricQuality::Fallback => "fallback",
            MetricQuality::Missing => "missing",
        }
    }

    pub fn is_trustworthy(self) -> bool {
        matches!(self, MetricQuality::Measured | MetricQuality::Estimated)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricProvenance {
    pub field: String,
    pub quality: MetricQuality,
    pub source: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    pub records: Vec<TraceRecord>,
    pub schema: TraceSchema,
    #[serde(default)]
    pub warnings: Vec<IngestWarning>,
    #[serde(default)]
    pub metric_provenance: Vec<MetricProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfBudget {
    pub schema_version: u32,
    pub generated_at: DateTime<Utc>,
    pub threshold_percent: f64,
    pub scenarios: BTreeMap<String, PerfBudgetEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfBudgetEntry {
    pub max_millis: f64,
    pub rows: usize,
    pub iterations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionStats {
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub mean: f64,
    pub std: f64,
    pub min: f64,
    pub max: f64,
}

impl Default for DistributionStats {
    fn default() -> Self {
        Self {
            p50: 0.0,
            p95: 0.0,
            p99: 0.0,
            mean: 0.0,
            std: 0.0,
            min: 0.0,
            max: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowLatencyStats {
    pub p50: f64,
    pub mean: f64,
    pub p95: f64,
    pub p99: f64,
    pub std: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputStats {
    pub mean: f64,
    pub p95: f64,
    pub min: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryWindow {
    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,
    pub count: usize,
    pub latency_ms: WindowLatencyStats,
    pub jitter_ms: DistributionStats,
    pub packet_loss_rate: f64,
    pub retransmission_rate: f64,
    pub timeout_events: f64,
    pub retry_events: f64,
    pub throughput_mbps: ThroughputStats,
    pub dns_failure_events: f64,
    pub tls_failure_events: f64,
    pub quic_blocked_ratio: f64,
    pub raw_rows: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverallTelemetry {
    pub duration_s: f64,
    pub samples: usize,
    pub latency: DistributionStats,
    pub jitter_ms: DistributionStats,
    pub packet_loss_rate: f64,
    pub retransmission_rate: f64,
    pub timeout_events: f64,
    pub retry_events: f64,
    pub throughput_mbps: ThroughputStats,
    pub dns_failure_events: f64,
    pub tls_failure_events: f64,
    pub quic_blocked_ratio: f64,
    pub window_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySummary {
    pub overall: OverallTelemetry,
    pub windows: Vec<TelemetryWindow>,
    #[serde(default)]
    pub metric_provenance: Vec<MetricProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub start_ts: DateTime<Utc>,
    pub end_ts: DateTime<Utc>,
    pub bucket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub name: String,
    pub value: f64,
    pub unit: String,
    pub baseline: Option<f64>,
    pub delta_pct: Option<f64>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub source: String,
    pub artifact: String,
    pub offset: Option<String>,
    #[serde(default)]
    pub details: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub run_id: String,
    pub method: String,
    pub symptom: FaultLabel,
    pub severity: Severity,
    pub confidence: f64,
    pub window: TimeWindow,
    pub supporting_metrics: Vec<MetricPoint>,
    pub raw_evidence_refs: Vec<EvidenceRef>,
    pub counter_evidence: Vec<String>,
    pub recommendation_need_approval: bool,
    pub hil_state: HilState,
    pub why: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosisEvent {
    pub event_id: String,
    pub evidence: EvidenceRecord,
    pub source: String,
    pub model_probability: Option<BTreeMap<String, f64>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub label: FaultLabel,
    pub prob: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureImportance {
    pub name: String,
    pub importance: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlResult {
    pub method: String,
    pub run_id: String,
    pub top_predictions: Vec<Prediction>,
    pub top_features: Vec<FeatureImportance>,
    pub features: BTreeMap<String, f64>,
    #[serde(default)]
    pub feature_quality: BTreeMap<String, MetricQuality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_manifest: Option<ModelManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelManifest {
    pub schema_version: String,
    pub model_name: String,
    pub model_kind: String,
    pub created_at: DateTime<Utc>,
    pub training_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_hash_sha256: Option<String>,
    pub model_file: String,
    pub feature_names: Vec<String>,
    pub labels: Vec<String>,
    pub training_examples: usize,
    #[serde(default)]
    pub label_distribution: BTreeMap<String, usize>,
    pub feature_count: usize,
    pub synthetic_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub training_config: Option<ModelTrainingConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation: Option<ModelEvaluation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelTrainingConfig {
    pub validation_split: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shuffle_seed: Option<u64>,
    pub stratified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelEvaluation {
    pub validation_examples: usize,
    pub accuracy: f64,
    pub macro_f1: f64,
    #[serde(default)]
    pub per_label: BTreeMap<String, LabelMetrics>,
    pub confusion_matrix: BTreeMap<String, BTreeMap<String, usize>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelMetrics {
    pub support: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatIfResult {
    pub action_id: String,
    pub action_notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_action: Option<TwinPolicyAction>,
    pub topology: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topology_snapshot: Option<TopologyModel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_topology_snapshot: Option<TopologyModel>,
    pub baseline: BTreeMap<String, serde_json::Value>,
    pub proposed: BTreeMap<String, serde_json::Value>,
    pub delta: BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TwinPolicyAction {
    pub id: String,
    pub kind: TwinPolicyActionKind,
    #[serde(default)]
    pub target: TwinPolicyTarget,
    #[serde(default)]
    pub parameters: BTreeMap<String, serde_json::Value>,
    pub impact: TwinPolicyImpact,
    pub qoe_risk: String,
    pub notes: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TwinPolicyActionKind {
    Reroute,
    QueueLimit,
    CapacityChange,
    LinkDisable,
    TrafficShift,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct TwinPolicyTarget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct TwinPolicyImpact {
    #[serde(default)]
    pub latency_delta_pct: f64,
    #[serde(default)]
    pub loss_delta_pct: f64,
    #[serde(default)]
    pub throughput_delta_pct: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyModel {
    pub key: String,
    pub name: String,
    pub nodes: Vec<TopologyNode>,
    pub links: Vec<TopologyLink>,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyNode {
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TopologyLink {
    pub id: String,
    pub source: String,
    pub target: String,
    pub latency_ms: f64,
    pub loss_pct: f64,
    pub capacity_mbps: f64,
    #[serde(default)]
    pub metadata: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationKind {
    #[default]
    DiagnosisMitigation,
    WhatIfAction,
    Monitoring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    #[serde(default)]
    pub recommendation_id: String,
    pub run_id: String,
    #[serde(default)]
    pub kind: RecommendationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what_if_action_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnosis_symptom: Option<FaultLabel>,
    pub recommended_action: String,
    pub expected_effect: String,
    pub risk_level: String,
    pub confidence: f64,
    pub recommendation_need_approval: bool,
    pub hil_state: HilState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<HilReview>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HilReview {
    pub state: HilState,
    pub notes: String,
    pub reviewer: String,
    pub reviewed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_label: Option<FaultLabel>,
}

impl HilReview {
    pub fn new(state: HilState, notes: impl Into<String>, reviewer: impl Into<String>) -> Self {
        Self::with_final_label(state, notes, reviewer, None)
    }

    pub fn with_final_label(
        state: HilState,
        notes: impl Into<String>,
        reviewer: impl Into<String>,
        final_label: Option<FaultLabel>,
    ) -> Self {
        Self {
            state,
            notes: notes.into(),
            reviewer: reviewer.into(),
            reviewed_at: Utc::now(),
            final_label,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HilFeedbackRecord {
    pub run_id: String,
    pub recommendation_id: String,
    pub review: HilReview,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HilReviewSummary {
    pub total: usize,
    pub pending: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub uncertain: usize,
    pub requires_rerun: usize,
}

impl HilReviewSummary {
    pub fn from_recommendations(recommendations: &[Recommendation]) -> Self {
        let mut summary = HilReviewSummary {
            total: recommendations.len(),
            ..HilReviewSummary::default()
        };
        for recommendation in recommendations {
            match recommendation.hil_state {
                HilState::Unreviewed => summary.pending += 1,
                HilState::Accepted => summary.accepted += 1,
                HilState::Rejected => summary.rejected += 1,
                HilState::Uncertain => summary.uncertain += 1,
                HilState::RequiresRerun => summary.requires_rerun += 1,
            }
        }
        summary
    }

    pub fn run_status(&self) -> &'static str {
        if self.requires_rerun > 0 {
            "requires_rerun"
        } else if self.pending > 0 {
            "pending_review"
        } else if self.total > 0 {
            "reviewed"
        } else {
            "complete"
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    pub run_id: String,
    pub sample: String,
    pub created_at: DateTime<Utc>,
    pub trace_rows: usize,
    pub artifact_paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunIndexEntry {
    pub run_id: String,
    pub sample: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
    pub run_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunArtifactEntry {
    pub key: String,
    pub path: String,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunHistoryEntry {
    pub run_id: String,
    pub sample: String,
    pub created_at: DateTime<Utc>,
    pub status: String,
    pub run_dir: String,
    #[serde(default)]
    pub root_causes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_top_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_top_probability: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_kind: Option<String>,
    #[serde(default)]
    pub synthetic_model: bool,
    #[serde(default)]
    pub measurement_quality: Vec<MetricProvenance>,
    #[serde(default)]
    pub hil_summary: HilReviewSummary,
    #[serde(default)]
    pub artifact_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunComparison {
    pub left: RunHistoryEntry,
    pub right: RunHistoryEntry,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_p95_delta_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_delta_pct: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub throughput_delta_pct: Option<f64>,
    pub ml_label_changed: bool,
    pub new_root_causes: Vec<String>,
    pub resolved_root_causes: Vec<String>,
    pub review_status_changed: bool,
    pub recommendation_state_changes: Vec<RecommendationStateChange>,
    pub measurement_quality_changes: Vec<MetricQualityChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationStateChange {
    pub recommendation_id: String,
    pub left_state: HilState,
    pub right_state: HilState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricQualityChange {
    pub field: String,
    pub left_quality: MetricQuality,
    pub right_quality: MetricQuality,
}
