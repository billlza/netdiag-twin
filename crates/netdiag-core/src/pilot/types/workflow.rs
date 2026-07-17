use super::{PilotPreflightReport, PilotReport};
use crate::models::ActionVerification;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PilotWorkflowOptions {
    pub artifacts: PathBuf,
    #[serde(default)]
    pub allow_active: bool,
    /// Explicitly authorizes trusted adapter execution for this workflow call.
    #[serde(default)]
    pub allow_adapter_execution: bool,
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
