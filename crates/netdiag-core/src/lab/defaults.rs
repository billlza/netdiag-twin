use crate::models::{ConnectorHealthStatus, DiagnosisStatus};

pub(super) fn default_lookback_secs() -> i64 {
    300
}

pub(super) fn default_step_secs() -> u64 {
    15
}

pub(super) fn default_packet_limit() -> usize {
    5000
}

pub(super) fn default_timeout_secs() -> u64 {
    20
}

pub(super) fn default_interval_secs() -> u64 {
    1
}

pub(super) fn default_min_rule_confidence() -> f64 {
    0.75
}

pub(super) fn default_min_ml_probability() -> f64 {
    0.70
}

pub(super) fn default_true() -> bool {
    true
}

pub(super) fn default_allowed_connector_status() -> Vec<ConnectorHealthStatus> {
    vec![ConnectorHealthStatus::Ok, ConnectorHealthStatus::Degraded]
}

pub(super) fn default_allowed_diagnosis_statuses() -> Vec<DiagnosisStatus> {
    vec![DiagnosisStatus::Known]
}

pub(super) fn default_required_artifacts() -> Vec<String> {
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
