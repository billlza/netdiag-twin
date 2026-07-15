use super::file_scan::{FileScanIssue, reason_for_io_error};
use super::{ReliabilityCheck, ReliabilityReasonCode};
use crate::error::NetdiagError;
use crate::models::ConnectorHealthStatus;
use std::path::Path;

pub(super) fn parser_reason(path: &Path) -> ReliabilityReasonCode {
    match path.extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("json") => {
            ReliabilityReasonCode::JsonInvalid
        }
        _ => ReliabilityReasonCode::MalformedPayload,
    }
}

pub(super) fn scan_issue_checks(
    name: &str,
    run_id: &str,
    issues: Vec<FileScanIssue>,
) -> Vec<ReliabilityCheck> {
    issues
        .into_iter()
        .map(|issue| scan_issue_check(name, run_id, issue))
        .collect()
}

pub(super) fn scan_issue_check(name: &str, run_id: &str, issue: FileScanIssue) -> ReliabilityCheck {
    error_check(name, Some(run_id), &issue.path, issue.reason, issue.message)
}

pub(super) fn netdiag_error_check(
    name: &str,
    run_id: Option<&str>,
    path: &Path,
    error: NetdiagError,
) -> ReliabilityCheck {
    let reason = reason_for_netdiag_error(&error);
    error_check(name, run_id, path, reason, error.to_string())
}

fn reason_for_netdiag_error(error: &NetdiagError) -> ReliabilityReasonCode {
    match error {
        NetdiagError::Io { source, .. } => reason_for_io_error(source),
        NetdiagError::Json(_) => ReliabilityReasonCode::JsonInvalid,
        NetdiagError::InvalidTrace(message) if path_confinement_message(message) => {
            ReliabilityReasonCode::PathEscapesArtifactRoot
        }
        NetdiagError::InvalidTrace(message) if message.contains("unknown run id") => {
            ReliabilityReasonCode::ArtifactMissing
        }
        _ => ReliabilityReasonCode::MalformedPayload,
    }
}

fn path_confinement_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("escape")
        || message.contains("outside the artifact root")
        || message.contains("must be relative to the artifact root")
        || message.contains("must be relative and confined")
}

pub(super) fn error_check(
    name: &str,
    run_id: Option<&str>,
    path: &Path,
    reason: ReliabilityReasonCode,
    message: String,
) -> ReliabilityCheck {
    ReliabilityCheck {
        name: name.to_string(),
        status: ConnectorHealthStatus::Error,
        run_id: run_id.map(str::to_string),
        artifact: Some(path.display().to_string()),
        reason_codes: vec![reason],
        message,
    }
}

pub(super) fn ok_check(name: &str, run_id: &str, path: &Path) -> ReliabilityCheck {
    ReliabilityCheck {
        name: name.to_string(),
        status: ConnectorHealthStatus::Ok,
        run_id: Some(run_id.to_string()),
        artifact: Some(path.display().to_string()),
        reason_codes: Vec::new(),
        message: "ok".to_string(),
    }
}

pub(super) fn aggregate_status(checks: &[ReliabilityCheck]) -> ConnectorHealthStatus {
    checks
        .iter()
        .map(|check| check.status)
        .max()
        .unwrap_or(ConnectorHealthStatus::Error)
}
