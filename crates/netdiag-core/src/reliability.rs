use crate::error::{IoContext, NetdiagError, Result};
use crate::models::ConnectorHealthStatus;
use crate::storage::{
    list_run_locations, resolve_run_location, run_artifacts, write_file_atomically,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

mod diagnostics;
mod file_scan;
mod secrets;
pub(crate) use file_scan::{StrictNamedScanLimits, scan_named_files_strict};
pub(crate) use secrets::{
    is_sensitive_parameter_key, query_contains_sensitive_or_ambiguous_syntax,
};

use diagnostics::{
    aggregate_status, error_check, netdiag_error_check, ok_check, parser_reason, scan_issue_check,
    scan_issue_checks,
};
use file_scan::{
    FileScan, confined_modified_time, read_confined_text, reason_for_io_error, scan_recursive,
    scan_top_level,
};
use secrets::inspect_document;
pub use secrets::{redact_json_value, redact_string, redact_url};

const RELIABILITY_SCHEMA: &str = "netdiag-reliability-report/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReliabilityReasonCode {
    Timeout,
    PartialData,
    MalformedPayload,
    MissingMetric,
    PermissionDenied,
    Cancelled,
    UnreachableEndpoint,
    ArtifactMissing,
    JsonInvalid,
    PathEscapesArtifactRoot,
    ModelHashMissing,
    BundleStale,
    SecretLeak,
    RetryPolicyInvalid,
}

impl ReliabilityReasonCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ReliabilityReasonCode::Timeout => "timeout",
            ReliabilityReasonCode::PartialData => "partial_data",
            ReliabilityReasonCode::MalformedPayload => "malformed_payload",
            ReliabilityReasonCode::MissingMetric => "missing_metric",
            ReliabilityReasonCode::PermissionDenied => "permission_denied",
            ReliabilityReasonCode::Cancelled => "cancelled",
            ReliabilityReasonCode::UnreachableEndpoint => "unreachable_endpoint",
            ReliabilityReasonCode::ArtifactMissing => "artifact_missing",
            ReliabilityReasonCode::JsonInvalid => "json_invalid",
            ReliabilityReasonCode::PathEscapesArtifactRoot => "path_escapes_artifact_root",
            ReliabilityReasonCode::ModelHashMissing => "model_hash_missing",
            ReliabilityReasonCode::BundleStale => "bundle_stale",
            ReliabilityReasonCode::SecretLeak => "secret_leak",
            ReliabilityReasonCode::RetryPolicyInvalid => "retry_policy_invalid",
        }
    }
}

impl std::fmt::Display for ReliabilityReasonCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityCheckOptions {
    pub artifact_root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityCheckReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub artifact_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub status: ConnectorHealthStatus,
    #[serde(default)]
    pub checks: Vec<ReliabilityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityCheck {
    pub name: String,
    pub status: ConnectorHealthStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(default)]
    pub reason_codes: Vec<ReliabilityReasonCode>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityRetryPolicy {
    pub max_attempts: usize,
    pub initial_backoff_millis: u64,
    pub max_backoff_millis: u64,
}

impl Default for ReliabilityRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_millis: 100,
            max_backoff_millis: 1_000,
        }
    }
}

impl ReliabilityRetryPolicy {
    pub fn validate(self) -> std::result::Result<(), String> {
        if self.max_attempts == 0 {
            return Err("max_attempts must be at least 1".to_string());
        }
        if self.initial_backoff_millis == 0 {
            return Err("initial_backoff_millis must be at least 1".to_string());
        }
        if self.max_backoff_millis < self.initial_backoff_millis {
            return Err("max_backoff_millis must be >= initial_backoff_millis".to_string());
        }
        Ok(())
    }

    pub fn retry_delays(self) -> std::result::Result<Vec<Duration>, String> {
        self.validate()?;
        if self.max_attempts <= 1 {
            return Ok(Vec::new());
        }
        let mut next = self.initial_backoff_millis;
        let mut delays = Vec::new();
        for _ in 1..self.max_attempts {
            delays.push(Duration::from_millis(next));
            next = next.saturating_mul(2).min(self.max_backoff_millis);
        }
        Ok(delays)
    }
}

pub fn check_reliability(options: ReliabilityCheckOptions) -> Result<ReliabilityCheckReport> {
    let artifact_root = options.artifact_root;
    let requested_run_id = options.run_id;
    let mut checks = Vec::new();
    checks.push(check_artifact_root_exists(&artifact_root));
    let mut discovery_failed = false;
    let locations_result = if let Some(run_id) = &requested_run_id {
        resolve_run_location(&artifact_root, run_id).map(|location| vec![location])
    } else {
        list_run_locations(&artifact_root)
    };
    let locations = match locations_result {
        Ok(locations) => locations,
        Err(error) => {
            discovery_failed = true;
            checks.push(netdiag_error_check(
                "run location readable",
                requested_run_id.as_deref(),
                &artifact_root,
                error,
            ));
            Vec::new()
        }
    };
    if locations.is_empty() && !discovery_failed {
        checks.push(ReliabilityCheck {
            name: "runs discovered".to_string(),
            status: ConnectorHealthStatus::Degraded,
            run_id: None,
            artifact: None,
            reason_codes: vec![ReliabilityReasonCode::ArtifactMissing],
            message: "no run manifests were found under the artifact root".to_string(),
        });
    }
    for location in locations {
        let Some(run_id) = location
            .run_dir
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_string)
        else {
            checks.push(error_check(
                "run id readable",
                None,
                &location.run_dir,
                ReliabilityReasonCode::MalformedPayload,
                "resolved run directory does not have a valid UTF-8 identifier".to_string(),
            ));
            continue;
        };
        checks.extend(check_run_required_files(&location.run_dir, &run_id));
        checks.extend(check_run_content(&location.run_dir, &run_id));
        if let Some(context_dir) = &location.lab_run_dir {
            checks.extend(check_context_content(context_dir, &run_id));
        }
        checks.extend(check_run_artifact_paths(&location.artifact_root, &run_id));
        checks.push(check_model_hashes(&location.artifact_root, &run_id));
        checks.push(check_bundle_freshness(&location.run_dir, &run_id));
    }
    let status = aggregate_status(&checks);
    Ok(ReliabilityCheckReport {
        schema: RELIABILITY_SCHEMA.to_string(),
        generated_at: Utc::now(),
        artifact_root: artifact_root.display().to_string(),
        run_id: requested_run_id,
        status,
        checks,
    })
}

pub fn classify_connector_error(message: &str) -> ReliabilityReasonCode {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timeout") || lower.contains("timed out") {
        ReliabilityReasonCode::Timeout
    } else if lower.contains("permission") || lower.contains("denied") {
        ReliabilityReasonCode::PermissionDenied
    } else if lower.contains("cancel") {
        ReliabilityReasonCode::Cancelled
    } else if lower.contains("missing") && lower.contains("metric") {
        ReliabilityReasonCode::MissingMetric
    } else if lower.contains("malformed") || lower.contains("json") || lower.contains("parse") {
        ReliabilityReasonCode::MalformedPayload
    } else if lower.contains("partial") || lower.contains("empty") {
        ReliabilityReasonCode::PartialData
    } else {
        ReliabilityReasonCode::UnreachableEndpoint
    }
}

fn check_artifact_root_exists(artifact_root: &Path) -> ReliabilityCheck {
    match fs::metadata(artifact_root) {
        Ok(metadata) if metadata.is_dir() => ReliabilityCheck {
            name: "artifact root exists".to_string(),
            status: ConnectorHealthStatus::Ok,
            run_id: None,
            artifact: Some(artifact_root.display().to_string()),
            reason_codes: Vec::new(),
            message: "artifact root is present".to_string(),
        },
        Ok(_) => error_check(
            "artifact root exists",
            None,
            artifact_root,
            ReliabilityReasonCode::ArtifactMissing,
            "artifact root is not a directory".to_string(),
        ),
        Err(error) => error_check(
            "artifact root exists",
            None,
            artifact_root,
            reason_for_io_error(&error),
            format!(
                "could not read artifact root metadata for {}: {error}",
                artifact_root.display()
            ),
        ),
    }
}

fn check_run_required_files(run_dir: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    ["manifest.json", "report.json"]
        .into_iter()
        .map(|file_name| {
            let path = run_dir.join(file_name);
            match fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() => {
                    ok_check("required artifact exists", run_id, &path)
                }
                Ok(_) => error_check(
                    "required artifact exists",
                    Some(run_id),
                    &path,
                    ReliabilityReasonCode::ArtifactMissing,
                    format!("{file_name} is not a regular file"),
                ),
                Err(error) => error_check(
                    "required artifact exists",
                    Some(run_id),
                    &path,
                    reason_for_io_error(&error),
                    format!("could not inspect required artifact {file_name}: {error}"),
                ),
            }
        })
        .collect()
}

fn check_run_content(run_dir: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    check_content_scan(
        scan_recursive(run_dir, &["json"]),
        "artifact content scan",
        Some("json parseable"),
        "secret redaction",
        run_id,
        "artifact appears to contain an unredacted credential value",
    )
}

fn check_context_content(context_dir: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    check_content_scan(
        scan_top_level(context_dir, &["json", "yaml", "yml", "md"]),
        "context content scan",
        Some("context json parseable"),
        "context secret redaction",
        run_id,
        "context artifact appears to contain an unredacted credential value",
    )
}

fn check_content_scan(
    scan: FileScan,
    scan_name: &str,
    json_check_name: Option<&str>,
    secret_check_name: &str,
    run_id: &str,
    leak_message: &str,
) -> Vec<ReliabilityCheck> {
    let FileScan { files, issues } = scan;
    let mut checks = scan_issue_checks(scan_name, run_id, issues);
    for file in files {
        let path = file.path().to_path_buf();
        match file.read_text() {
            Ok(body) => match inspect_document(&path, &body) {
                Ok(leaked) => {
                    if let Some(name) = json_check_name.filter(|_| is_json_file(&path)) {
                        checks.push(ok_check(name, run_id, &path));
                    }
                    if leaked {
                        checks.push(error_check(
                            secret_check_name,
                            Some(run_id),
                            &path,
                            ReliabilityReasonCode::SecretLeak,
                            leak_message.to_string(),
                        ));
                    } else {
                        checks.push(ok_check(secret_check_name, run_id, &path));
                    }
                }
                Err(message) => {
                    if let Some(name) = json_check_name.filter(|_| is_json_file(&path)) {
                        checks.push(error_check(
                            name,
                            Some(run_id),
                            &path,
                            ReliabilityReasonCode::JsonInvalid,
                            message.clone(),
                        ));
                    }
                    checks.push(error_check(
                        secret_check_name,
                        Some(run_id),
                        &path,
                        parser_reason(&path),
                        message,
                    ));
                }
            },
            Err(issue) => checks.push(scan_issue_check(scan_name, run_id, issue)),
        }
    }
    checks
}

fn is_json_file(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
}

fn check_run_artifact_paths(artifact_root: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    let mut checks = Vec::new();
    let location = match resolve_run_location(artifact_root, run_id) {
        Ok(location) => location,
        Err(error) => {
            checks.push(netdiag_error_check(
                "manifest artifact paths readable",
                Some(run_id),
                artifact_root,
                error,
            ));
            return checks;
        }
    };
    let allowed = match fs::canonicalize(&location.run_dir) {
        Ok(path) => path,
        Err(error) => {
            checks.push(error_check(
                "manifest artifact paths readable",
                Some(run_id),
                &location.run_dir,
                reason_for_io_error(&error),
                format!(
                    "could not canonicalize run directory {}: {error}",
                    location.run_dir.display()
                ),
            ));
            return checks;
        }
    };
    let artifacts = match run_artifacts(artifact_root, run_id) {
        Ok(artifacts) => artifacts,
        Err(error) => {
            checks.push(netdiag_error_check(
                "manifest artifact paths readable",
                Some(run_id),
                &location.run_dir.join("manifest.json"),
                error,
            ));
            return checks;
        }
    };
    for artifact in artifacts {
        let path = PathBuf::from(&artifact.path);
        if !artifact.exists {
            checks.push(error_check(
                "manifest artifact exists",
                Some(run_id),
                &path,
                ReliabilityReasonCode::ArtifactMissing,
                format!("manifest artifact {} is missing", artifact.key),
            ));
            continue;
        }
        let canonical = match fs::canonicalize(&path) {
            Ok(path) => path,
            Err(error) => {
                checks.push(error_check(
                    "manifest path confined",
                    Some(run_id),
                    &path,
                    reason_for_io_error(&error),
                    format!(
                        "could not canonicalize manifest artifact {} at {}: {error}",
                        artifact.key,
                        path.display()
                    ),
                ));
                continue;
            }
        };
        if canonical.starts_with(&allowed) {
            checks.push(ok_check("manifest path confined", run_id, &canonical));
        } else {
            checks.push(error_check(
                "manifest path confined",
                Some(run_id),
                &canonical,
                ReliabilityReasonCode::PathEscapesArtifactRoot,
                "manifest artifact path is outside the resolved run directory".to_string(),
            ));
        }
    }
    checks
}

fn check_model_hashes(artifact_root: &Path, run_id: &str) -> ReliabilityCheck {
    let location = match resolve_run_location(artifact_root, run_id) {
        Ok(location) => location,
        Err(error) => {
            return netdiag_error_check(
                "model identity hashes present",
                Some(run_id),
                artifact_root,
                error,
            );
        }
    };
    let report_path = location.run_dir.join("report.json");
    let body = match read_confined_text(&location.run_dir, &report_path) {
        Ok(body) => body,
        Err(issue) => return scan_issue_check("model identity hashes present", run_id, issue),
    };
    let report = match crate::strict_json::from_slice::<crate::report::Report>(body.as_bytes()) {
        Ok(report) => report,
        Err(error) => {
            return error_check(
                "model identity hashes present",
                Some(run_id),
                &report_path,
                ReliabilityReasonCode::JsonInvalid,
                format!(
                    "invalid report JSON: {}",
                    crate::strict_json::error_summary(&error)
                ),
            );
        }
    };
    if report.run_id != run_id {
        return error_check(
            "model identity hashes present",
            Some(run_id),
            &report_path,
            ReliabilityReasonCode::MalformedPayload,
            format!(
                "report run id {} does not match requested run id {run_id}",
                report.run_id
            ),
        );
    }
    if report.model_manifest_hash.is_some() && report.model_file_hash.is_some() {
        ReliabilityCheck {
            name: "model identity hashes present".to_string(),
            status: ConnectorHealthStatus::Ok,
            run_id: Some(run_id.to_string()),
            artifact: Some(report_path.display().to_string()),
            reason_codes: Vec::new(),
            message: "report records model_manifest_hash and model_file_hash".to_string(),
        }
    } else {
        ReliabilityCheck {
            name: "model identity hashes present".to_string(),
            status: ConnectorHealthStatus::Degraded,
            run_id: Some(run_id.to_string()),
            artifact: Some(report_path.display().to_string()),
            reason_codes: vec![ReliabilityReasonCode::ModelHashMissing],
            message: "report is missing model_manifest_hash or model_file_hash".to_string(),
        }
    }
}

fn check_bundle_freshness(run_dir: &Path, run_id: &str) -> ReliabilityCheck {
    let bundle = run_dir.join("evidence_bundle.json");
    match fs::symlink_metadata(&bundle) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return error_check(
                "evidence bundle freshness",
                Some(run_id),
                &bundle,
                ReliabilityReasonCode::ArtifactMissing,
                "evidence_bundle.json has not been generated for this run".to_string(),
            );
        }
        Err(error) => {
            return error_check(
                "evidence bundle freshness",
                Some(run_id),
                &bundle,
                reason_for_io_error(&error),
                format!("could not inspect evidence bundle metadata: {error}"),
            );
        }
    }
    let bundle_mtime = match confined_modified_time(run_dir, &bundle) {
        Ok(modified) => modified,
        Err(issue) => return scan_issue_check("evidence bundle freshness", run_id, issue),
    };
    let mut stale_inputs = Vec::new();
    for name in ["report.json", "recommendations.json", "hil_feedback.json"] {
        let path = run_dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => match confined_modified_time(run_dir, &path) {
                Ok(modified) if modified > bundle_mtime => stale_inputs.push(name),
                Ok(_) => {}
                Err(issue) => {
                    return scan_issue_check("evidence bundle freshness", run_id, issue);
                }
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return error_check(
                    "evidence bundle freshness",
                    Some(run_id),
                    &path,
                    reason_for_io_error(&error),
                    format!("could not inspect freshness input metadata: {error}"),
                );
            }
        }
    }
    if stale_inputs.is_empty() {
        ok_check("evidence bundle freshness", run_id, &bundle)
    } else {
        ReliabilityCheck {
            name: "evidence bundle freshness".to_string(),
            status: ConnectorHealthStatus::Degraded,
            run_id: Some(run_id.to_string()),
            artifact: Some(bundle.display().to_string()),
            reason_codes: vec![ReliabilityReasonCode::BundleStale],
            message: format!("evidence bundle predates {}", stale_inputs.join(", ")),
        }
    }
}

pub fn write_text_atomic(path: impl AsRef<Path>, body: &str) -> Result<PathBuf> {
    let path = path.as_ref();
    write_file_atomically(path, "txt", |file| {
        use std::io::Write;
        file.write_all(body.as_bytes()).with_path(path)
    })
    .map(|(path, ())| path)
}

pub fn invalid_retry_policy_check(policy: ReliabilityRetryPolicy) -> Option<ReliabilityCheck> {
    policy.validate().err().map(|message| ReliabilityCheck {
        name: "retry policy valid".to_string(),
        status: ConnectorHealthStatus::Error,
        run_id: None,
        artifact: None,
        reason_codes: vec![ReliabilityReasonCode::RetryPolicyInvalid],
        message,
    })
}

pub fn ensure_safe_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "path must be relative and confined: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
