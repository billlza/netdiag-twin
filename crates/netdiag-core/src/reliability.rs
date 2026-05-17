use crate::error::{IoContext, NetdiagError, Result};
use crate::models::ConnectorHealthStatus;
use crate::storage::{
    list_run_locations, read_json, read_report, resolve_run_location, run_artifacts,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

const RELIABILITY_SCHEMA: &str = "netdiag-reliability-report/v1";
const SECRET_PLACEHOLDER: &str = "[redacted]";

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

    pub fn retry_delays(self) -> Vec<Duration> {
        if self.validate().is_err() || self.max_attempts <= 1 {
            return Vec::new();
        }
        let mut next = self.initial_backoff_millis;
        let mut delays = Vec::new();
        for _ in 1..self.max_attempts {
            delays.push(Duration::from_millis(next));
            next = next.saturating_mul(2).min(self.max_backoff_millis);
        }
        delays
    }
}

pub fn check_reliability(options: ReliabilityCheckOptions) -> Result<ReliabilityCheckReport> {
    let artifact_root = options.artifact_root;
    let mut checks = Vec::new();
    checks.push(check_artifact_root_exists(&artifact_root));
    let locations = if let Some(run_id) = &options.run_id {
        vec![resolve_run_location(&artifact_root, run_id)?]
    } else {
        list_run_locations(&artifact_root)?
    };
    if locations.is_empty() {
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
        let run_id = location
            .run_dir
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("unknown")
            .to_string();
        checks.extend(check_run_required_files(&location.run_dir, &run_id));
        checks.extend(check_run_json_files(&location.run_dir, &run_id));
        if let Some(context_dir) = &location.lab_run_dir {
            checks.extend(check_context_json_files(context_dir, &run_id));
            checks.extend(check_context_secret_leaks(context_dir, &run_id));
        }
        checks.extend(check_run_artifact_paths(&location.artifact_root, &run_id));
        checks.push(check_model_hashes(&location.artifact_root, &run_id));
        checks.push(check_bundle_freshness(&location.run_dir, &run_id));
        checks.extend(check_secret_leaks(&location.run_dir, &run_id));
    }
    let status = aggregate_status(&checks);
    Ok(ReliabilityCheckReport {
        schema: RELIABILITY_SCHEMA.to_string(),
        generated_at: Utc::now(),
        artifact_root: artifact_root.display().to_string(),
        run_id: options.run_id,
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

pub fn redact_string(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == SECRET_PLACEHOLDER {
        return value.to_string();
    }
    if looks_like_secret_value(trimmed) {
        SECRET_PLACEHOLDER.to_string()
    } else {
        value.to_string()
    }
}

pub fn redact_json_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                if secret_key(key) {
                    if !item.is_null() {
                        *item = Value::String(SECRET_PLACEHOLDER.to_string());
                    }
                } else {
                    redact_json_value(item);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        Value::String(text) => {
            *text = redact_string(text);
        }
        _ => {}
    }
}

fn check_artifact_root_exists(artifact_root: &Path) -> ReliabilityCheck {
    if artifact_root.exists() && artifact_root.is_dir() {
        return ReliabilityCheck {
            name: "artifact root exists".to_string(),
            status: ConnectorHealthStatus::Ok,
            run_id: None,
            artifact: Some(artifact_root.display().to_string()),
            reason_codes: Vec::new(),
            message: "artifact root is present".to_string(),
        };
    }
    ReliabilityCheck {
        name: "artifact root exists".to_string(),
        status: ConnectorHealthStatus::Error,
        run_id: None,
        artifact: Some(artifact_root.display().to_string()),
        reason_codes: vec![ReliabilityReasonCode::ArtifactMissing],
        message: "artifact root does not exist or is not a directory".to_string(),
    }
}

fn check_run_required_files(run_dir: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    ["manifest.json", "report.json"]
        .into_iter()
        .map(|file_name| {
            let path = run_dir.join(file_name);
            if path.is_file() {
                ok_check("required artifact exists", run_id, &path)
            } else {
                ReliabilityCheck {
                    name: "required artifact exists".to_string(),
                    status: ConnectorHealthStatus::Error,
                    run_id: Some(run_id.to_string()),
                    artifact: Some(path.display().to_string()),
                    reason_codes: vec![ReliabilityReasonCode::ArtifactMissing],
                    message: format!("{file_name} is missing"),
                }
            }
        })
        .collect()
}

fn check_run_json_files(run_dir: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    let mut checks = Vec::new();
    for path in json_files_under(run_dir) {
        match read_json(&path) {
            Ok(_) => checks.push(ok_check("json parseable", run_id, &path)),
            Err(err) => checks.push(ReliabilityCheck {
                name: "json parseable".to_string(),
                status: ConnectorHealthStatus::Error,
                run_id: Some(run_id.to_string()),
                artifact: Some(path.display().to_string()),
                reason_codes: vec![ReliabilityReasonCode::JsonInvalid],
                message: err.to_string(),
            }),
        }
    }
    checks
}

fn check_context_json_files(context_dir: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    top_level_files_with_extensions(context_dir, &["json"])
        .into_iter()
        .map(|path| match read_json(&path) {
            Ok(_) => ok_check("context json parseable", run_id, &path),
            Err(err) => ReliabilityCheck {
                name: "context json parseable".to_string(),
                status: ConnectorHealthStatus::Error,
                run_id: Some(run_id.to_string()),
                artifact: Some(path.display().to_string()),
                reason_codes: vec![ReliabilityReasonCode::JsonInvalid],
                message: err.to_string(),
            },
        })
        .collect()
}

fn check_run_artifact_paths(artifact_root: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    let mut checks = Vec::new();
    let Ok(artifacts) = run_artifacts(artifact_root, run_id) else {
        return checks;
    };
    let Ok(location) = resolve_run_location(artifact_root, run_id) else {
        return checks;
    };
    let allowed = location
        .run_dir
        .canonicalize()
        .unwrap_or_else(|_| location.run_dir.clone());
    for artifact in artifacts {
        let path = PathBuf::from(&artifact.path);
        if !artifact.exists {
            checks.push(ReliabilityCheck {
                name: "manifest artifact exists".to_string(),
                status: ConnectorHealthStatus::Error,
                run_id: Some(run_id.to_string()),
                artifact: Some(artifact.path),
                reason_codes: vec![ReliabilityReasonCode::ArtifactMissing],
                message: format!("manifest artifact {} is missing", artifact.key),
            });
            continue;
        }
        let canonical = path.canonicalize().unwrap_or(path);
        if canonical.starts_with(&allowed) {
            checks.push(ok_check("manifest path confined", run_id, &canonical));
        } else {
            checks.push(ReliabilityCheck {
                name: "manifest path confined".to_string(),
                status: ConnectorHealthStatus::Error,
                run_id: Some(run_id.to_string()),
                artifact: Some(canonical.display().to_string()),
                reason_codes: vec![ReliabilityReasonCode::PathEscapesArtifactRoot],
                message: "manifest artifact path is outside the resolved run directory".to_string(),
            });
        }
    }
    checks
}

fn check_model_hashes(artifact_root: &Path, run_id: &str) -> ReliabilityCheck {
    match read_report(artifact_root, run_id) {
        Ok(report) if report.model_manifest_hash.is_some() && report.model_file_hash.is_some() => {
            ReliabilityCheck {
                name: "model identity hashes present".to_string(),
                status: ConnectorHealthStatus::Ok,
                run_id: Some(run_id.to_string()),
                artifact: None,
                reason_codes: Vec::new(),
                message: "report records model_manifest_hash and model_file_hash".to_string(),
            }
        }
        Ok(_) => ReliabilityCheck {
            name: "model identity hashes present".to_string(),
            status: ConnectorHealthStatus::Degraded,
            run_id: Some(run_id.to_string()),
            artifact: None,
            reason_codes: vec![ReliabilityReasonCode::ModelHashMissing],
            message: "report is missing model_manifest_hash or model_file_hash".to_string(),
        },
        Err(err) => ReliabilityCheck {
            name: "model identity hashes present".to_string(),
            status: ConnectorHealthStatus::Error,
            run_id: Some(run_id.to_string()),
            artifact: None,
            reason_codes: vec![ReliabilityReasonCode::JsonInvalid],
            message: err.to_string(),
        },
    }
}

fn check_bundle_freshness(run_dir: &Path, run_id: &str) -> ReliabilityCheck {
    let bundle = run_dir.join("evidence_bundle.json");
    if !bundle.exists() {
        return ReliabilityCheck {
            name: "evidence bundle freshness".to_string(),
            status: ConnectorHealthStatus::Error,
            run_id: Some(run_id.to_string()),
            artifact: Some(bundle.display().to_string()),
            reason_codes: vec![ReliabilityReasonCode::ArtifactMissing],
            message: "evidence_bundle.json has not been generated for this run".to_string(),
        };
    }
    let bundle_mtime = modified_at(&bundle);
    let stale_inputs = ["report.json", "recommendations.json", "hil_feedback.json"]
        .into_iter()
        .filter_map(|name| {
            let path = run_dir.join(name);
            let input_mtime = modified_at(&path)?;
            (input_mtime > bundle_mtime?).then_some(name)
        })
        .collect::<Vec<_>>();
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

fn check_secret_leaks(run_dir: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    json_files_under(run_dir)
        .into_iter()
        .filter_map(|path| {
            let body = fs::read_to_string(&path).ok()?;
            contains_secret_like_document(&path, &body).then(|| ReliabilityCheck {
                name: "secret redaction".to_string(),
                status: ConnectorHealthStatus::Error,
                run_id: Some(run_id.to_string()),
                artifact: Some(path.display().to_string()),
                reason_codes: vec![ReliabilityReasonCode::SecretLeak],
                message: "artifact appears to contain an unredacted credential value".to_string(),
            })
        })
        .collect()
}

fn check_context_secret_leaks(context_dir: &Path, run_id: &str) -> Vec<ReliabilityCheck> {
    top_level_files_with_extensions(context_dir, &["json", "yaml", "yml", "md"])
        .into_iter()
        .filter_map(|path| {
            let body = fs::read_to_string(&path).ok()?;
            contains_secret_like_document(&path, &body).then(|| ReliabilityCheck {
                name: "context secret redaction".to_string(),
                status: ConnectorHealthStatus::Error,
                run_id: Some(run_id.to_string()),
                artifact: Some(path.display().to_string()),
                reason_codes: vec![ReliabilityReasonCode::SecretLeak],
                message: "context artifact appears to contain an unredacted credential value"
                    .to_string(),
            })
        })
        .collect()
}

fn ok_check(name: &str, run_id: &str, path: &Path) -> ReliabilityCheck {
    ReliabilityCheck {
        name: name.to_string(),
        status: ConnectorHealthStatus::Ok,
        run_id: Some(run_id.to_string()),
        artifact: Some(path.display().to_string()),
        reason_codes: Vec::new(),
        message: "ok".to_string(),
    }
}

fn aggregate_status(checks: &[ReliabilityCheck]) -> ConnectorHealthStatus {
    checks
        .iter()
        .map(|check| check.status)
        .max()
        .unwrap_or(ConnectorHealthStatus::Ok)
}

fn json_files_under(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_json_files(root, &mut paths);
    paths.sort();
    paths
}

fn top_level_files_with_extensions(root: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut paths = fs::read_dir(root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|value| value.to_str())
                    .is_some_and(|ext| extensions.contains(&ext))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

fn collect_json_files(root: &Path, paths: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_json_files(&path, paths);
        } else if path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path);
        }
    }
}

fn modified_at(path: &Path) -> Option<std::time::SystemTime> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
}

fn contains_secret_like_json(body: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    let mut leaks = BTreeSet::new();
    collect_secret_leaks(&value, None, &mut leaks);
    !leaks.is_empty()
}

fn contains_secret_like_document(path: &Path, body: &str) -> bool {
    match path.extension().and_then(|value| value.to_str()) {
        Some("json") => contains_secret_like_json(body),
        Some("yaml" | "yml") => serde_yaml::from_str::<serde_yaml::Value>(body)
            .ok()
            .and_then(|value| serde_json::to_value(value).ok())
            .is_some_and(|value| {
                let mut leaks = BTreeSet::new();
                collect_secret_leaks(&value, None, &mut leaks);
                !leaks.is_empty()
            }),
        _ => contains_secret_like_text(body),
    }
}

fn contains_secret_like_text(body: &str) -> bool {
    body.lines().any(|line| {
        let Some((key, value)) = line.split_once(':') else {
            return looks_like_secret_value(line.trim());
        };
        secret_key(key) && !value.trim().is_empty() && !value.contains(SECRET_PLACEHOLDER)
    })
}

fn collect_secret_leaks(value: &Value, key: Option<&str>, leaks: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (child_key, child) in map {
                collect_secret_leaks(child, Some(child_key), leaks);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_secret_leaks(item, key, leaks);
            }
        }
        Value::String(text)
            if key.is_some_and(secret_key) && text != SECRET_PLACEHOLDER && !text.is_empty() =>
        {
            leaks.insert(text.clone());
        }
        Value::String(_) => {}
        _ => {}
    }
}

fn secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("token")
        || key.contains("secret")
        || key.contains("password")
        || key.contains("credential")
        || key.contains("authorization")
        || key.contains("bearer")
        || key.contains("api_key")
}

fn looks_like_secret_value(value: &str) -> bool {
    value.starts_with("Bearer ")
        || value.starts_with("Token ")
        || value.starts_with("Basic ")
        || value.contains("://")
            && (value.contains("@") || value.to_ascii_lowercase().contains("token="))
}

pub fn write_text_atomic(path: impl AsRef<Path>, body: &str) -> Result<PathBuf> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_path(parent)?;
    }
    let tmp_path = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("txt")
    ));
    fs::write(&tmp_path, body).with_path(&tmp_path)?;
    fs::rename(&tmp_path, path).with_path(path)?;
    Ok(path.to_path_buf())
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
mod tests {
    use super::*;
    use crate::storage::save_json_atomic;
    use chrono::Utc;
    use serde_json::json;
    use tempfile::tempdir;

    #[test]
    fn retry_policy_has_bounded_exponential_delays() {
        let policy = ReliabilityRetryPolicy {
            max_attempts: 4,
            initial_backoff_millis: 50,
            max_backoff_millis: 120,
        };
        assert_eq!(
            policy.retry_delays(),
            vec![
                Duration::from_millis(50),
                Duration::from_millis(100),
                Duration::from_millis(120)
            ]
        );
    }

    #[test]
    fn redacts_secret_json_values() {
        let mut value = json!({
            "endpoint": "https://lab.example",
            "bearer_token": "secret-token",
            "nested": {"password": "letmein"}
        });
        redact_json_value(&mut value);
        assert_eq!(value["endpoint"], "https://lab.example");
        assert_eq!(value["bearer_token"], SECRET_PLACEHOLDER);
        assert_eq!(value["nested"]["password"], SECRET_PLACEHOLDER);
    }

    #[test]
    fn reliability_reports_path_escape() {
        let temp = tempdir().expect("tempdir");
        let root = temp.path();
        let run_id = "run-1";
        let run_dir = root.join("runs").join(run_id);
        fs::create_dir_all(&run_dir).expect("run dir");
        save_json_atomic(
            run_dir.join("manifest.json"),
            &json!({
                "run_id": run_id,
                "sample": "sample",
                "created_at": Utc::now(),
                "trace_rows": 1,
                "artifact_paths": {"escaped": "../outside.json"}
            }),
        )
        .expect("manifest");
        save_json_atomic(
            run_dir.join("report.json"),
            &json!({
                "run_id": run_id,
                "generated_at": Utc::now(),
                "trace_summary": {"overall": {}, "windows": []},
                "root_causes": [],
                "rule_vs_ml": {
                    "rule_labels": [],
                    "ml_top": "normal",
                    "ml_top_prob": 1.0,
                    "agreement": true,
                    "agreement_text": "ok",
                    "rule_missing": [],
                    "rule_only": []
                },
                "recommendations": []
            }),
        )
        .expect("report");
        save_json_atomic(root.join("runs").join("outside.json"), &json!({"x": true}))
            .expect("outside");

        let report = check_reliability(ReliabilityCheckOptions {
            artifact_root: root.to_path_buf(),
            run_id: Some(run_id.to_string()),
        })
        .expect("reliability");
        assert!(report.checks.iter().any(|check| {
            check
                .reason_codes
                .contains(&ReliabilityReasonCode::PathEscapesArtifactRoot)
        }));
    }
}
