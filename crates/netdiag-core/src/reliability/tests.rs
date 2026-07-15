use super::*;
use crate::storage::save_json_atomic;
use chrono::Utc;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn write_minimal_run(root: &Path, run_id: &str) -> PathBuf {
    let run_dir = root.join("runs").join(run_id);
    fs::create_dir_all(&run_dir).expect("run dir");
    save_json_atomic(
        run_dir.join("manifest.json"),
        &json!({
            "run_id": run_id,
            "sample": "sample",
            "created_at": Utc::now(),
            "trace_rows": 1,
            "artifact_paths": {}
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
    save_json_atomic(run_dir.join("evidence_bundle.json"), &json!({"files": []}))
        .expect("bundle manifest");
    run_dir
}

fn reliability_report(root: &Path, run_id: &str) -> ReliabilityCheckReport {
    check_reliability(ReliabilityCheckOptions {
        artifact_root: root.to_path_buf(),
        run_id: Some(run_id.to_string()),
    })
    .expect("reliability report")
}

#[test]
fn retry_policy_has_bounded_exponential_delays() {
    let policy = ReliabilityRetryPolicy {
        max_attempts: 4,
        initial_backoff_millis: 50,
        max_backoff_millis: 120,
    };
    assert_eq!(
        policy.retry_delays().expect("valid retry policy"),
        vec![
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(120)
        ]
    );
}

#[test]
fn retry_policy_rejects_invalid_configuration_before_building_delays() {
    let error = ReliabilityRetryPolicy {
        max_attempts: 3,
        initial_backoff_millis: 0,
        max_backoff_millis: 120,
    }
    .retry_delays()
    .expect_err("invalid retry policy must not masquerade as no retries");

    assert_eq!(error, "initial_backoff_millis must be at least 1");
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
    assert_eq!(value["bearer_token"], secrets::SECRET_PLACEHOLDER);
    assert_eq!(value["nested"]["password"], secrets::SECRET_PLACEHOLDER);
}

#[test]
fn redacts_structured_url_credentials_and_sensitive_query_variants() {
    let secret = "opaque-url-secret";
    for key in [
        "token",
        "ACCESS_TOKEN",
        "api-key",
        "ApiKey",
        "password",
        "passwd",
        "secret",
        "signature",
        "sig",
        "key",
        "credential",
        "auth",
        "%74oken",
        "%2574oken",
    ] {
        let redacted = redact_url(&format!(
            "https://operator:{secret}@example.test/metrics?region=lab&{key}={secret}#fragment-secret"
        ));
        let url = reqwest::Url::parse(&redacted).expect("redacted URL");
        assert!(url.username().is_empty(), "{key}: {redacted}");
        assert!(url.password().is_none(), "{key}: {redacted}");
        assert!(url.fragment().is_none(), "{key}: {redacted}");
        assert!(!redacted.contains(secret), "{key}: {redacted}");
        assert!(url.query_pairs().any(|(_, value)| value == "[redacted]"));
        assert!(
            url.query_pairs()
                .any(|(query_key, value)| query_key == "region" && value == "lab")
        );
    }
}

#[test]
fn url_redaction_is_fail_closed_and_does_not_rewrite_safe_urls() {
    let safe = "https://example.test/metrics?region=lab";
    assert_eq!(redact_url(safe), safe);
    let already_redacted = "https://example.test/metrics?auth=%5Bredacted-env%5D";
    assert_eq!(redact_url(already_redacted), already_redacted);
    assert_eq!(redact_url("not a URL?token=opaque"), "[redacted]");
    assert_eq!(
        redact_string("https://invalid host?access_token=opaque"),
        "[redacted]"
    );
    assert_eq!(
        redact_string("request failed for https://example.test/data?API-KEY=opaque"),
        "[redacted]"
    );
    assert_eq!(redact_string("bEaReR opaque"), "[redacted]");
}

#[test]
fn secret_inspection_detects_credentials_inside_endpoint_values() {
    let body = r#"{"endpoint":"https://example.test/data?access_token=opaque"}"#;
    assert!(
        secrets::inspect_document(Path::new("context.json"), body)
            .expect("valid secret-bearing document")
    );
}

#[test]
fn secret_inspection_rejects_ambiguous_duplicate_json_keys_without_echoing_them() {
    let body = r#"{"private-token":"first","private-token":"second"}"#;

    let error = secrets::inspect_document(Path::new("context.json"), body)
        .expect_err("duplicate keys can hide the first secret value");

    assert!(error.contains("duplicate key"), "{error}");
    assert!(!error.contains("private-token"), "{error}");
    assert!(!error.contains("first"), "{error}");
    assert!(!error.contains("second"), "{error}");
}

#[test]
fn secret_inspection_allows_evidence_integrity_metadata_and_logical_keys() {
    let body = r#"{
        "schema": "netdiag-evidence-bundle/v1",
        "files": [{
            "key": "connector_health",
            "artifact_key": "topology_snapshot",
            "topology_key": "mesh",
            "public_key": "published-verification-material",
            "sha256": "68a291b7b555d8a7592204feef854918498d6c0a7a7a14f26ec785a8d814f81b"
        }]
    }"#;

    assert!(
        !secrets::inspect_document(Path::new("evidence_bundle.json"), body)
            .expect("valid evidence bundle manifest")
    );
}

#[test]
fn secret_inspection_keeps_document_credential_keys_fail_closed() {
    let digest_shaped_secret = "68a291b7b555d8a7592204feef854918498d6c0a7a7a14f26ec785a8d814f81b";
    for key in [
        "api_key",
        "%61pi-key",
        "access-key-id",
        "auth_key",
        "privateKey",
        "signing_key",
        "bearer_token",
        "password",
        "authorization",
        "signature",
    ] {
        let body =
            serde_json::to_string(&json!({key: digest_shaped_secret})).expect("credential fixture");
        assert!(
            secrets::inspect_document(Path::new("context.json"), &body)
                .expect("valid credential-bearing document"),
            "credential key was not detected: {key}"
        );
    }
}

#[test]
fn secret_inspection_keeps_unstructured_key_value_text_fail_closed() {
    assert!(
        secrets::inspect_document(Path::new("adapter.log"), "key: opaque-credential")
            .expect("valid plain-text credential fixture")
    );
}

#[test]
fn reliability_reports_path_escape_from_manifest_resolution() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path();
    let run_id = "run-1";
    let run_dir = write_minimal_run(root, run_id);
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
    save_json_atomic(root.join("runs").join("outside.json"), &json!({"x": true})).expect("outside");

    let report = reliability_report(root, run_id);

    assert!(report.checks.iter().any(|check| {
        check.status == ConnectorHealthStatus::Error
            && check
                .reason_codes
                .contains(&ReliabilityReasonCode::PathEscapesArtifactRoot)
    }));
}

#[test]
fn reliability_reports_malformed_context_json_and_yaml() {
    let temp = tempdir().expect("tempdir");
    let root = temp.path();
    let run_id = "run-1";
    write_minimal_run(root, run_id);
    fs::write(root.join("scenario.yaml"), "id: scenario-1\n").expect("scenario");
    fs::write(root.join("broken.json"), "{").expect("broken json");
    fs::write(root.join("broken.yaml"), "token: [unterminated").expect("broken yaml");

    let report = reliability_report(root, run_id);

    assert!(report.checks.iter().any(|check| {
        check.name == "context json parseable"
            && check.status == ConnectorHealthStatus::Error
            && check
                .reason_codes
                .contains(&ReliabilityReasonCode::JsonInvalid)
    }));
    assert!(report.checks.iter().any(|check| {
        check.name == "context secret redaction"
            && check.status == ConnectorHealthStatus::Error
            && check
                .reason_codes
                .contains(&ReliabilityReasonCode::MalformedPayload)
            && check.message.contains("invalid YAML")
    }));
}

#[cfg(unix)]
#[test]
fn reliability_reports_recursive_symlink_escape() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().expect("tempdir");
    let root = temp.path();
    let run_id = "run-1";
    let run_dir = write_minimal_run(root, run_id);
    let outside = root.join("outside.json");
    fs::write(&outside, "{}").expect("outside");
    symlink(&outside, run_dir.join("linked.json")).expect("symlink");

    let report = reliability_report(root, run_id);

    assert!(report.checks.iter().any(|check| {
        check.status == ConnectorHealthStatus::Error
            && check
                .reason_codes
                .contains(&ReliabilityReasonCode::PathEscapesArtifactRoot)
            && check
                .artifact
                .as_deref()
                .is_some_and(|path| path.ends_with("linked.json"))
    }));
}

#[cfg(unix)]
#[test]
fn reliability_reports_unreadable_json() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempdir().expect("tempdir");
    let root = temp.path();
    let run_id = "run-1";
    let run_dir = write_minimal_run(root, run_id);
    let unreadable = run_dir.join("unreadable.json");
    fs::write(&unreadable, "{}").expect("unreadable fixture");
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000))
        .expect("remove permissions");

    let report = reliability_report(root, run_id);
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o600))
        .expect("restore permissions");

    assert!(report.checks.iter().any(|check| {
        check.status == ConnectorHealthStatus::Error
            && check
                .reason_codes
                .contains(&ReliabilityReasonCode::PermissionDenied)
            && check
                .artifact
                .as_deref()
                .is_some_and(|path| path.ends_with("unreadable.json"))
    }));
}

#[test]
fn empty_check_aggregation_is_error() {
    assert_eq!(aggregate_status(&[]), ConnectorHealthStatus::Error);
}
