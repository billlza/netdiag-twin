use super::super::{PilotCollection, PilotSourceKind, PilotSourceRole};
use super::*;
use std::collections::BTreeMap;
use std::fs;
use std::time::Duration;

fn source_with_metadata(metadata: BTreeMap<String, String>) -> PilotSource {
    PilotSource {
        name: "adapter".to_string(),
        kind: PilotSourceKind::AdapterSample,
        endpoint: "adapter.py".to_string(),
        role: PilotSourceRole::Primary,
        active: false,
        bearer_token_env: None,
        mapping: None,
        collection: PilotCollection::default(),
        metadata,
    }
}

#[test]
fn adapter_contract_accepts_supported_aliases() {
    for value in [
        "v1",
        "adapter-v1",
        "netdiag-adapter/v1",
        "netdiag-adapter-preflight/v1",
    ] {
        let source = source_with_metadata(BTreeMap::from([(
            "adapter_contract".to_string(),
            value.to_string(),
        )]));
        assert!(adapter_contract_enabled(&source), "{value}");
    }

    let source = source_with_metadata(BTreeMap::from([(
        "contract".to_string(),
        "netdiag-adapter/v1".to_string(),
    )]));
    assert!(adapter_contract_enabled(&source));
}

#[test]
fn adapter_contract_rejects_missing_or_unknown_metadata() {
    assert!(!adapter_contract_enabled(&source_with_metadata(
        BTreeMap::new()
    )));
    let source = source_with_metadata(BTreeMap::from([(
        "adapter_contract".to_string(),
        "legacy".to_string(),
    )]));
    assert!(!adapter_contract_enabled(&source));
}

#[test]
fn adapter_preflight_validation_requires_schema_health_and_redaction() {
    let valid = serde_json::json!({
        "schema": "netdiag-adapter-preflight/v1",
        "passed": true,
        "checks": [{"name": "adapter", "status": "ok"}],
        "health": {"status": "ok"},
        "redaction": {"fields": []}
    });
    validate_adapter_preflight(&valid).expect("valid preflight");

    for invalid in [
        serde_json::json!({"schema": "wrong", "passed": true, "checks": [1], "health": {}, "redaction": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "passed": false, "checks": [1], "health": {}, "redaction": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "passed": true, "checks": [], "health": {}, "redaction": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "passed": true, "checks": [1], "redaction": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "passed": true, "checks": [1], "health": {}}),
    ] {
        assert!(validate_adapter_preflight(&invalid).is_err());
    }
}

#[test]
fn python_adapter_runner_reports_spawn_failures() {
    let temp = tempfile::tempdir().expect("tempdir");
    let adapter = temp.path().join("adapter.py");
    fs::write(&adapter, "print('ok')\n").expect("adapter script");
    let missing_cwd = temp.path().join("missing-cwd");
    let error = run_python_adapter(&adapter, &missing_cwd, &[], Duration::from_millis(50))
        .expect_err("invalid cwd should fail to spawn");

    assert!(error.to_string().contains("failed to run adapter sample"));
}

#[test]
fn python_adapter_runner_kills_timed_out_adapter_and_keeps_stderr() {
    let temp = tempfile::tempdir().expect("tempdir");
    let adapter = temp.path().join("slow.py");
    fs::write(
        &adapter,
        r#"
import sys
import time

sys.stderr.write("adapter still running")
sys.stderr.flush()
time.sleep(5)
"#,
    )
    .expect("adapter script");

    let error = run_python_adapter(&adapter, temp.path(), &[], Duration::from_millis(200))
        .expect_err("slow adapter should time out");

    let message = error.to_string();
    assert!(message.contains("timed out"));
    assert!(message.contains("adapter still running"));
}
