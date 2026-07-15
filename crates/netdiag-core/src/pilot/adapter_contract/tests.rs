use super::super::{
    PilotAdapterMode, PilotAdapterOptions, PilotCollection, PilotSource, PilotSourceKind,
    PilotSourceRole,
};
use super::declaration::{AdapterContractDeclaration, adapter_contract_declaration};
#[cfg(unix)]
use super::process::{ADAPTER_STDERR_LIMIT_BYTES, ADAPTER_STDOUT_LIMIT_BYTES};
use super::*;
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
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
        adapter: PilotAdapterOptions {
            mode: Some(PilotAdapterMode::Live),
            args: Vec::new(),
            env_allowlist: Vec::new(),
        },
        metadata,
    }
}

#[cfg(unix)]
fn python_interpreter() -> std::path::PathBuf {
    resolve_python_interpreter(None)
        .expect("absolute Python interpreter")
        .path()
        .to_path_buf()
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
        assert_eq!(
            adapter_contract_declaration(&source).expect("supported contract"),
            AdapterContractDeclaration::Supported,
            "{value}"
        );
    }

    let source = source_with_metadata(BTreeMap::from([(
        "contract".to_string(),
        "netdiag-adapter/v1".to_string(),
    )]));
    assert_eq!(
        adapter_contract_declaration(&source).expect("supported alias"),
        AdapterContractDeclaration::Supported
    );
}

#[test]
fn adapter_contract_distinguishes_absent_unknown_and_conflicting_metadata() {
    assert_eq!(
        adapter_contract_declaration(&source_with_metadata(BTreeMap::new()))
            .expect("absent contract"),
        AdapterContractDeclaration::Absent
    );
    let absent = validated_adapter_contract(&source_with_metadata(BTreeMap::new()))
        .expect_err("absent contract must fail closed");
    assert!(absent.to_string().contains("must declare"));
    let source = source_with_metadata(BTreeMap::from([(
        "adapter_contract".to_string(),
        "legacy".to_string(),
    )]));
    assert_eq!(
        adapter_contract_declaration(&source).expect("unknown declaration remains explicit"),
        AdapterContractDeclaration::Unknown("legacy".to_string())
    );
    let unknown = validated_adapter_contract(&source).expect_err("unknown contract must fail");
    assert!(unknown.to_string().contains("unsupported adapter contract"));

    let conflicting = source_with_metadata(BTreeMap::from([
        ("adapter_contract".to_string(), "v1".to_string()),
        ("contract".to_string(), "netdiag-adapter/v1".to_string()),
    ]));
    let conflict =
        adapter_contract_declaration(&conflicting).expect_err("conflicting aliases must fail");
    assert!(conflict.to_string().contains("conflicting"));
}

#[test]
fn adapter_passthrough_args_reject_control_and_secret_flags() {
    for argument in [
        "--preflight",
        "--collect",
        "--emit-sample",
        "--api-token=secret",
        "--password",
        "--client-secret",
    ] {
        let mut source = source_with_metadata(BTreeMap::new());
        source.adapter.args = vec![argument.to_string()];
        let error =
            validate_adapter_options(&source).expect_err("reserved or secret flags must fail");
        assert!(
            error.to_string().contains("adapter source"),
            "{argument}: {error}"
        );
    }

    let mut source = source_with_metadata(BTreeMap::new());
    source.adapter.args = vec![
        "--input-json".to_string(),
        "fixture.json".to_string(),
        "--scenario-id=lab-a".to_string(),
    ];
    validate_adapter_options(&source).expect("non-secret adapter args");

    source.adapter.args = vec!["--apply".to_string()];
    let inactive = validate_adapter_options(&source)
        .expect_err("inactive adapters must not request active changes");
    assert!(inactive.to_string().contains("active=true"));
    source.active = true;
    validate_adapter_options(&source).expect("active adapter may request --apply");

    source.adapter.args.clear();
    for protected_name in ["path", "PythonPath", "ld_preload", "DyLd_Insert_Libraries"] {
        source.adapter.env_allowlist = vec![protected_name.to_string()];
        let protected = validate_adapter_options(&source)
            .expect_err("controlled environment names must be case-insensitive");
        assert!(
            protected
                .to_string()
                .contains("controlled runtime environment")
        );
    }
    source.adapter.env_allowlist = vec!["LAB_ENDPOINT".to_string(), "lab_endpoint".to_string()];
    let duplicate =
        validate_adapter_options(&source).expect_err("duplicate environment names must fail");
    assert!(
        duplicate
            .to_string()
            .contains("repeats environment variable")
    );
    source.adapter.env_allowlist = vec!["LAB_ENDPOINT".to_string()];
    validate_adapter_options(&source).expect("explicit bounded environment name");

    source
        .metadata
        .insert("sample_mode".to_string(), "true".to_string());
    let legacy = validate_adapter_options(&source).expect_err("legacy mode metadata must fail");
    assert!(legacy.to_string().contains("adapter.mode"));
}

#[test]
fn adapter_passthrough_args_reject_empty_long_option_names_without_echoing_values() {
    let secret = "opaque-malformed-value";
    let mut source = source_with_metadata(BTreeMap::new());
    source.adapter.args = vec![format!("--={secret}")];

    let error = validate_adapter_options(&source)
        .expect_err("empty long option names must fail declaration validation");
    let message = error.to_string();
    assert!(message.contains("empty long option name"), "{message}");
    assert!(
        !message.contains(secret),
        "validation error leaked {secret}"
    );
}

#[test]
fn adapter_option_limits_and_environment_names_fail_closed() {
    let mut source = source_with_metadata(BTreeMap::new());
    source.adapter.mode = None;
    let missing_mode = validate_adapter_options(&source).expect_err("mode is required");
    assert!(
        missing_mode
            .to_string()
            .contains("must declare adapter.mode")
    );

    source.adapter.mode = Some(PilotAdapterMode::Live);
    source.adapter.args = vec!["value".to_string(); 65];
    let too_many = validate_adapter_options(&source).expect_err("argument count is bounded");
    assert!(too_many.to_string().contains("more than 64"));

    source.adapter.args = vec!["x".repeat(4 * 1024); 17];
    let excessive_total =
        validate_adapter_options(&source).expect_err("total argument bytes are bounded");
    assert!(excessive_total.to_string().contains("arguments exceed"));

    for (argument, expected) in [
        ("   ".to_string(), "empty passthrough argument"),
        ("x".repeat(4 * 1024 + 1), "argument exceeds"),
        ("--session-token=value".to_string(), "secret flag"),
    ] {
        source.adapter.args = vec![argument];
        let error = validate_adapter_options(&source).expect_err("invalid argument must fail");
        assert!(error.to_string().contains(expected), "{error}");
    }

    source.adapter.args.clear();
    source.adapter.env_allowlist = (0..17).map(|index| format!("SAFE_{index}")).collect();
    let too_many_environment =
        validate_adapter_options(&source).expect_err("environment count is bounded");
    assert!(too_many_environment.to_string().contains("more than 16"));

    for name in ["9INVALID", "BAD-NAME", &"A".repeat(129), "PYTHONWARNINGS"] {
        source.adapter.env_allowlist = vec![name.to_string()];
        let error =
            validate_adapter_options(&source).expect_err("unsafe environment name must fail");
        assert!(
            error.to_string().contains("environment variable"),
            "{error}"
        );
    }
}

#[test]
fn adapter_preflight_validation_requires_schema_health_and_redaction() {
    let valid = serde_json::json!({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "test-adapter",
        "collection_mode": "sample",
        "passed": true,
        "checks": [{"name": "adapter", "status": "ok"}],
        "health": {"status": "ok"},
        "redaction": {"fields": []}
    });
    validate_adapter_preflight(&valid, PilotAdapterMode::Sample, "test-adapter")
        .expect("valid preflight");

    let mut wrong_identity = valid.clone();
    wrong_identity["adapter"] = serde_json::json!("different-adapter");
    let mut unstructured_check = valid.clone();
    unstructured_check["checks"] = serde_json::json!(["ok"]);
    let mut inconsistent_check = valid.clone();
    inconsistent_check["checks"][0]["status"] = serde_json::json!("error");
    let mut inconsistent_health = valid.clone();
    inconsistent_health["health"]["status"] = serde_json::json!("error");
    let mut invalid_redaction = valid.clone();
    invalid_redaction["redaction"] = serde_json::json!([]);

    for invalid in [
        serde_json::json!({"schema": "wrong", "collection_mode": "sample", "passed": true, "checks": [1], "health": {}, "redaction": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "collection_mode": "sample", "passed": false, "checks": [1], "health": {}, "redaction": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "collection_mode": "sample", "passed": true, "checks": [], "health": {}, "redaction": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "collection_mode": "sample", "passed": true, "checks": [1], "redaction": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "collection_mode": "sample", "passed": true, "checks": [1], "health": {}}),
        serde_json::json!({"schema": "netdiag-adapter-preflight/v1", "collection_mode": "live", "passed": true, "checks": [1], "health": {}, "redaction": {}}),
        wrong_identity,
        unstructured_check,
        inconsistent_check,
        inconsistent_health,
        invalid_redaction,
    ] {
        assert!(
            validate_adapter_preflight(&invalid, PilotAdapterMode::Sample, "test-adapter").is_err()
        );
    }
}

#[test]
fn adapter_preflight_rejects_each_malformed_structured_field() {
    let valid = serde_json::json!({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "test-adapter",
        "collection_mode": "sample",
        "passed": true,
        "checks": [{"name": "adapter", "status": "degraded"}],
        "health": {"status": "degraded"},
        "redaction": {"fields": ["token", "password"]}
    });
    validate_adapter_preflight(&valid, PilotAdapterMode::Sample, "test-adapter")
        .expect("degraded structured fields remain a passing preflight");

    let non_object = validate_adapter_preflight(
        &serde_json::json!(["not-an-object"]),
        PilotAdapterMode::Sample,
        "test-adapter",
    )
    .expect_err("preflight must be an object");
    assert!(non_object.to_string().contains("JSON object"));

    let mut missing_passed = valid.clone();
    missing_passed
        .as_object_mut()
        .expect("object")
        .remove("passed");
    let error =
        validate_adapter_preflight(&missing_passed, PilotAdapterMode::Sample, "test-adapter")
            .expect_err("passed must be explicit");
    assert!(error.to_string().contains("passed must be a boolean"));

    let explicitly_failed = serde_json::json!({
        "schema": "netdiag-adapter-preflight/v1",
        "adapter": "test-adapter",
        "collection_mode": "sample",
        "passed": false,
        "checks": [{"name": "adapter", "status": "error"}],
        "health": {"status": "error"},
        "redaction": {"fields": []}
    });
    let error =
        validate_adapter_preflight(&explicitly_failed, PilotAdapterMode::Sample, "test-adapter")
            .expect_err("an internally consistent failed report must still fail");
    assert!(error.to_string().contains("did not pass"));

    let oversized_checks = (0..65)
        .map(|index| serde_json::json!({"name": format!("check-{index}"), "status": "ok"}))
        .collect::<Vec<_>>();
    let mut invalid_reports = Vec::new();
    let mut oversized = valid.clone();
    oversized["checks"] = serde_json::Value::Array(oversized_checks);
    invalid_reports.push(oversized);
    for name in ["".to_string(), "x".repeat(129)] {
        let mut report = valid.clone();
        report["checks"][0]["name"] = serde_json::Value::String(name);
        invalid_reports.push(report);
    }
    let mut missing_name = valid.clone();
    missing_name["checks"][0]
        .as_object_mut()
        .expect("check object")
        .remove("name");
    invalid_reports.push(missing_name);
    let mut unknown_check_status = valid.clone();
    unknown_check_status["checks"][0]["status"] = serde_json::json!("unknown");
    invalid_reports.push(unknown_check_status);
    let mut unknown_health_status = valid.clone();
    unknown_health_status["health"]["status"] = serde_json::json!("unknown");
    invalid_reports.push(unknown_health_status);
    let mut missing_fields = valid.clone();
    missing_fields["redaction"] = serde_json::json!({});
    invalid_reports.push(missing_fields);
    let mut mixed_fields = valid.clone();
    mixed_fields["redaction"]["fields"] = serde_json::json!(["token", 7]);
    invalid_reports.push(mixed_fields);

    for report in invalid_reports {
        validate_adapter_preflight(&report, PilotAdapterMode::Sample, "test-adapter")
            .expect_err("malformed structured field must fail");
    }
}

#[cfg(unix)]
#[test]
fn python_adapter_runner_drains_outputs_larger_than_pipe_capacity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let adapter = temp.path().join("large-output.py");
    let stdout_len = 512 * 1024;
    let stderr_len = 128 * 1024;
    fs::write(
        &adapter,
        format!(
            "import sys\nsys.stdout.write('o' * {stdout_len})\nsys.stderr.write('e' * {stderr_len})\n"
        ),
    )
    .expect("adapter script");

    let output = run_python_adapter(
        &python_interpreter(),
        &adapter,
        temp.path(),
        &[],
        Duration::from_secs(5),
        &[],
        &[],
    )
    .expect("large output below limits should complete");

    assert!(output.status.success());
    assert_eq!(output.stdout.len(), stdout_len);
    assert_eq!(output.stderr.len(), stderr_len);
}

#[cfg(unix)]
#[test]
fn python_adapter_runner_rejects_stdout_and_stderr_over_limits() {
    let temp = tempfile::tempdir().expect("tempdir");
    for (stream, limit) in [
        ("stdout", ADAPTER_STDOUT_LIMIT_BYTES),
        ("stderr", ADAPTER_STDERR_LIMIT_BYTES),
    ] {
        let adapter = temp.path().join(format!("large-{stream}.py"));
        fs::write(
            &adapter,
            format!("import sys\nsys.{stream}.write('x' * {})\n", limit + 1),
        )
        .expect("adapter script");

        let error = run_python_adapter(
            &python_interpreter(),
            &adapter,
            temp.path(),
            &[],
            Duration::from_secs(5),
            &[],
            &[],
        )
        .expect_err("output beyond the configured limit must fail");

        assert!(error.to_string().contains(stream), "{error}");
        assert!(error.to_string().contains("exceeded"), "{error}");
    }
}

#[cfg(unix)]
#[test]
fn python_adapter_runner_reports_spawn_failures() {
    let temp = tempfile::tempdir().expect("tempdir");
    let adapter = temp.path().join("adapter.py");
    fs::write(&adapter, "print('ok')\n").expect("adapter script");
    let missing_cwd = temp.path().join("missing-cwd");
    let error = run_python_adapter(
        &python_interpreter(),
        &adapter,
        &missing_cwd,
        &[],
        Duration::from_millis(50),
        &[],
        &[],
    )
    .expect_err("invalid cwd should fail to spawn");

    assert!(error.to_string().contains("phase=spawn"));

    let relative = run_python_adapter(
        std::path::Path::new("python3"),
        &adapter,
        temp.path(),
        &[],
        Duration::from_secs(1),
        &[],
        &[],
    )
    .expect_err("relative interpreter paths must fail before spawn");
    assert!(relative.to_string().contains("must be absolute"));
}

#[cfg(unix)]
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

    let error = run_python_adapter(
        &python_interpreter(),
        &adapter,
        temp.path(),
        &[],
        Duration::from_secs(2),
        &[],
        &[],
    )
    .expect_err("slow adapter should time out");

    let message = error.to_string();
    assert!(message.contains("reason=timeout"));
    assert!(message.contains("adapter still running"));
}

#[cfg(unix)]
#[test]
fn python_adapter_runner_clears_parent_environment_and_redacts_allowed_values() {
    let temp = tempfile::tempdir().expect("tempdir");
    let adapter = temp.path().join("environment.py");
    fs::write(
        &adapter,
        r#"import os
import sys
print("home=" + str(os.environ.get("HOME")))
print("token=" + os.environ["EXPLICIT_TOKEN"], file=sys.stderr)
"#,
    )
    .expect("adapter script");
    let secret = "adapter-secret-sentinel".to_string();
    let environment = vec![("EXPLICIT_TOKEN".to_string(), secret.clone())];
    let output = run_python_adapter(
        &python_interpreter(),
        &adapter,
        temp.path(),
        &[],
        Duration::from_secs(2),
        &environment,
        std::slice::from_ref(&secret),
    )
    .expect("adapter process");

    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "home=None");
    let excerpt = adapter_stderr_excerpt(&output.stderr, std::slice::from_ref(&secret));
    assert!(excerpt.contains("[redacted]"));
    assert!(!excerpt.contains(&secret));
}

#[cfg(unix)]
#[test]
fn python_adapter_runner_enforces_isolated_no_bytecode_mode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let adapter = temp.path().join("runtime-flags.py");
    fs::write(
        &adapter,
        r#"import json
import site
import sys

print(json.dumps({
    "dont_write_bytecode": sys.flags.dont_write_bytecode,
    "ignore_environment": sys.flags.ignore_environment,
    "isolated": sys.flags.isolated,
    "no_user_site": sys.flags.no_user_site,
    "user_site_enabled": site.ENABLE_USER_SITE,
}))
"#,
    )
    .expect("adapter script");

    let output = run_python_adapter(
        &python_interpreter(),
        &adapter,
        temp.path(),
        &[],
        Duration::from_secs(2),
        &[],
        &[],
    )
    .expect("isolated adapter process");

    let flags: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("runtime flags JSON");
    assert_eq!(flags["isolated"], 1);
    assert_eq!(flags["ignore_environment"], 1);
    assert_eq!(flags["no_user_site"], 1);
    assert_eq!(flags["dont_write_bytecode"], 1);
    assert_eq!(flags["user_site_enabled"], false);
}

#[cfg(unix)]
#[test]
fn python_adapter_runner_terminates_descendant_holding_output_pipe() {
    let temp = tempfile::tempdir().expect("tempdir");
    let adapter = temp.path().join("descendant.py");
    let marker = temp.path().join("descendant-survived");
    let marker_literal =
        serde_json::to_string(&marker.display().to_string()).expect("path literal");
    let child_code = format!(
        "import pathlib,time; time.sleep(2); pathlib.Path({marker_literal}).write_text('alive')"
    );
    let child_code_literal = serde_json::to_string(&child_code).expect("child code literal");
    fs::write(
        &adapter,
        format!(
            r#"import subprocess
import sys
subprocess.Popen([sys.executable, "-c", {child_code_literal}])
print("parent exited")
"#
        ),
    )
    .expect("adapter script");

    let started = std::time::Instant::now();
    let error = run_python_adapter(
        &python_interpreter(),
        &adapter,
        temp.path(),
        &[],
        Duration::from_millis(700),
        &[],
        &[],
    )
    .expect_err("a descendant retaining the pipe must trigger bounded termination");
    assert!(started.elapsed() < Duration::from_secs(4), "{error}");
    thread::sleep(Duration::from_millis(2_100));
    assert!(
        !marker.exists(),
        "descendant escaped process-tree termination"
    );
}
