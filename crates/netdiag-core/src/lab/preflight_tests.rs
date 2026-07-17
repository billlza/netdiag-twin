use super::*;
use crate::connectors::authentication::{
    BearerEnvironmentBinding, BearerEnvironmentBindings, BearerSourceKind,
};

#[test]
fn manifest_bearer_declaration_is_not_an_environment_authorization() {
    let temp = tempfile::tempdir().expect("tempdir");
    let scenario_path = temp.path().join("scenario.yaml");
    let artifacts = temp.path().join("artifacts");
    std::fs::write(
        &scenario_path,
        r#"schema: netdiag-lab-scenario/v1
id: unauthorized-lab-source
name: Unauthorized lab source
data_sources:
  - name: gateway
    role: primary
    kind: http-json
    endpoint: http://127.0.0.1:1/adapter
    bearer_token_env: AWS_SECRET_ACCESS_KEY
"#,
    )
    .expect("scenario");

    let report = preflight_lab_scenario(
        &scenario_path,
        LabPreflightOptions {
            artifacts: artifacts.clone(),
            mode: LabPreflightMode::Live,
        },
    )
    .expect("structured preflight failure");

    assert!(!report.passed);
    let binding_check = report
        .checks
        .iter()
        .find(|check| check.name == "bearer environment bindings valid")
        .expect("binding check");
    assert_eq!(binding_check.status, LabPreflightCheckStatus::Failed);
    assert!(binding_check.message.contains("not externally authorized"));
    assert!(!artifacts.exists(), "failure must precede artifact writes");
}

#[test]
fn static_preflight_validates_exact_binding_without_reading_the_environment() {
    let temp = tempfile::tempdir().expect("tempdir");
    let scenario_path = temp.path().join("scenario.yaml");
    std::fs::write(
        &scenario_path,
        r#"schema: netdiag-lab-scenario/v1
id: bound-lab-source
name: Bound lab source
data_sources:
  - name: gateway
    role: primary
    kind: http-json
    endpoint: https://example.invalid/adapter
    bearer_token_env: DEFINITELY_NOT_SET_FOR_STATIC_PREFLIGHT
"#,
    )
    .expect("scenario");
    let bindings = BearerEnvironmentBindings::new([BearerEnvironmentBinding::new(
        "gateway",
        BearerSourceKind::HttpJson,
        "https://example.invalid/other-path",
        "DEFINITELY_NOT_SET_FOR_STATIC_PREFLIGHT",
    )
    .expect("binding")])
    .expect("bindings");

    let report = preflight_lab_scenario_with_bearer_bindings(
        &scenario_path,
        LabPreflightOptions {
            artifacts: temp.path().join("artifacts"),
            mode: LabPreflightMode::Static,
        },
        &bindings,
    )
    .expect("static preflight");

    let binding_check = report
        .checks
        .iter()
        .find(|check| check.name == "bearer environment bindings valid")
        .expect("binding check");
    assert_eq!(binding_check.status, LabPreflightCheckStatus::Passed);
}

#[test]
fn lab_run_resolves_authorized_environment_before_network_or_staging() {
    const ENVIRONMENT: &str = "NETDIAG_TEST_MISSING_LAB_BEARER_05_3";
    assert!(
        std::env::var_os(ENVIRONMENT).is_none(),
        "test requires an absent environment variable"
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let scenario_path = temp.path().join("scenario.yaml");
    let artifacts = temp.path().join("artifacts");
    std::fs::write(
        &scenario_path,
        format!(
            r#"schema: netdiag-lab-scenario/v1
id: missing-authorized-token
name: Missing authorized token
data_sources:
  - name: gateway
    role: primary
    kind: http-json
    endpoint: http://127.0.0.1:1/adapter
    bearer_token_env: {ENVIRONMENT}
"#
        ),
    )
    .expect("scenario");
    let bindings = BearerEnvironmentBindings::new([BearerEnvironmentBinding::new(
        "gateway",
        BearerSourceKind::HttpJson,
        "http://127.0.0.1:1/different-path",
        ENVIRONMENT,
    )
    .expect("binding")])
    .expect("bindings");

    let error = run_lab_scenario_with_bearer_bindings(
        &scenario_path,
        LabRunOptions {
            artifacts: artifacts.clone(),
        },
        &bindings,
    )
    .expect_err("missing authorized environment must fail before collection");

    assert!(error.to_string().contains("is not set"));
    assert!(
        !artifacts.join("lab-runs").exists(),
        "token resolution must precede lab staging"
    );
}

#[test]
fn static_preflight_parses_trace_file_schema() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bad_trace = temp.path().join("bad.csv");
    std::fs::write(&bad_trace, "timestamp,latency_ms\nnot-a-time,10\n").expect("bad trace");
    let scenario_path = temp.path().join("scenario.yaml");
    std::fs::write(
        &scenario_path,
        format!(
            r#"schema: netdiag-lab-scenario/v1
id: lab-bad-trace-preflight
name: Bad trace preflight
expected_label: normal
data_sources:
  - role: primary
    kind: trace-file
    endpoint: "{}"
"#,
            bad_trace.display()
        ),
    )
    .expect("scenario");

    let report = preflight_lab_scenario(
        &scenario_path,
        LabPreflightOptions {
            artifacts: temp.path().join("artifacts"),
            mode: LabPreflightMode::Static,
        },
    )
    .expect("preflight report");

    assert!(!report.passed);
    assert!(
        report.checks.iter().any(|check| {
            check.name == "primary source reachable"
                && check.status == LabPreflightCheckStatus::Failed
        }),
        "{:?}",
        report.checks
    );
}

#[test]
fn static_preflight_fails_bad_corroborating_trace_file_schema() {
    let temp = tempfile::tempdir().expect("tempdir");
    let good_trace = temp.path().join("good.csv");
    std::fs::write(
        &good_trace,
        "timestamp,latency_ms,packet_loss_rate,retransmission_rate,throughput_mbps\n2026-04-30T12:00:00Z,10,0,0,100\n",
    )
    .expect("good trace");
    let bad_trace = temp.path().join("bad.csv");
    std::fs::write(
        &bad_trace,
        "timestamp,latency_ms,packet_loss_rate,retransmission_rate,throughput_mbps\n2026-04-30T12:00:00Z,-1,0,0,100\n",
    )
    .expect("bad trace");
    let scenario_path = temp.path().join("scenario.yaml");
    std::fs::write(
        &scenario_path,
        format!(
            r#"schema: netdiag-lab-scenario/v1
id: lab-bad-corroborating-trace-preflight
name: Bad corroborating trace preflight
expected_label: normal
data_sources:
  - role: primary
    kind: trace-file
    endpoint: "{}"
  - name: corroborating
    role: corroborating
    kind: trace-file
    endpoint: "{}"
"#,
            good_trace.display(),
            bad_trace.display()
        ),
    )
    .expect("scenario");

    let report = preflight_lab_scenario(
        &scenario_path,
        LabPreflightOptions {
            artifacts: temp.path().join("artifacts"),
            mode: LabPreflightMode::Static,
        },
    )
    .expect("preflight report");

    assert!(!report.passed);
    assert!(
        report.checks.iter().any(|check| {
            check.name == "corroborating reachable"
                && check.required
                && check.status == LabPreflightCheckStatus::Failed
        }),
        "{:?}",
        report.checks
    );
}
