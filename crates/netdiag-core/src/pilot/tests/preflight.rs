use super::*;

#[test]
fn preflight_rejects_nonempty_unowned_artifact_root_without_claiming_it() {
    let temp = tempdir().expect("tempdir");
    let input_dir = temp.path().join("inputs");
    let artifacts = temp.path().join("artifacts");
    fs::create_dir(&input_dir).expect("input directory");
    fs::create_dir(&artifacts).expect("artifact directory");
    let sentinel = artifacts.join("sentinel");
    fs::write(&sentinel, b"preserve-me").expect("unowned sentinel");
    let manifest_path = input_dir.join("pilot.yaml");
    fs::write(
        &manifest_path,
        r#"schema: netdiag-pilot/v1
id: unowned-artifacts
name: Unowned artifacts
sources:
  - name: gateway
    kind: http_json
    endpoint: https://example.invalid/adapter
    role: primary
"#,
    )
    .expect("manifest");

    let report = preflight_pilot(
        &manifest_path,
        PilotOptions {
            artifacts: artifacts.clone(),
            allow_active: false,
            allow_adapter_execution: false,
        },
    )
    .expect("artifact ownership failure must remain a structured preflight result");

    assert!(!report.passed);
    let artifact_check = report
        .checks
        .iter()
        .find(|check| check.name == "artifact directory writable")
        .expect("artifact directory check");
    assert_eq!(
        artifact_check.status,
        crate::models::ConnectorHealthStatus::Error
    );
    assert_eq!(
        artifact_check.reason_codes.as_slice(),
        &[crate::reliability::ReliabilityReasonCode::PermissionDenied]
    );
    assert!(artifact_check.message.contains("explicit migration"));
    assert_eq!(
        fs::read(&sentinel).expect("preserved sentinel"),
        b"preserve-me"
    );
    assert!(!artifacts.join(".netdiag-artifact-root.json").exists());
}
