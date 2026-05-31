use super::super::PilotDiagnosisSummary;
use super::*;
use crate::diagnose_file;
use crate::ml::{TrainingOptions, train_model_from_jsonl_with_options};
use crate::models::ActionVerificationVerdict;
use tempfile::tempdir;

fn sample(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data/samples")
        .join(format!("{name}.csv"))
}

fn repo_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("repo root")
        .to_path_buf()
}

fn provision_test_model(artifacts: &std::path::Path) {
    train_model_from_jsonl_with_options(
        repo_root().join("examples/datasets/pilot-smoke-training.jsonl"),
        artifacts.join("model"),
        TrainingOptions {
            min_rows_per_label: 1,
            ..TrainingOptions::default()
        },
    )
    .expect("trained smoke model");
}

fn minimal_pilot_report(artifact_root: &std::path::Path, run_id: String) -> PilotReport {
    PilotReport {
        schema: "netdiag-pilot-report/v1".to_string(),
        generated_at: Utc::now(),
        pilot_id: "test-pilot".to_string(),
        pilot_name: "Test pilot".to_string(),
        read_only: true,
        passed: true,
        run_id,
        pilot_run_dir: artifact_root.display().to_string(),
        source_inventory: Vec::new(),
        connector_health: Vec::new(),
        diagnosis_summary: PilotDiagnosisSummary {
            diagnosis_status: "known".to_string(),
            primary_label: Some("normal".to_string()),
            root_causes: vec!["normal".to_string()],
            recommendation_count: 0,
        },
        evidence_bundle: None,
        checks: Vec::new(),
    }
}

#[test]
fn workflow_propagates_manifest_load_errors() {
    let temp = tempdir().expect("tempdir");
    let manifest = temp.path().join("pilot.yaml");
    std::fs::write(
        &manifest,
        r#"
schema: netdiag-pilot/v1
id: invalid-pilot
name: Invalid pilot
sources: []
"#,
    )
    .expect("manifest");

    let error = run_pilot_workflow(
        &manifest,
        PilotWorkflowOptions {
            artifacts: temp.path().join("artifacts"),
            allow_active: false,
            verification: None,
        },
    )
    .expect_err("invalid manifest should fail before structured preflight");

    assert!(error.to_string().contains("has no sources"));
}

#[test]
fn workflow_returns_structured_report_when_preflight_fails() {
    let temp = tempdir().expect("tempdir");
    let manifest = temp.path().join("pilot.yaml");
    std::fs::write(
        &manifest,
        r#"
schema: netdiag-pilot/v1
id: failing-preflight
name: Failing preflight
sources:
  - name: missing-trace
    kind: trace_file
    endpoint: missing.csv
    role: primary
"#,
    )
    .expect("manifest");

    let report = run_pilot_workflow(
        &manifest,
        PilotWorkflowOptions {
            artifacts: temp.path().join("artifacts"),
            allow_active: false,
            verification: None,
        },
    )
    .expect("workflow report");

    assert!(!report.passed);
    assert!(report.pilot_run.is_none());
    assert_eq!(report.phases[0].status, PilotWorkflowPhaseStatus::Failed);
}

#[test]
fn workflow_propagates_live_collection_errors_after_preflight() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let manifest = temp.path().join("pilot.yaml");
    std::fs::write(
        &manifest,
        r#"
schema: netdiag-pilot/v1
id: live-collection-failure
name: Live collection failure
sources:
  - name: unreachable-http-json
    kind: http_json
    endpoint: http://127.0.0.1:9/netdiag
    role: primary
    collection:
      timeout_secs: 1
"#,
    )
    .expect("manifest");

    let error = run_pilot_workflow(
        &manifest,
        PilotWorkflowOptions {
            artifacts,
            allow_active: false,
            verification: None,
        },
    )
    .expect_err("unreachable live source should fail during run");

    assert!(error.to_string().contains("HTTP/JSON request failed"));
}

#[test]
fn workflow_propagates_verification_errors_after_successful_run() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);

    let error = run_pilot_workflow(
        repo_root().join("examples/pilots/generic-lab-kit.yaml"),
        PilotWorkflowOptions {
            artifacts,
            allow_active: false,
            verification: Some(PilotWorkflowVerificationOptions {
                after_run_id: "missing-after-run".to_string(),
                recommendation_id: None,
                policy_path: None,
                objective_path: None,
            }),
        },
    )
    .expect_err("missing after-run should fail verification");

    assert!(error.to_string().contains("unknown run id"));
}

#[test]
fn workflow_verifies_after_run_from_global_artifacts_root() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let after = diagnose_file(
        sample("congestion"),
        &artifacts,
        Some(("line", "reroute_path_b")),
    )
    .expect("after run");

    let report = run_pilot_workflow(
        repo_root().join("examples/pilots/generic-lab-kit.yaml"),
        PilotWorkflowOptions {
            artifacts,
            allow_active: false,
            verification: Some(PilotWorkflowVerificationOptions {
                after_run_id: after.run_id.clone(),
                recommendation_id: None,
                policy_path: None,
                objective_path: None,
            }),
        },
    )
    .expect("workflow verification");

    let pilot_run = report.pilot_run.as_ref().expect("pilot run");
    let verification = report.verification.as_ref().expect("verification");
    let verification_path = std::path::PathBuf::from(&pilot_run.pilot_run_dir)
        .join("runs")
        .join(&pilot_run.run_id)
        .join(format!("action_verification_{}.json", after.run_id));
    assert_eq!(verification.before_run_id, pilot_run.run_id);
    assert_eq!(verification.after_run_id, after.run_id);
    assert!(verification_path.exists());
    assert!(report.phases.iter().any(|phase| {
        phase.name == "verify" && phase.status == verification_phase_status(verification.verdict)
    }));
}

#[test]
fn workflow_report_fails_when_verification_objective_is_not_met() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let after = diagnose_file(
        sample("normal"),
        &artifacts,
        Some(("line", "reroute_path_b")),
    )
    .expect("after run");
    let objective_path = temp.path().join("objective.yaml");
    std::fs::write(
        &objective_path,
        r#"
objective:
  throughput_delta_pct: ">= 1000"
"#,
    )
    .expect("objective");

    let report = run_pilot_workflow(
        repo_root().join("examples/pilots/loopback-mock.yaml"),
        PilotWorkflowOptions {
            artifacts,
            allow_active: false,
            verification: Some(PilotWorkflowVerificationOptions {
                after_run_id: after.run_id,
                recommendation_id: None,
                policy_path: None,
                objective_path: Some(objective_path),
            }),
        },
    )
    .expect("workflow report");

    let verification = report.verification.as_ref().expect("verification");
    assert_eq!(verification.verdict, ActionVerificationVerdict::NotVerified);
    assert!(!report.passed);
    assert!(report.phases.iter().any(|phase| {
        phase.name == "verify"
            && phase.status == PilotWorkflowPhaseStatus::Failed
            && phase.message.contains("not verified")
    }));
}

#[test]
fn workflow_report_fails_when_verification_metric_is_missing() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let after = diagnose_file(
        sample("normal"),
        &artifacts,
        Some(("line", "reroute_path_b")),
    )
    .expect("after run");
    let objective_path = temp.path().join("missing-metric-objective.yaml");
    std::fs::write(
        &objective_path,
        r#"
objective:
  missing_metric_delta_pct: "<= 0"
"#,
    )
    .expect("objective");

    let report = run_pilot_workflow(
        repo_root().join("examples/pilots/loopback-mock.yaml"),
        PilotWorkflowOptions {
            artifacts,
            allow_active: false,
            verification: Some(PilotWorkflowVerificationOptions {
                after_run_id: after.run_id,
                recommendation_id: None,
                policy_path: None,
                objective_path: Some(objective_path),
            }),
        },
    )
    .expect("workflow report");

    let verification = report.verification.as_ref().expect("verification");
    assert_eq!(
        verification.verdict,
        ActionVerificationVerdict::Inconclusive
    );
    assert!(!report.passed);
    assert!(report.phases.iter().any(|phase| {
        phase.name == "verify"
            && phase.status == PilotWorkflowPhaseStatus::Failed
            && phase.message.contains("inconclusive")
    }));
}

#[test]
fn phase_preserves_status_and_message() {
    let phase = phase("verify", PilotWorkflowPhaseStatus::Pending, "waiting");
    assert_eq!(phase.name, "verify");
    assert_eq!(phase.status, PilotWorkflowPhaseStatus::Pending);
    assert_eq!(phase.message, "waiting");
}

#[test]
fn passed_or_failed_maps_boolean_gate_results() {
    assert_eq!(passed_or_failed(true), PilotWorkflowPhaseStatus::Passed);
    assert_eq!(passed_or_failed(false), PilotWorkflowPhaseStatus::Failed);
}

#[test]
fn workflow_passed_requires_pilot_and_all_phases_to_pass() {
    let temp = tempdir().expect("tempdir");
    let mut pilot_run = minimal_pilot_report(temp.path(), "before".to_string());
    let passed = vec![phase("diagnose", PilotWorkflowPhaseStatus::Passed, "ok")];
    assert!(workflow_passed(&pilot_run, &passed));

    let failed_phase = vec![phase(
        "diagnose",
        PilotWorkflowPhaseStatus::Failed,
        "failed",
    )];
    assert!(!workflow_passed(&pilot_run, &failed_phase));

    pilot_run.passed = false;
    assert!(!workflow_passed(&pilot_run, &passed));
}

#[test]
fn workflow_verification_records_completed_verify_phase() {
    let temp = tempdir().expect("tempdir");
    let before = diagnose_file(
        sample("normal"),
        temp.path(),
        Some(("line", "reroute_path_b")),
    )
    .expect("before run");
    let after = diagnose_file(
        sample("congestion"),
        temp.path(),
        Some(("line", "reroute_path_b")),
    )
    .expect("after run");
    let pilot_run = minimal_pilot_report(temp.path(), before.run_id.clone());
    let mut phases = Vec::new();

    let verification = workflow_verification(
        &mut phases,
        &pilot_run,
        temp.path(),
        Some(PilotWorkflowVerificationOptions {
            after_run_id: after.run_id.clone(),
            recommendation_id: None,
            policy_path: None,
            objective_path: None,
        }),
    )
    .expect("verification")
    .expect("verification report");

    assert_eq!(verification.before_run_id, before.run_id);
    assert_eq!(verification.after_run_id, after.run_id);
    assert_eq!(phases.len(), 1);
    assert_eq!(phases[0].name, "verify");
    assert_eq!(
        phases[0].status,
        verification_phase_status(verification.verdict)
    );
}

#[test]
fn workflow_verification_fails_phase_when_connector_quality_degrades() {
    let temp = tempdir().expect("tempdir");
    let before = diagnose_file(
        sample("normal"),
        temp.path(),
        Some(("line", "reroute_path_b")),
    )
    .expect("before run");
    let after = diagnose_file(
        sample("normal"),
        temp.path(),
        Some(("line", "reroute_path_b")),
    )
    .expect("after run");
    mark_connector_health_degraded(temp.path(), &after.run_id);
    let pilot_run = minimal_pilot_report(temp.path(), before.run_id.clone());
    let mut phases = Vec::new();

    let verification = workflow_verification(
        &mut phases,
        &pilot_run,
        temp.path(),
        Some(PilotWorkflowVerificationOptions {
            after_run_id: after.run_id,
            recommendation_id: None,
            policy_path: None,
            objective_path: None,
        }),
    )
    .expect("verification")
    .expect("verification report");

    assert_eq!(
        verification.verdict,
        ActionVerificationVerdict::Inconclusive
    );
    assert_eq!(phases.len(), 1);
    assert_eq!(phases[0].name, "verify");
    assert_eq!(phases[0].status, PilotWorkflowPhaseStatus::Failed);
    assert!(phases[0].message.contains("quality degraded"));
}

#[test]
fn workflow_verification_bubbles_missing_after_run_error() {
    let temp = tempdir().expect("tempdir");
    let before = diagnose_file(
        sample("normal"),
        temp.path(),
        Some(("line", "reroute_path_b")),
    )
    .expect("before run");
    let pilot_run = minimal_pilot_report(temp.path(), before.run_id);
    let mut phases = Vec::new();

    let error = workflow_verification(
        &mut phases,
        &pilot_run,
        temp.path(),
        Some(PilotWorkflowVerificationOptions {
            after_run_id: "missing-after-run".to_string(),
            recommendation_id: None,
            policy_path: None,
            objective_path: None,
        }),
    )
    .expect_err("missing after run should fail");

    assert!(error.to_string().contains("unknown run id"));
    assert!(phases.is_empty());
}

#[test]
fn workflow_verification_reports_pending_when_no_after_run_is_configured() {
    let temp = tempdir().expect("tempdir");
    let pilot_run = minimal_pilot_report(temp.path(), "before".to_string());
    let mut phases = Vec::new();

    let verification = workflow_verification(&mut phases, &pilot_run, temp.path(), None)
        .expect("verification phase");

    assert!(verification.is_none());
    assert_eq!(phases.len(), 1);
    assert_eq!(phases[0].status, PilotWorkflowPhaseStatus::Pending);
    assert_eq!(phases[0].message, "no after-run configured yet");
}

#[test]
fn workflow_options_round_trip_verification_paths() {
    let options = PilotWorkflowOptions {
        artifacts: "artifacts".into(),
        allow_active: true,
        verification: Some(PilotWorkflowVerificationOptions {
            after_run_id: "after".to_string(),
            recommendation_id: Some("rec-1".to_string()),
            policy_path: Some("policy.yaml".into()),
            objective_path: Some("objective.yaml".into()),
        }),
    };

    let round_trip: PilotWorkflowOptions =
        serde_json::from_value(serde_json::to_value(&options).expect("json")).expect("round trip");

    let verification = round_trip.verification.expect("verification options");
    assert!(round_trip.allow_active);
    assert_eq!(verification.after_run_id, "after");
    assert_eq!(verification.recommendation_id.as_deref(), Some("rec-1"));
    assert_eq!(
        verification.policy_path.as_deref(),
        Some(std::path::Path::new("policy.yaml"))
    );
    assert_eq!(
        verification.objective_path.as_deref(),
        Some(std::path::Path::new("objective.yaml"))
    );
}

fn mark_connector_health_degraded(artifact_root: &std::path::Path, run_id: &str) {
    let path = crate::storage::run_dir(artifact_root, run_id).join("connector_health.json");
    let raw = std::fs::read_to_string(&path).expect("connector health");
    let mut value: serde_json::Value = serde_json::from_str(&raw).expect("connector health json");
    value["status"] = serde_json::Value::String("degraded".to_string());
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&value).expect("connector health json"),
    )
    .expect("write degraded connector health");
}
