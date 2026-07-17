use super::*;
use netdiag_core::diagnose_file;
use netdiag_core::ml::{
    MODEL_GENERATIONS_DIR_NAME, MODEL_MANIFEST_FILE_NAME, TrainingOptions,
    load_existing_model_bundle_identity, replace_model_manifest_if_current,
    train_model_from_jsonl_with_options,
};
use netdiag_core::models::{FaultLabel, ModelUncertaintyThresholds};
use netdiag_core::storage::save_json_atomic;
use tempfile::tempdir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("repo root")
        .to_path_buf()
}

fn sample(name: &str) -> PathBuf {
    repo_root().join("data/samples").join(format!("{name}.csv"))
}

fn provision_model(artifacts: &std::path::Path) {
    netdiag_core::storage::ensure_artifact_root_owned(artifacts).expect("owned artifacts dir");
    train_model_from_jsonl_with_options(
        repo_root().join("examples/datasets/pilot-smoke-training.jsonl"),
        artifacts.join("model"),
        TrainingOptions {
            min_rows_per_label: 1,
            ..TrainingOptions::default()
        },
    )
    .expect("trained model");
}

fn write_passing_benchmark(path: &std::path::Path, model_dir: &std::path::Path) {
    let identity = load_existing_model_bundle_identity(model_dir).expect("model identity");
    let report = serde_json::json!({
        "schema": "netdiag-benchmark-report/v1",
        "generated_at": "2026-01-01T00:00:00Z",
        "suite": "test",
        "passed": true,
        "artifacts": "test",
        "output": "test",
        "candidate_model_manifest_hash_sha256": identity.model_manifest_hash_sha256,
        "candidate_model_file_hash_sha256": identity.model_file_hash_sha256,
        "candidate_dataset_hash_sha256": identity.manifest.dataset_hash_sha256,
        "environment": {
            "os": "test",
            "arch": "test",
            "profile": "test"
        },
        "sections": [{
            "name": "ood benchmark preflight",
            "status": "ok",
            "elapsed_millis": 1.0,
            "checks": [{
                "name": "ood-cpu-saturation",
                "status": "ok",
                "message": "static preflight passed"
            }]
        }]
    });
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&report).expect("benchmark json"),
    )
    .expect("benchmark report");
}

fn write_passing_calibration(artifacts: &std::path::Path) -> PathBuf {
    let model_dir = artifacts.join("model");
    let source = load_existing_model_bundle_identity(&model_dir).expect("source model identity");
    let mut manifest = source.manifest.clone();
    let thresholds = ModelUncertaintyThresholds::default();
    manifest.uncertainty_thresholds = Some(thresholds.clone());
    replace_model_manifest_if_current(&model_dir, &source.model_manifest_hash_sha256, &manifest)
        .expect("manifest thresholds");
    let current = load_existing_model_bundle_identity(&model_dir).expect("calibrated model");
    let manifest_path = model_dir
        .join(MODEL_GENERATIONS_DIR_NAME)
        .join(current.generation.as_deref().expect("generation"))
        .join(MODEL_MANIFEST_FILE_NAME);

    let per_label = FaultLabel::ALL
        .iter()
        .map(|label| {
            (
                label.as_str().to_string(),
                serde_json::json!({
                    "runs": 1,
                    "accepted_known_runs": 1,
                    "rule_correct": 1,
                    "ml_correct": 1,
                    "rule_accuracy": 1.0,
                    "ml_accuracy": 1.0,
                    "known_rate": 1.0,
                    "uncertain_rate": 0.0,
                    "out_of_distribution_rate": 0.0
                }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let report = serde_json::json!({
        "schema": "netdiag-lab-calibration/v2",
        "generated_at": "2026-01-01T00:00:00Z",
        "artifact_root": artifacts.display().to_string(),
        "model_manifest_path": manifest_path.display().to_string(),
        "source_model_manifest_hash_sha256": source.model_manifest_hash_sha256,
        "model_manifest_hash_sha256": current.model_manifest_hash_sha256,
        "model_file_hash_sha256": current.model_file_hash_sha256,
        "dataset_hash_sha256": manifest.dataset_hash_sha256,
        "evaluated_runs": FaultLabel::ALL.len() + 1,
        "known_runs": FaultLabel::ALL.len(),
        "uncertain_runs": 0,
        "out_of_distribution_runs": 1,
        "skipped_runs": 0,
        "per_label": per_label,
        "ood": {
            "expected_ood_runs": 1,
            "expected_known_runs": FaultLabel::ALL.len(),
            "false_positive_runs": 0,
            "false_negative_runs": 0,
            "false_positive_rate": 0.0,
            "false_negative_rate": 0.0
        },
        "rule_ml_disagreement_hotspots": [],
        "feature_distance_distribution": {
            "count": FaultLabel::ALL.len() + 1,
            "p50": 1.0,
            "p95": 2.0,
            "max": 3.0
        },
        "suggested_rule_thresholds": {},
        "applied": true,
        "calibrated_thresholds": thresholds,
        "warnings": []
    });
    let calibration_path = artifacts.join("lab_calibration_report.json");
    save_json_atomic(&calibration_path, &report).expect("calibration report");
    calibration_path
}

#[test]
fn preflight_command_succeeds_for_connector_family_manifest() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_model(&artifacts);

    run(PilotCommand::Preflight {
        pilot: repo_root().join("examples/pilots/connector-family-readonly.yaml"),
        artifacts,
        allow_active: false,
        bearer_bindings: CliBearerBindings::default(),
    })
    .expect("preflight command");
}

#[test]
fn run_command_succeeds_for_loopback_manifest() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_model(&artifacts);

    run(PilotCommand::Run {
        pilot: repo_root().join("examples/pilots/loopback-mock.yaml"),
        artifacts,
        allow_active: false,
        allow_adapter_execution: true,
        bearer_bindings: CliBearerBindings::default(),
    })
    .expect("run command");
}

#[test]
fn workflow_command_fails_without_after_run_verification() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_model(&artifacts);

    let error = run(PilotCommand::Workflow {
        pilot: repo_root().join("examples/pilots/generic-lab-kit.yaml"),
        artifacts,
        allow_active: false,
        allow_adapter_execution: true,
        after_run_id: None,
        recommendation_id: None,
        policy: None,
        objective: None,
        bearer_bindings: CliBearerBindings::default(),
    })
    .expect_err("workflow should not pass with pending verification");

    assert!(error.to_string().contains("pilot workflow gates failed"));
}

#[test]
fn workflow_command_succeeds_with_after_run_verification() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_model(&artifacts);
    let after = diagnose_file(
        sample("normal"),
        &artifacts,
        Some(("line", "reroute_path_b")),
    )
    .expect("after run");

    run(PilotCommand::Workflow {
        pilot: repo_root().join("examples/pilots/generic-lab-kit.yaml"),
        artifacts,
        allow_active: false,
        allow_adapter_execution: true,
        after_run_id: Some(after.run_id),
        recommendation_id: None,
        policy: None,
        objective: None,
        bearer_bindings: CliBearerBindings::default(),
    })
    .expect("workflow command");
}

#[test]
fn model_gate_command_succeeds_with_missing_evaluation_override() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_model(&artifacts);
    let benchmark_report = temp.path().join("benchmark_report.json");
    let calibration_report = write_passing_calibration(&artifacts);
    write_passing_benchmark(&benchmark_report, &artifacts.join("model"));

    run(PilotCommand::ModelGate {
        model_dir: artifacts.join("model"),
        benchmark_report,
        calibration_report,
        min_rows_per_label: 1,
        min_accuracy: 0.9,
        min_macro_f1: 0.9,
        allow_missing_evaluation: true,
        max_ood_false_positive_rate: 0.05,
        max_ood_false_negative_rate: 0.05,
        max_rule_ml_disagreement_hotspot_rate: 0.10,
        max_calibration_age_days: 1000,
        min_expected_ood_runs: 1,
    })
    .expect("model gate command");
}
