use super::{fail_next_manifest_update, record_action_verification_artifact};
use crate::models::{
    ActionVerification, ActionVerificationVerdict, ConnectorHealthStatus, DiagnosisStatus,
    HilReviewSummary, MeasurementQualitySummary, RunComparison, RunHistoryEntry, RunManifest,
};
use crate::storage::{read_json, save_json};
use chrono::Utc;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};

fn history_entry(run_id: &str) -> RunHistoryEntry {
    RunHistoryEntry {
        run_id: run_id.to_string(),
        sample: "sample".to_string(),
        created_at: Utc::now(),
        status: "complete".to_string(),
        run_dir: format!("runs/{run_id}"),
        root_causes: Vec::new(),
        diagnosis_status: DiagnosisStatus::Known,
        uncertainty_reason_codes: Vec::new(),
        ml_top_label: None,
        ml_top_probability: None,
        model_kind: None,
        synthetic_model: false,
        measurement_quality: Vec::new(),
        quality: MeasurementQualitySummary::default(),
        quality_status: ConnectorHealthStatus::Ok,
        warning_count: 0,
        hil_summary: HilReviewSummary::default(),
        artifact_count: 0,
    }
}

fn verification(after_run_id: &str) -> ActionVerification {
    ActionVerification {
        schema: "netdiag-action-verification/v1".to_string(),
        generated_at: Utc::now(),
        before_run_id: "before".to_string(),
        after_run_id: after_run_id.to_string(),
        recommendation_id: None,
        predicted_what_if_effect: None,
        predicted_deltas_pct: BTreeMap::new(),
        observed_deltas_pct: BTreeMap::new(),
        prediction_error_pct: BTreeMap::new(),
        objective: BTreeMap::new(),
        fail_if: BTreeMap::new(),
        observed_comparison: RunComparison {
            left: history_entry("before"),
            right: history_entry(after_run_id),
            latency_p95_delta_pct: None,
            loss_delta_pct: None,
            throughput_delta_pct: None,
            ml_label_changed: false,
            new_root_causes: Vec::new(),
            resolved_root_causes: Vec::new(),
            review_status_changed: false,
            recommendation_state_changes: Vec::new(),
            measurement_quality_changes: Vec::new(),
            quality_status_changed: false,
            warning_count_delta: 0,
        },
        verdict: ActionVerificationVerdict::Inconclusive,
        reasons: Vec::new(),
    }
}

fn create_run_dir(root: &Path, manifest_run_id: &str) -> std::path::PathBuf {
    let run_dir = root.join("runs").join("before");
    std::fs::create_dir_all(&run_dir).expect("run directory");
    save_json(
        run_dir.join("manifest.json"),
        &RunManifest {
            run_id: manifest_run_id.to_string(),
            sample: "sample".to_string(),
            created_at: Utc::now(),
            trace_rows: 1,
            artifact_paths: BTreeMap::new(),
        },
    )
    .expect("manifest");
    run_dir
}

#[test]
fn missing_manifest_rejects_without_writing_artifact() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = temp.path().join("runs/before");
    std::fs::create_dir_all(&run_dir).expect("run directory");

    let error = record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect_err("missing manifest must fail");

    assert!(error.to_string().contains("run manifest is missing"));
    assert!(!run_dir.join("action_verification_after.json").exists());
}

#[test]
fn corrupt_manifest_rejects_without_writing_artifact() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = temp.path().join("runs/before");
    std::fs::create_dir_all(&run_dir).expect("run directory");
    std::fs::write(run_dir.join("manifest.json"), b"not-json").expect("corrupt manifest");

    let error = record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect_err("corrupt manifest must fail");

    assert!(error.to_string().contains("invalid run manifest"));
    assert!(!run_dir.join("action_verification_after.json").exists());
}

#[cfg(unix)]
#[test]
fn symlink_manifest_rejects_without_writing_artifact() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = temp.path().join("runs/before");
    std::fs::create_dir_all(&run_dir).expect("run directory");
    let outside_manifest = temp.path().join("outside-manifest.json");
    save_json(
        &outside_manifest,
        &RunManifest {
            run_id: "before".to_string(),
            sample: "sample".to_string(),
            created_at: Utc::now(),
            trace_rows: 1,
            artifact_paths: BTreeMap::new(),
        },
    )
    .expect("outside manifest");
    symlink(&outside_manifest, run_dir.join("manifest.json")).expect("manifest symlink");

    let error = record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect_err("symlink manifest must fail");

    assert!(error.to_string().contains("not a regular file"));
    assert!(!run_dir.join("action_verification_after.json").exists());
}

#[test]
fn wrong_run_manifest_rejects_without_writing_artifact() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = create_run_dir(temp.path(), "another-run");

    let error = record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect_err("wrong run manifest must fail");

    assert!(
        error
            .to_string()
            .contains("does not match action verification")
    );
    assert!(!run_dir.join("action_verification_after.json").exists());
}

#[test]
fn concurrent_manifest_updates_preserve_both_artifacts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = Arc::new(create_run_dir(temp.path(), "before"));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for after_run_id in ["after-one", "after-two"] {
        let run_dir = Arc::clone(&run_dir);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let verification = verification(after_run_id);
            barrier.wait();
            record_action_verification_artifact(&run_dir, after_run_id, &verification)
        }));
    }
    barrier.wait();
    for handle in handles {
        handle.join().expect("verification thread").expect("record");
    }

    let manifest: RunManifest =
        serde_json::from_value(read_json(run_dir.join("manifest.json")).expect("read manifest"))
            .expect("parse manifest");
    assert_eq!(
        manifest
            .artifact_paths
            .get("action_verification_after-one")
            .map(String::as_str),
        Some("action_verification_after-one.json")
    );
    assert_eq!(
        manifest
            .artifact_paths
            .get("action_verification_after-two")
            .map(String::as_str),
        Some("action_verification_after-two.json")
    );
    assert!(run_dir.join("action_verification_after-one.json").exists());
    assert!(run_dir.join("action_verification_after-two.json").exists());
}

#[test]
fn manifest_update_failure_leaves_a_recoverable_transaction_and_retry_commits() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = create_run_dir(temp.path(), "before");
    let manifest_path = run_dir.join("manifest.json");
    let original_manifest = std::fs::read(&manifest_path).expect("manifest preimage");
    fail_next_manifest_update();

    let error = record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect_err("injected update failure");

    assert!(error.to_string().contains("injected action verification"));
    assert_eq!(
        std::fs::read(&manifest_path).expect("unchanged manifest"),
        original_manifest
    );
    assert!(run_dir.join("action_verification_after.json").is_file());
    assert_pending_transaction_blocks_read(temp.path());

    record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect("retry must roll the transaction forward");

    assert_committed_artifact(&run_dir, "after");
}

#[test]
fn abrupt_process_exit_after_each_publication_step_recovers_without_an_orphan() {
    for (crash_point, expected_exit_code) in [("after_artifact", 86), ("after_manifest", 87)] {
        let temp = tempfile::tempdir().expect("tempdir");
        let run_dir = create_run_dir(temp.path(), "before");
        let status = spawn_crash_helper(&run_dir, crash_point);
        assert_eq!(status.code(), Some(expected_exit_code), "{crash_point}");
        assert_pending_transaction_blocks_read(temp.path());

        record_action_verification_artifact(&run_dir, "after", &verification("after"))
            .expect("retry must recover the interrupted transaction");

        assert_committed_artifact(&run_dir, "after");
        let action_files = std::fs::read_dir(&run_dir)
            .expect("run directory")
            .map(|entry| entry.expect("directory entry").file_name())
            .filter(|name| {
                name.to_string_lossy().starts_with("action_verification_")
                    && name.to_string_lossy().ends_with(".json")
                    && name.to_string_lossy() != "action_verification_transaction.json"
            })
            .collect::<Vec<_>>();
        assert_eq!(action_files.len(), 1, "{crash_point}");
    }
}

#[test]
fn recovery_rejects_manifest_new_artifact_old_state_instead_of_healing_tampering() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = create_run_dir(temp.path(), "before");
    let status = spawn_crash_helper(&run_dir, "after_manifest");
    assert_eq!(status.code(), Some(87));
    let artifact_path = run_dir.join("action_verification_after.json");
    std::fs::remove_file(&artifact_path).expect("simulate artifact rollback after manifest commit");

    let error = record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect_err("an impossible publication order must fail closed");

    assert!(
        error
            .to_string()
            .contains("manifest contains the new artifact reference"),
        "{error}"
    );
    assert!(
        !artifact_path.exists(),
        "recovery must not conceal tampering"
    );
    assert_pending_transaction_blocks_read(temp.path());
}

#[test]
fn committed_receipt_rejects_artifact_tampering_before_a_new_transaction() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = create_run_dir(temp.path(), "before");
    record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect("initial transaction");
    let artifact_path = run_dir.join("action_verification_after.json");
    std::fs::write(&artifact_path, b"tampered").expect("tamper artifact");

    let error =
        record_action_verification_artifact(&run_dir, "after-two", &verification("after-two"))
            .expect_err("committed receipt must detect artifact tampering");

    assert!(
        error
            .to_string()
            .contains("action verification transaction conflict"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&artifact_path).expect("tampered bytes"),
        b"tampered"
    );
    let manifest: RunManifest =
        serde_json::from_value(read_json(run_dir.join("manifest.json")).expect("manifest"))
            .expect("manifest schema");
    assert!(
        !manifest
            .artifact_paths
            .contains_key("action_verification_after-two")
    );
}

#[test]
fn cumulative_receipt_rejects_older_artifact_tampering_before_a_third_transaction() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = create_run_dir(temp.path(), "before");
    for after_run_id in ["after-one", "after-two"] {
        record_action_verification_artifact(&run_dir, after_run_id, &verification(after_run_id))
            .expect("commit action verification");
    }
    let first_artifact = run_dir.join("action_verification_after-one.json");
    std::fs::write(&first_artifact, b"tampered older artifact").expect("tamper first artifact");

    let error =
        record_action_verification_artifact(&run_dir, "after-three", &verification("after-three"))
            .expect_err("every historical action artifact must remain hash-bound");

    assert!(
        error
            .to_string()
            .contains("action artifact action_verification_after-one"),
        "{error}"
    );
    let manifest: RunManifest =
        serde_json::from_value(read_json(run_dir.join("manifest.json")).expect("manifest"))
            .expect("manifest schema");
    assert!(
        !manifest
            .artifact_paths
            .contains_key("action_verification_after-three")
    );
    let journal = read_json(run_dir.join("action_verification_transaction.json"))
        .expect("cumulative receipt");
    assert_eq!(
        journal["artifacts"]
            .as_object()
            .expect("artifact receipts")
            .len(),
        2
    );
}

#[test]
fn committed_receipt_allows_unrelated_manifest_updates_before_a_new_transaction() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = create_run_dir(temp.path(), "before");
    record_action_verification_artifact(&run_dir, "after", &verification("after"))
        .expect("initial transaction");
    let manifest_path = run_dir.join("manifest.json");
    let mut manifest: RunManifest =
        serde_json::from_value(read_json(&manifest_path).expect("manifest"))
            .expect("manifest schema");
    manifest
        .artifact_paths
        .insert("unrelated".to_string(), "unrelated.json".to_string());
    save_json(&manifest_path, &manifest).expect("legitimate manifest update");

    record_action_verification_artifact(&run_dir, "after-two", &verification("after-two"))
        .expect("receipt must validate its own slot without freezing the whole manifest");

    assert_committed_artifact(&run_dir, "after-two");
    let updated: RunManifest =
        serde_json::from_value(read_json(manifest_path).expect("updated manifest"))
            .expect("updated manifest schema");
    assert_eq!(
        updated.artifact_paths.get("unrelated").map(String::as_str),
        Some("unrelated.json")
    );
}

#[test]
fn subprocess_crash_action_verification_helper() {
    let Some(run_dir) = std::env::var_os("NETDIAG_TEST_ACTION_VERIFICATION_RUN_DIR") else {
        return;
    };
    let run_dir = std::path::PathBuf::from(run_dir);
    let result = record_action_verification_artifact(&run_dir, "after", &verification("after"));
    panic!("crash failpoint did not terminate the helper: {result:?}");
}

fn spawn_crash_helper(run_dir: &Path, crash_point: &str) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "lab::action_verification_artifact::tests::subprocess_crash_action_verification_helper",
            "--nocapture",
        ])
        .env("NETDIAG_TEST_ACTION_VERIFICATION_RUN_DIR", run_dir)
        .env("NETDIAG_TEST_ACTION_VERIFICATION_CRASH_POINT", crash_point)
        .status()
        .expect("crash helper process")
}

fn assert_pending_transaction_blocks_read(artifact_root: &Path) {
    let error = crate::storage::read_manifest(artifact_root, "before")
        .expect_err("pending transaction reads must fail closed");
    assert!(
        error
            .to_string()
            .contains("pending action verification transaction"),
        "{error}"
    );
    let journal = read_json(
        artifact_root
            .join("runs/before")
            .join("action_verification_transaction.json"),
    )
    .expect("transaction journal");
    assert_eq!(journal["phase"], "committing");
}

fn assert_committed_artifact(run_dir: &Path, after_run_id: &str) {
    let artifact_key = format!("action_verification_{after_run_id}");
    let file_name = format!("{artifact_key}.json");
    let manifest: RunManifest =
        serde_json::from_value(read_json(run_dir.join("manifest.json")).expect("manifest"))
            .expect("manifest schema");
    assert_eq!(
        manifest
            .artifact_paths
            .get(&artifact_key)
            .map(String::as_str),
        Some(file_name.as_str())
    );
    assert!(run_dir.join(file_name).is_file());
    let journal = read_json(run_dir.join("action_verification_transaction.json"))
        .expect("transaction receipt");
    assert_eq!(journal["phase"], "committed");
    assert!(journal["artifacts"].get(&artifact_key).is_some());
    assert!(journal.get("verification").is_none());
    assert!(journal.get("manifest").is_none());
}
