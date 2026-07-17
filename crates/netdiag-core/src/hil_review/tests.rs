use super::*;
use crate::models::{HilState, Recommendation, RunManifest};
use crate::pipeline::diagnose_file;
use crate::storage::hil_transaction::JournalPhase;
use crate::storage::{read_json, read_report, save_json_atomic};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::Duration;

fn sample(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("data")
        .join("samples")
        .join(format!("{name}.csv"))
}

fn diagnose(root: &Path) -> crate::pipeline::PipelineResult {
    diagnose_file(sample("congestion"), root, Some(("line", "reroute_path_b")))
        .expect("diagnose fixture")
}

#[test]
fn pending_transaction_rolls_forward_with_fixed_review_time() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    fail_before_publishing("report");

    let error = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("injected failure");
    assert!(
        error
            .to_string()
            .contains("injected HIL transaction failure")
    );

    let pending = load_journal(&result.run_dir, &result.run_id)
        .expect("journal")
        .expect("pending journal");
    assert_eq!(pending.phase, JournalPhase::Committing);
    assert!(pending.target("recommendations").is_some());
    assert!(pending.target("report").is_some());
    assert!(pending.target("manifest").is_some());
    assert_eq!(pending.targets.len(), 5);
    let reviewed_at = pending.review.reviewed_at;
    let read_error = read_report(temp.path(), &result.run_id)
        .expect_err("pending transaction reads must fail closed");
    assert!(read_error.to_string().contains("pending HIL transaction"));

    let outcome = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect("recover transaction");

    assert_eq!(outcome.review.reviewed_at, reviewed_at);
    let committed = load_journal(&result.run_dir, &result.run_id)
        .expect("journal")
        .expect("committed journal");
    assert_eq!(committed.phase, JournalPhase::Committed);
    assert_eq!(committed.review.reviewed_at, reviewed_at);
    let report = read_report(temp.path(), &result.run_id).expect("report after recovery");
    assert_eq!(report.recommendations[0].hil_state, HilState::Accepted);
    assert_no_staged_files(&result.run_dir);
}

#[cfg(unix)]
#[test]
fn process_exit_after_all_targets_publish_rolls_forward_without_partial_visibility() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    let status = spawn_commit_receipt_crash_helper(temp.path(), &result.run_id);
    assert_eq!(status.code(), Some(88));

    let pending = load_journal(&result.run_dir, &result.run_id)
        .expect("journal")
        .expect("pending journal");
    assert_eq!(pending.phase, JournalPhase::Committing);
    assert_eq!(pending.targets.len(), 5);
    for target in &pending.targets {
        let path = PathBuf::from(&target.target_path);
        let actual =
            crate::storage::sha256_stable_regular_file_bounded(&path, MAX_TRANSACTION_JSON_BYTES)
                .expect("published target hash")
                .expect("published target");
        assert_eq!(actual, target.new_sha256, "{}", target.key);
    }
    assert_no_staged_files(&result.run_dir);

    let read_error = read_report(temp.path(), &result.run_id)
        .expect_err("a transaction without its commit receipt must remain invisible");
    assert!(
        read_error.to_string().contains("pending HIL transaction"),
        "{read_error}"
    );

    let outcome = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "crash recovery review",
        "crash-test-reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect("retry must publish the commit receipt");

    assert_eq!(outcome.review.state, HilState::Accepted);
    assert_eq!(outcome.review.reviewed_at, pending.review.reviewed_at);
    let committed = load_journal(&result.run_dir, &result.run_id)
        .expect("journal")
        .expect("committed journal");
    assert_eq!(committed.phase, JournalPhase::Committed);
    let report = read_report(temp.path(), &result.run_id).expect("committed report");
    assert_eq!(report.recommendations[0].hil_state, HilState::Accepted);
    assert_no_staged_files(&result.run_dir);
}

#[cfg(unix)]
#[test]
fn subprocess_crash_before_hil_commit_receipt_helper() {
    let Some(artifact_root) = std::env::var_os("NETDIAG_TEST_HIL_ARTIFACT_ROOT") else {
        return;
    };
    let run_id = std::env::var("NETDIAG_TEST_HIL_RUN_ID").expect("test run id");
    let run_dir = PathBuf::from(&artifact_root).join("runs").join(&run_id);
    let recommendations = read_recommendations(&run_dir).expect("recommendations");
    let recommendation = recommendations.first().expect("recommendation");
    let result = review_recommendation(
        PathBuf::from(artifact_root),
        &run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "crash recovery review",
        "crash-test-reviewer",
        recommendation.diagnosis_symptom,
    );
    panic!("HIL crash failpoint did not terminate the helper: {result:?}");
}

#[cfg(unix)]
fn spawn_commit_receipt_crash_helper(
    artifact_root: &Path,
    run_id: &str,
) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "hil_review::tests::subprocess_crash_before_hil_commit_receipt_helper",
            "--nocapture",
        ])
        .env("NETDIAG_TEST_HIL_ARTIFACT_ROOT", artifact_root)
        .env("NETDIAG_TEST_HIL_RUN_ID", run_id)
        .env("NETDIAG_TEST_HIL_CRASH_POINT", "before_commit_receipt")
        .status()
        .expect("HIL crash helper process")
}

#[test]
fn recovery_rejects_target_changed_outside_transaction() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    fail_before_publishing("report");
    review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Rejected,
        "rejected",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("injected failure");

    let manifest_path = result.run_dir.join("manifest.json");
    let mut manifest = read_json(&manifest_path).expect("manifest JSON");
    manifest["external_change"] = json!(true);
    save_json_atomic(&manifest_path, &manifest).expect("external write");

    let error = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Rejected,
        "rejected",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("conflicting recovery must fail");

    assert!(error.to_string().contains("HIL transaction conflict"));
    assert_eq!(
        read_json(&manifest_path).expect("preserved external manifest")["external_change"],
        true
    );
    assert_eq!(
        load_journal(&result.run_dir, &result.run_id)
            .expect("journal")
            .expect("pending")
            .phase,
        JournalPhase::Committing
    );
}

#[cfg(unix)]
#[test]
fn recovery_rejects_staged_file_replaced_with_symlink() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    fail_before_publishing("report");
    review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("injected failure");

    let pending = load_journal(&result.run_dir, &result.run_id)
        .expect("journal")
        .expect("pending journal");
    let staged = result.run_dir.join(format!(
        ".report.json.hil-{}-report.stage",
        pending.transaction_id
    ));
    let report_path = result.run_dir.join("report.json");
    fs::remove_file(&staged).expect("remove staged report");
    symlink(&report_path, &staged).expect("replace stage with symlink");

    let error = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("a symlinked stage must fail closed");

    assert!(
        error.to_string().contains("symlink/reparse point"),
        "{error}"
    );
    assert_eq!(
        load_journal(&result.run_dir, &result.run_id)
            .expect("journal")
            .expect("pending")
            .phase,
        JournalPhase::Committing
    );
}

#[test]
fn committed_retry_verifies_targets_before_returning_success() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect("initial review");

    let report_path = result.run_dir.join("report.json");
    let mut report = read_json(&report_path).expect("report JSON");
    report["external_change"] = json!(true);
    save_json_atomic(&report_path, &report).expect("external write");

    let error = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("committed receipt must not mask target tampering");
    assert!(error.to_string().contains("HIL transaction conflict"));
    assert_eq!(
        read_json(&report_path).expect("preserved report")["external_change"],
        true
    );
}

#[test]
fn journal_rejects_uppercase_new_and_preimage_hashes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    fail_before_publishing("report");
    review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("injected failure");
    let path = journal_path(&result.run_dir);
    let original = read_json(&path).expect("journal JSON");

    let mut uppercase_new = original.clone();
    let new_hash = uppercase_new["targets"][0]["new_sha256"]
        .as_str()
        .expect("new hash")
        .to_ascii_uppercase();
    uppercase_new["targets"][0]["new_sha256"] = json!(new_hash);
    save_json_atomic(&path, &uppercase_new).expect("uppercase new hash journal");
    let error =
        load_journal(&result.run_dir, &result.run_id).expect_err("uppercase new hash must fail");
    assert!(
        error
            .to_string()
            .contains("invalid HIL transaction target hash")
    );

    let mut uppercase_old = original;
    let old_hash = uppercase_old["targets"][0]["expected_old_sha256"]
        .as_str()
        .expect("old hash")
        .to_ascii_uppercase();
    uppercase_old["targets"][0]["expected_old_sha256"] = json!(old_hash);
    save_json_atomic(&path, &uppercase_old).expect("uppercase old hash journal");
    let error = load_journal(&result.run_dir, &result.run_id)
        .expect_err("uppercase preimage hash must fail");
    assert!(
        error
            .to_string()
            .contains("invalid HIL transaction target hash")
    );
}

#[test]
fn preflight_rejects_missing_required_files_before_journal_creation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    let recommendations_before =
        fs::read(result.run_dir.join("recommendations.json")).expect("recommendations before");

    for (path, expected) in [
        (result.run_dir.join("report.json"), "report is missing"),
        (
            result.run_dir.join("manifest.json"),
            "run manifest is missing",
        ),
        (temp.path().join("run_index.json"), "run index is missing"),
    ] {
        let bytes = fs::read(&path).expect("required artifact");
        fs::remove_file(&path).expect("remove required artifact");
        let error = review_recommendation(
            temp.path(),
            &result.run_id,
            &recommendation.recommendation_id,
            HilState::Accepted,
            "confirmed",
            "reviewer",
            recommendation.diagnosis_symptom,
        )
        .expect_err("preflight must fail");
        assert!(error.to_string().contains(expected), "{error}");
        fs::write(&path, bytes).expect("restore required artifact");
        assert!(!journal_path(&result.run_dir).exists());
        assert_eq!(
            fs::read(result.run_dir.join("recommendations.json")).expect("recommendations after"),
            recommendations_before
        );
    }
}

#[test]
fn oversized_transaction_journal_fails_before_any_target_publication() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    let protected_paths = [
        result.run_dir.join("recommendations.json"),
        result.run_dir.join("report.json"),
        result.run_dir.join("manifest.json"),
        temp.path().join("run_index.json"),
    ];
    let protected_bytes = protected_paths
        .iter()
        .map(|path| fs::read(path).expect("protected target"))
        .collect::<Vec<_>>();
    let oversized_notes = "x".repeat((MAX_TRANSACTION_JSON_BYTES as usize / 2) + 1024);

    let error = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        &oversized_notes,
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("an unreadable transaction journal must not be published");

    assert!(
        error
            .to_string()
            .contains("serialized HIL transaction journal exceeds the 16777216-byte limit"),
        "{error}"
    );
    assert!(!journal_path(&result.run_dir).exists());
    assert!(!result.run_dir.join("hil_feedback.json").exists());
    assert_no_staged_files(&result.run_dir);
    for (path, expected) in protected_paths.iter().zip(protected_bytes) {
        assert_eq!(fs::read(path).expect("unchanged target"), expected);
    }
}

#[test]
fn concurrent_reviews_preserve_both_updates() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    assert!(result.recommendations.len() >= 2);
    let artifact_root = Arc::new(temp.path().to_path_buf());
    let run_id = Arc::new(result.run_id.clone());
    let barrier = Arc::new(Barrier::new(2));
    let handles = result
        .recommendations
        .iter()
        .take(2)
        .cloned()
        .enumerate()
        .map(|(index, recommendation)| {
            let artifact_root = Arc::clone(&artifact_root);
            let run_id = Arc::clone(&run_id);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                review_recommendation(
                    artifact_root.as_path(),
                    run_id.as_str(),
                    &recommendation.recommendation_id,
                    HilState::Accepted,
                    &format!("concurrent-{index}"),
                    "reviewer",
                    recommendation.diagnosis_symptom,
                )
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        handle
            .join()
            .expect("review thread")
            .expect("concurrent review");
    }

    let recommendations: Vec<Recommendation> = serde_json::from_value(
        read_json(result.run_dir.join("recommendations.json")).expect("recommendations"),
    )
    .expect("recommendations JSON");
    assert!(
        recommendations
            .iter()
            .take(2)
            .all(|recommendation| recommendation.hil_state == HilState::Accepted)
    );
    let manifest: RunManifest =
        serde_json::from_value(read_json(result.run_dir.join("manifest.json")).expect("manifest"))
            .expect("manifest JSON");
    assert!(manifest.artifact_paths.contains_key("hil_feedback"));
    assert_no_staged_files(&result.run_dir);
}

#[test]
fn legacy_write_feedback_is_rejected_without_creating_an_incompatible_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    let error = crate::storage::write_feedback(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "legacy review",
    )
    .expect_err("legacy feedback writer must fail closed");
    assert!(error.to_string().contains("use review_recommendation"));
    assert!(!result.run_dir.join("hil_feedback.json").exists());
}

#[test]
fn legacy_feedback_file_requires_explicit_migration() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    save_json_atomic(
        result.run_dir.join("hil_feedback.json"),
        &json!({
            recommendation.recommendation_id.clone(): {
                "state": "accepted",
                "notes": "legacy review"
            }
        }),
    )
    .expect("legacy feedback fixture");

    let error = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "replacement review",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("legacy feedback must not be silently migrated");
    assert!(error.to_string().contains("legacy HIL feedback schema"));
    assert!(error.to_string().contains("archive and remove"));
    assert!(!journal_path(&result.run_dir).exists());
}

#[test]
fn corrupt_lab_index_is_not_bypassed_by_direct_run_fallback() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = &result.recommendations[0];
    fs::remove_file(result.run_dir.join("manifest.json")).expect("remove manifest");
    fs::write(temp.path().join("lab_run_index.json"), b"{").expect("corrupt lab index fixture");

    let error = review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "review",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("corrupt index must fail closed");
    assert!(
        error.to_string().contains("invalid lab run index"),
        "{error}"
    );
    assert!(!journal_path(&result.run_dir).exists());
}

#[test]
fn review_waits_for_feedback_target_lock_before_reading_preimage() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = result.recommendations[0].clone();
    let artifact_root = temp.path().to_path_buf();
    let run_id = result.run_id.clone();
    let feedback_path = result.run_dir.join("hil_feedback.json");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    let handle = crate::storage::with_exclusive_file_lock(&feedback_path, || {
        let handle = std::thread::spawn(move || {
            started_tx.send(()).expect("started signal");
            let review = review_recommendation(
                &artifact_root,
                &run_id,
                &recommendation.recommendation_id,
                HilState::Accepted,
                "locked review",
                "reviewer",
                recommendation.diagnosis_symptom,
            );
            done_tx.send(()).expect("done signal");
            review
        });
        started_rx.recv().expect("review started");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(150)).is_err(),
            "review completed while its feedback target lock was held"
        );
        Ok(handle)
    })
    .expect("hold feedback lock");
    handle
        .join()
        .expect("review thread")
        .expect("review after lock release");
}

#[test]
fn unsupported_windows_replace_semantics_fail_closed() {
    let error = crate::storage::hil_transaction::reject_unsupported_durability_for_test()
        .expect_err("unsupported replace semantics must fail");
    assert!(error.to_string().contains("atomic overwrite rename"));
    assert!(error.to_string().contains("no transaction was started"));
}

fn assert_no_staged_files(run_dir: &Path) {
    let staged = fs::read_dir(run_dir)
        .expect("run directory")
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".stage"))
        .collect::<Vec<_>>();
    assert!(staged.is_empty(), "staged files leaked: {staged:?}");
}
