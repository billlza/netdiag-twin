use super::publication::checked_serialized_size;
use super::*;
use crate::models::{FaultLabel, HilFeedbackRecord, MlResult};
use crate::pipeline::diagnose_file;
use crate::report::Report;
use crate::storage::{
    read_json, resolve_run_location, save_json_atomic, with_transaction_target_locks,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

struct ReviewedRun {
    run_id: String,
    run_dir: PathBuf,
}

fn sample() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("data/samples/congestion.csv")
}

fn diagnose(root: &Path) -> crate::pipeline::PipelineResult {
    diagnose_file(sample(), root, Some(("line", "reroute_path_b"))).expect("diagnose fixture")
}

fn reviewed_run(root: &Path) -> ReviewedRun {
    let result = diagnose(root);
    let recommendation = result
        .recommendations
        .iter()
        .find(|item| item.diagnosis_symptom.is_some())
        .expect("diagnosis recommendation");
    crate::hil_review::review_recommendation(
        root,
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "original generation",
        "feedback-export-test",
        recommendation.diagnosis_symptom,
    )
    .expect("review recommendation");
    ReviewedRun {
        run_id: result.run_id,
        run_dir: result.run_dir,
    }
}

fn feedback(path: &Path) -> BTreeMap<String, HilFeedbackRecord> {
    serde_json::from_value(read_json(path).expect("feedback JSON")).expect("typed feedback")
}

fn read_export_row(path: &Path) -> FeedbackTrainingRow {
    let line = fs::read_to_string(path).expect("exported dataset");
    serde_json::from_str(line.trim()).expect("training row")
}

#[test]
fn export_waits_for_transaction_locks_and_reads_one_generation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let reviewed = reviewed_run(temp.path());
    let location = resolve_run_location(temp.path(), &reviewed.run_id).expect("run location");
    let output = temp.path().join("feedback.jsonl");
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();

    let exporter = with_transaction_target_locks(&location, &reviewed.run_id, || {
        let root = temp.path().to_path_buf();
        let output_for_thread = output.clone();
        let handle = std::thread::spawn(move || {
            started_tx.send(()).expect("started signal");
            let result = export_feedback_training_dataset(root, output_for_thread);
            done_tx.send(()).expect("done signal");
            result
        });
        started_rx.recv().expect("exporter started");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(150)).is_err(),
            "export must wait while the HIL transaction target locks are held"
        );

        let report_path = reviewed.run_dir.join("report.json");
        let mut report: Report =
            serde_json::from_value(read_json(&report_path)?).expect("typed report");
        report.rule_vs_ml.rule_labels = vec!["locked-generation".to_string()];
        save_json_atomic(&report_path, &report)?;
        let feedback_path = reviewed.run_dir.join("hil_feedback.json");
        let mut records = feedback(&feedback_path);
        records
            .values_mut()
            .next()
            .expect("feedback record")
            .review
            .notes = "locked generation".to_string();
        save_json_atomic(&feedback_path, &records)?;
        Result::Ok(handle)
    })
    .expect("locked writer");

    let summary = exporter
        .join()
        .expect("exporter thread")
        .expect("feedback export");
    done_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("export completed after lock release");
    assert_eq!(summary.rows, 1);
    let row = read_export_row(&output);
    assert_eq!(row.rule_labels, ["locked-generation"]);
    assert_eq!(row.feedback_notes, "locked generation");
}

#[test]
fn export_rejects_pending_hil_transaction() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = diagnose(temp.path());
    let recommendation = result
        .recommendations
        .iter()
        .find(|item| item.diagnosis_symptom.is_some())
        .expect("diagnosis recommendation");
    crate::hil_review::fail_before_publishing("report");
    crate::hil_review::review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "pending review",
        "feedback-export-test",
        recommendation.diagnosis_symptom,
    )
    .expect_err("injected transaction failure");

    let error =
        export_feedback_training_dataset(temp.path(), temp.path().join("pending-feedback.jsonl"))
            .expect_err("pending transaction must fail closed");
    assert!(
        error.to_string().contains("pending HIL transaction"),
        "{error}"
    );
}

#[test]
fn export_skips_only_when_a_required_input_is_missing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let reviewed = reviewed_run(temp.path());
    fs::remove_file(reviewed.run_dir.join("hil_feedback.json")).expect("remove feedback");
    let output = temp.path().join("missing-feedback.jsonl");

    let summary =
        export_feedback_training_dataset(temp.path(), &output).expect("missing input is skipped");
    assert_eq!(summary.rows, 0);
    assert_eq!(summary.skipped_runs, 1);
    assert_eq!(fs::read_to_string(output).expect("empty dataset"), "");
}

#[test]
fn export_rejects_corrupt_feedback_instead_of_skipping_it() {
    let temp = tempfile::tempdir().expect("tempdir");
    let reviewed = reviewed_run(temp.path());
    let feedback_path = reviewed.run_dir.join("hil_feedback.json");
    fs::write(&feedback_path, b"{private-feedback-sentinel}").expect("corrupt feedback");
    let output = temp.path().join("corrupt.jsonl");

    let error = export_feedback_training_dataset(temp.path(), &output)
        .expect_err("corrupt feedback must fail");
    let message = error.to_string();
    assert!(
        message.contains("not syntactically valid JSON"),
        "{message}"
    );
    assert!(!message.contains("private-feedback-sentinel"), "{message}");
    assert!(message.contains("hil_feedback.json"), "{message}");
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn export_rejects_symlinked_snapshot_input() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let reviewed = reviewed_run(temp.path());
    let ml_path = reviewed.run_dir.join("ml_result.json");
    let target = temp.path().join("ml-target.json");
    fs::copy(&ml_path, &target).expect("copy ML result");
    fs::remove_file(&ml_path).expect("remove ML result");
    symlink(&target, &ml_path).expect("symlink ML result");

    let error = export_feedback_training_dataset(temp.path(), temp.path().join("symlink.jsonl"))
        .expect_err("symlinked input must fail");
    assert!(
        error.to_string().contains("regular, non-symlink"),
        "{error}"
    );
}

#[test]
fn export_rejects_cross_file_run_id_mismatch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let reviewed = reviewed_run(temp.path());
    let ml_path = reviewed.run_dir.join("ml_result.json");
    let mut ml: MlResult =
        serde_json::from_value(read_json(&ml_path).expect("ML JSON")).expect("typed ML result");
    ml.run_id = "different-run".to_string();
    save_json_atomic(&ml_path, &ml).expect("mismatched ML result");

    let error = export_feedback_training_dataset(temp.path(), temp.path().join("mismatch.jsonl"))
        .expect_err("mixed run ids must fail");
    assert!(error.to_string().contains("ML result run id"), "{error}");
}

#[test]
fn export_rejects_feedback_key_and_recommendation_contract_mismatch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let reviewed = reviewed_run(temp.path());
    let feedback_path = reviewed.run_dir.join("hil_feedback.json");
    let mut records = feedback(&feedback_path);
    let (_, mut record) = records.pop_first().expect("feedback record");
    records.insert("not-the-record-id".to_string(), record.clone());
    save_json_atomic(&feedback_path, &records).expect("mismatched feedback");

    let error = export_feedback_training_dataset(temp.path(), temp.path().join("bad-key.jsonl"))
        .expect_err("feedback key mismatch must fail");
    assert!(error.to_string().contains("feedback key"), "{error}");

    record.recommendation_id = "unknown-recommendation".to_string();
    records.clear();
    records.insert(record.recommendation_id.clone(), record);
    save_json_atomic(&feedback_path, &records).expect("unknown recommendation feedback");
    let error = export_feedback_training_dataset(
        temp.path(),
        temp.path().join("unknown-recommendation.jsonl"),
    )
    .expect_err("unknown feedback recommendation must fail");
    assert!(error.to_string().contains("absent from report"), "{error}");
}

#[test]
fn export_limits_runs_rows_and_retained_dataset_bytes() {
    let run_error = ensure_collection_limit(
        "feedback export run locations",
        MAX_FEEDBACK_EXPORT_RUNS + 1,
        MAX_FEEDBACK_EXPORT_RUNS,
    )
    .expect_err("run limit");
    assert!(run_error.to_string().contains("exceeding"), "{run_error}");
    let row_error = ensure_collection_limit(
        "feedback export rows",
        MAX_FEEDBACK_EXPORT_ROWS + 1,
        MAX_FEEDBACK_EXPORT_ROWS,
    )
    .expect_err("row limit");
    assert!(row_error.to_string().contains("exceeding"), "{row_error}");
    let row = FeedbackTrainingRow {
        label: FaultLabel::Normal,
        final_label: FaultLabel::Normal,
        run_id: "run-limit".to_string(),
        source: "hil_accepted".to_string(),
        features: BTreeMap::new(),
        rule_labels: Vec::new(),
        ml_top: "normal".to_string(),
        ml_top_prob: 1.0,
        recommendation_id: "rec-limit".to_string(),
        feedback_state: HilState::Accepted,
        feedback_notes: String::new(),
        reviewer: "tester".to_string(),
    };
    let size_error =
        checked_serialized_size(MAX_FEEDBACK_EXPORT_BYTES, &row).expect_err("dataset byte limit");
    assert!(
        size_error.to_string().contains("safety limit"),
        "{size_error}"
    );
}

#[test]
fn zero_run_export_cannot_replace_the_artifact_run_index() {
    let temp = tempfile::tempdir().expect("tempdir");
    let index_path = temp.path().join("run_index.json");
    let original = b"[]\n";
    fs::write(&index_path, original).expect("empty run index");

    let error = export_feedback_training_dataset(temp.path(), &index_path)
        .expect_err("feedback output must not overlap the run index");

    assert!(error.to_string().contains("protected run input"), "{error}");
    assert_eq!(
        fs::read(&index_path).expect("preserved run index"),
        original
    );
}
