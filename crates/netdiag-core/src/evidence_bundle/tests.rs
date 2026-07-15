use super::export::{export_standard_with_observer, export_standard_with_snapshot_observers};
use super::stream::MAX_SOURCE_FILE_BYTES;
use super::{
    EvidenceBundleExtraFile, EvidenceContext, export_evidence_bundle,
    export_evidence_bundle_with_context,
};
use crate::models::{HilState, Recommendation};
use crate::pipeline::diagnose_file;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use zip::ZipArchive;

struct TestRun {
    root: TempDir,
    run_id: String,
    run_dir: PathBuf,
}

fn completed_run() -> TestRun {
    let root = tempfile::tempdir().expect("tempdir");
    let sample = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv");
    let result = diagnose_file(sample, root.path(), None).expect("diagnose sample");
    TestRun {
        root,
        run_id: result.run_id,
        run_dir: result.run_dir,
    }
}

#[cfg(unix)]
fn completed_run_with_what_if() -> TestRun {
    let root = tempfile::tempdir().expect("tempdir");
    let sample = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv");
    let result = diagnose_file(sample, root.path(), Some(("line", "reroute_path_b")))
        .expect("diagnose sample with what-if");
    TestRun {
        root,
        run_id: result.run_id,
        run_dir: result.run_dir,
    }
}

fn read_zip_entry(path: &Path, name: &str) -> Vec<u8> {
    let file = File::open(path).expect("zip file");
    let mut archive = ZipArchive::new(file).expect("zip archive");
    let mut entry = archive.by_name(name).expect("zip entry");
    let mut body = Vec::new();
    entry.read_to_end(&mut body).expect("read zip entry");
    body
}

fn extra(path: impl AsRef<Path>, zip_path: &str) -> EvidenceBundleExtraFile {
    EvidenceBundleExtraFile {
        key: "operator_note".to_string(),
        path: path.as_ref().to_path_buf(),
        zip_path: zip_path.to_string(),
    }
}

fn export_path(run: &TestRun, name: &str) -> PathBuf {
    run.root.path().join("exports").join(name)
}

#[test]
fn requested_zip_paths_reject_zip_slip_absolute_and_directory_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("note.txt");
    fs::write(&source, "note").expect("write note");
    for (index, zip_path) in [
        "../escape.txt",
        "/absolute.txt",
        r"C:\absolute.txt",
        "directory/",
        "directory/.",
        ".",
        "",
    ]
    .into_iter()
    .enumerate()
    {
        let output = temp.path().join(format!("invalid-{index}.zip"));
        let error = export_evidence_bundle(
            temp.path(),
            "unused-run-id",
            &output,
            &[extra(&source, zip_path)],
        )
        .expect_err("unsafe zip path must fail before run resolution");
        assert!(error.to_string().contains("normalized relative file"));
        assert!(!output.exists(), "invalid export must not publish output");
    }
}

#[test]
fn duplicate_normalized_zip_paths_are_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("note.txt");
    fs::write(&source, "note").expect("write note");
    let output = temp.path().join("duplicate.zip");
    let error = export_evidence_bundle(
        temp.path(),
        "unused-run-id",
        &output,
        &[
            extra(&source, "notes/./operator.txt"),
            extra(&source, r"NOTES\operator.txt"),
        ],
    )
    .expect_err("normalized duplicate must fail");
    assert!(error.to_string().contains("duplicate normalized"));
    assert!(!output.exists());
}

#[test]
fn missing_requested_extra_is_an_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = temp.path().join("missing.zip");
    let error = export_evidence_bundle(
        temp.path(),
        "unused-run-id",
        &output,
        &[extra(temp.path().join("missing.txt"), "missing.txt")],
    )
    .expect_err("requested missing extra must fail");
    assert!(error.to_string().contains("source does not exist"));
    assert!(!output.exists());
}

#[test]
fn missing_manifest_declared_artifact_aborts_atomic_export() {
    let run = completed_run();
    let declared_artifact = run.run_dir.join("telemetry_summary.json");
    fs::remove_file(&declared_artifact).expect("remove declared artifact");
    let output = export_path(&run, "missing-declared-artifact.zip");

    let error = export_evidence_bundle(run.root.path(), &run.run_id, &output, &[])
        .expect_err("a missing manifest-declared artifact must fail closed");

    assert!(
        error.to_string().contains("source does not exist"),
        "unexpected error: {error}"
    );
    assert!(!output.exists(), "failed export must not publish a bundle");
}

#[test]
fn snapshot_capture_failure_explicitly_removes_its_store() {
    let run = completed_run();
    fs::remove_file(run.run_dir.join("telemetry_summary.json")).expect("remove declared artifact");
    let output = export_path(&run, "capture-failure.zip");
    let mut store_path = None;

    let error = export_standard_with_snapshot_observers(
        run.root.path(),
        &run.run_id,
        &output,
        EvidenceContext::Plain,
        &[],
        |path| store_path = Some(path.to_path_buf()),
        |_| {},
    )
    .expect_err("capture must fail for a missing declared artifact");

    assert!(
        error.to_string().contains("source does not exist"),
        "{error}"
    );
    assert!(
        !store_path.expect("snapshot store path").exists(),
        "mid-capture failure must explicitly remove the snapshot store"
    );
}

#[test]
fn successful_export_explicitly_removes_its_snapshot_store() {
    let run = completed_run();
    let output = export_path(&run, "explicit-cleanup.zip");
    let mut store_path = None;

    export_standard_with_snapshot_observers(
        run.root.path(),
        &run.run_id,
        &output,
        EvidenceContext::Plain,
        &[],
        |_| {},
        |path| store_path = Some(path.to_path_buf()),
    )
    .expect("evidence export");

    assert!(output.is_file());
    assert!(
        !store_path.expect("snapshot store path").exists(),
        "successful export must explicitly remove the snapshot store"
    );
}

#[cfg(unix)]
fn truncate_first_snapshot(store: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let snapshot = fs::read_dir(store)
        .expect("snapshot directory")
        .map(|entry| entry.expect("snapshot entry").path())
        .find(|path| path.is_file())
        .expect("captured snapshot");
    fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o600))
        .expect("make snapshot writable");
    File::create(snapshot).expect("truncate snapshot");
}

#[cfg(unix)]
#[test]
fn failed_export_explicitly_removes_its_snapshot_store() {
    let run = completed_run();
    let output = export_path(&run, "archive-failure.zip");
    let mut store_path = None;

    let error = export_standard_with_snapshot_observers(
        run.root.path(),
        &run.run_id,
        &output,
        EvidenceContext::Plain,
        &[],
        |_| {},
        |path| {
            store_path = Some(path.to_path_buf());
            truncate_first_snapshot(path);
        },
    )
    .expect_err("mutated snapshot must fail archive verification");

    assert!(error.to_string().contains("snapshot changed"), "{error}");
    assert!(
        !store_path.expect("snapshot store path").exists(),
        "failed export must explicitly remove the snapshot store"
    );
}

#[cfg(unix)]
#[test]
fn failed_export_preserves_operation_and_snapshot_cleanup_failures() {
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt;

    let run = completed_run();
    let output = export_path(&run, "archive-cleanup-failure.zip");
    let mut store_path = None;
    let mut displaced_path = None;
    let error = export_standard_with_snapshot_observers(
        run.root.path(),
        &run.run_id,
        &output,
        EvidenceContext::Plain,
        &[],
        |_| {},
        |path| {
            store_path = Some(path.to_path_buf());
            truncate_first_snapshot(path);
            let displaced = path.with_extension("displaced");
            displaced_path = Some(displaced.clone());
            fs::rename(path, &displaced).expect("displace snapshot store");
            fs::create_dir(path).expect("replacement snapshot store");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("replacement mode");
        },
    )
    .expect_err("archive and cleanup failures must both remain observable");
    let store_path = store_path.expect("snapshot store path");
    fs::remove_dir_all(&store_path).expect("remove replacement snapshot fixture");
    fs::remove_dir_all(displaced_path.expect("displaced snapshot path"))
        .expect("remove displaced snapshot fixture");

    let (operation, cleanup) = match &error {
        crate::error::NetdiagError::TrustedTemporaryDirectoryOperationAndCleanup {
            operation,
            cleanup,
            ..
        } => (operation, cleanup),
        other => panic!("expected structured export and cleanup failure: {other}"),
    };
    assert!(operation.to_string().contains("snapshot changed"));
    assert!(matches!(
        cleanup,
        netdiag_platform::TrustedTempDirectoryError::CleanupSkipped { .. }
    ));
    assert_eq!(
        error.source().expect("operation source").to_string(),
        operation.to_string()
    );
}

#[test]
fn oversized_requested_extra_fails_before_reading_or_publishing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("oversized.bin");
    let file = File::create(&source).expect("create sparse source");
    file.set_len(MAX_SOURCE_FILE_BYTES + 1)
        .expect("set sparse source length");
    let output = temp.path().join("oversized.zip");
    let error = export_evidence_bundle(
        temp.path(),
        "unused-run-id",
        &output,
        &[extra(&source, "oversized.bin")],
    )
    .expect_err("oversized source must fail");
    assert!(error.to_string().contains("single source file byte limit"));
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn internal_artifact_symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    let run = completed_run();
    let outside = run.root.path().join("outside-telemetry.json");
    fs::write(&outside, "{}").expect("outside source");
    let artifact = run.run_dir.join("telemetry_summary.json");
    fs::remove_file(&artifact).expect("remove original artifact");
    symlink(&outside, &artifact).expect("create escaping symlink");
    let output = export_path(&run, "escape.zip");
    let error = export_evidence_bundle(run.root.path(), &run.run_id, &output, &[])
        .expect_err("artifact symlink escape must fail");
    assert!(
        error
            .to_string()
            .contains("manifest artifact path resolves outside the run directory"),
        "{error}"
    );
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn lab_required_symlink_source_is_rejected() {
    use std::os::unix::fs::symlink;

    let run = completed_run();
    let outside_root = tempfile::tempdir().expect("outside tempdir");
    let outside = outside_root.path().join("scenario.yaml");
    fs::write(&outside, "id: outside").expect("outside scenario");
    symlink(&outside, run.root.path().join("scenario.yaml")).expect("scenario symlink");
    let output = export_path(&run, "default-extra-escape.zip");
    let error = export_evidence_bundle_with_context(
        run.root.path(),
        &run.run_id,
        &output,
        EvidenceContext::Lab,
        &[],
    )
    .expect_err("lab required symlink source must fail");
    assert!(error.to_string().contains("non-reparse regular file"));
    assert!(!output.exists());
}

#[test]
fn required_report_duplicate_keys_fail_safely_and_output_is_atomic() {
    let run = completed_run();
    fs::write(
        run.run_dir.join("report.json"),
        br#"{"private-field":"private-value","private-field":"second-private-value"}"#,
    )
    .expect("duplicate-key report");
    let output = export_path(&run, "corrupt-report.zip");
    let error = export_evidence_bundle(run.root.path(), &run.run_id, &output, &[])
        .expect_err("corrupt required report must fail");
    let message = error.to_string();
    assert!(
        message.contains("evidence report snapshot is invalid")
            && message.contains("contains a duplicate key"),
        "{message}"
    );
    for private_input in ["private-field", "private-value", "second-private-value"] {
        assert!(!message.contains(private_input), "{message}");
    }
    assert!(!output.exists());
}

#[test]
fn legal_requested_extra_is_streamed_with_normalized_path_and_hash() {
    let run = completed_run();
    let source = run.root.path().join("operator-note.txt");
    fs::write(&source, "review note").expect("operator note");
    let output = export_path(&run, "legal-extra.zip");
    let manifest = export_evidence_bundle(
        run.root.path(),
        &run.run_id,
        &output,
        &[extra(&source, "notes/./operator-note.txt")],
    )
    .expect("valid evidence export");
    let entry = manifest
        .files
        .iter()
        .find(|entry| entry.key == "operator_note")
        .expect("operator note manifest entry");
    assert_eq!(entry.zip_path, "notes/operator-note.txt");
    assert_eq!(entry.bytes, 11);
    assert_eq!(
        entry.sha256,
        "a857e67b849628529430b0e4d2ccdcb0a9dc07e4bc1071310af12289122a1a7a"
    );
    assert!(output.is_file());
}

#[test]
fn lab_context_fails_closed_when_any_required_artifact_is_missing() {
    const REQUIRED: &[(&str, &[u8])] = &[
        (
            "scenario.yaml",
            b"schema: netdiag-lab/v1\nid: evidence-test\n",
        ),
        ("acceptance.json", b"{}"),
        ("comparison.json", b"{}"),
        ("multi_source_evidence.json", b"{}"),
        ("connector_health.json", b"[]"),
    ];

    for (missing, _) in REQUIRED {
        let run = completed_run();
        for (name, body) in REQUIRED {
            if name != missing {
                fs::write(run.root.path().join(name), body).expect("required lab artifact");
            }
        }
        let output = export_path(&run, &format!("missing-{missing}.zip"));
        let error = export_evidence_bundle_with_context(
            run.root.path(),
            &run.run_id,
            &output,
            EvidenceContext::Lab,
            &[],
        )
        .expect_err("missing lab context artifact must fail closed");
        assert!(
            error.to_string().contains("source does not exist"),
            "{error}"
        );
        assert!(!output.exists(), "failed lab export published a bundle");
    }
}

#[cfg(unix)]
#[test]
fn report_archive_and_topology_use_one_snapshot_across_atomic_source_replacement() {
    let run = completed_run_with_what_if();
    let report_path = run.run_dir.join("report.json");
    let original_report = fs::read(&report_path).expect("original report");
    let mut replacement: serde_json::Value =
        serde_json::from_slice(&original_report).expect("report json");
    replacement["what_if"] = serde_json::Value::Null;
    let replacement_path = run.run_dir.join("report.replacement.json");
    fs::write(
        &replacement_path,
        serde_json::to_vec_pretty(&replacement).expect("replacement json"),
    )
    .expect("replacement report");
    let output = export_path(&run, "consistent-snapshot.zip");

    export_standard_with_observer(
        run.root.path(),
        &run.run_id,
        &output,
        EvidenceContext::Plain,
        &[],
        || fs::rename(&replacement_path, &report_path).expect("atomic report replacement"),
    )
    .expect("snapshot-backed export");

    assert_eq!(read_zip_entry(&output, "report.json"), original_report);
    assert!(
        !read_zip_entry(&output, "topology.json").is_empty(),
        "topology must come from the same pre-replacement report snapshot"
    );
}

#[test]
fn protected_run_and_transaction_files_cannot_be_evidence_outputs() {
    let run = completed_run();
    let report_alias = run.run_dir.join("unused").join("..").join("report.json");
    let protected = [
        run.run_dir.join("report.json"),
        report_alias,
        run.run_dir.join("manifest.json"),
        run.run_dir.join("hil_review_transaction.json"),
        run.run_dir.join("action_verification_transaction.json"),
        run.root.path().join("run_index.json"),
    ];
    for output in protected {
        let before = fs::read(&output).ok();
        let error = export_evidence_bundle(run.root.path(), &run.run_id, &output, &[])
            .expect_err("protected run state must not be overwritten by an export");
        assert!(error.to_string().contains("protected run input"), "{error}");
        assert_eq!(fs::read(&output).ok(), before, "{}", output.display());
    }
}

#[test]
fn any_output_in_a_protected_transaction_directory_is_rejected() {
    let run = completed_run();
    let output = run.run_dir.join("REPORT.JSON");
    let report_before = fs::read(run.run_dir.join("report.json")).expect("report before");

    let error = export_evidence_bundle(run.root.path(), &run.run_id, &output, &[])
        .expect_err("filesystem leaf aliases must not bypass protected output checks");

    assert!(error.to_string().contains("protected run input"), "{error}");
    assert_eq!(
        fs::read(run.run_dir.join("report.json")).expect("report after"),
        report_before
    );
}

#[test]
fn protected_coordination_locks_cannot_be_evidence_outputs() {
    let run = completed_run();
    for target in [
        run.run_dir.join("report.json"),
        run.run_dir.join("manifest.json"),
        run.run_dir.join("hil_review_transaction.json"),
        run.run_dir.join("action_verification_transaction.json"),
    ] {
        crate::storage::with_exclusive_file_lock(&target, || Ok(()))
            .expect("create coordination lock");
        let lock_path =
            crate::storage::exclusive_file_lock_path(&target).expect("coordination lock path");
        let original_target = fs::read(&target).ok();
        let original_lock_bytes = fs::read(&lock_path).expect("coordination lock bytes");
        let original_lock =
            crate::file_identity::open_file(&lock_path).expect("coordination lock identity handle");

        let error = export_evidence_bundle(run.root.path(), &run.run_id, &lock_path, &[])
            .expect_err("coordination lock must not be replaced by evidence output");

        assert!(error.to_string().contains("coordination lock"), "{error}");
        assert_eq!(fs::read(&target).ok(), original_target);
        assert_eq!(
            fs::read(&lock_path).expect("preserved coordination lock"),
            original_lock_bytes
        );
        let current_lock = crate::file_identity::open_file(&lock_path)
            .expect("preserved coordination lock identity handle");
        assert!(
            crate::file_identity::same_file(&original_lock, &current_lock, &lock_path)
                .expect("compare coordination lock identity")
        );
    }
}

#[test]
fn rejected_lock_replacement_leaves_hil_waiting_on_the_original_lock() {
    let run = completed_run();
    let report_path = run.run_dir.join("report.json");
    let report_lock =
        crate::storage::exclusive_file_lock_path(&report_path).expect("coordination lock path");
    let recommendations: Vec<Recommendation> = serde_json::from_slice(
        &fs::read(run.run_dir.join("recommendations.json")).expect("recommendations"),
    )
    .expect("recommendations JSON");
    let recommendation = recommendations
        .first()
        .expect("diagnosis recommendation")
        .clone();

    let holder_report = report_path.clone();
    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let holder = thread::spawn(move || {
        crate::storage::with_exclusive_file_lock(&holder_report, || {
            held_tx.send(()).expect("signal held report lock");
            release_rx.recv().expect("release report lock");
            Ok(())
        })
    });
    held_rx.recv().expect("report lock holder started");
    let original_lock =
        crate::file_identity::open_file(&report_lock).expect("original report lock identity");

    let attack_root = run.root.path().to_path_buf();
    let attack_run_id = run.run_id.clone();
    let attack_output = report_lock.clone();
    let (attack_tx, attack_rx) = mpsc::channel();
    let attacker = thread::spawn(move || {
        attack_tx
            .send(export_evidence_bundle(
                &attack_root,
                &attack_run_id,
                &attack_output,
                &[],
            ))
            .expect("send attack result");
    });
    let attack_result = match attack_rx.recv_timeout(Duration::from_secs(1)) {
        Ok(result) => result,
        Err(error) => {
            release_tx.send(()).expect("release after attack timeout");
            holder.join().expect("holder thread").expect("holder lock");
            attacker.join().expect("attacker thread");
            panic!("lock replacement attack did not fail promptly: {error}");
        }
    };
    attacker.join().expect("attacker thread");
    let attack_error = attack_result.expect_err("lock replacement attack must fail closed");
    assert!(
        attack_error.to_string().contains("coordination lock"),
        "{attack_error}"
    );
    assert!(
        crate::file_identity::same_file(
            &original_lock,
            &crate::file_identity::open_file(&report_lock).expect("unchanged report lock"),
            &report_lock
        )
        .expect("compare unchanged report lock")
    );

    let review_root = run.root.path().to_path_buf();
    let review_run_id = run.run_id.clone();
    let (review_started_tx, review_started_rx) = mpsc::channel();
    let (review_tx, review_rx) = mpsc::channel();
    let reviewer = thread::spawn(move || {
        review_started_tx.send(()).expect("signal review start");
        let result = crate::hil_review::review_recommendation(
            &review_root,
            &review_run_id,
            &recommendation.recommendation_id,
            HilState::Accepted,
            "lock identity preserved",
            "reviewer",
            recommendation.diagnosis_symptom,
        );
        review_tx.send(result).expect("send review result");
    });
    review_started_rx.recv().expect("review thread started");
    let early_review = review_rx.recv_timeout(Duration::from_millis(100));
    let review_was_blocked = matches!(&early_review, Err(mpsc::RecvTimeoutError::Timeout));

    release_tx.send(()).expect("release original report lock");
    holder.join().expect("holder thread").expect("holder lock");
    let review_result = match early_review {
        Err(mpsc::RecvTimeoutError::Timeout) => review_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("review completes after original lock release"),
        Ok(result) => result,
        Err(error) => panic!("review result channel failed: {error}"),
    };
    reviewer.join().expect("reviewer thread");

    assert!(
        review_was_blocked,
        "HIL must remain blocked on the original report lock"
    );
    review_result.expect("review succeeds after lock release");
    assert!(
        crate::file_identity::same_file(
            &original_lock,
            &crate::file_identity::open_file(&report_lock).expect("same report lock after HIL"),
            &report_lock
        )
        .expect("compare report lock after HIL")
    );
}

#[test]
fn lab_archive_target_is_allowed_but_lab_inputs_are_protected() {
    let run = completed_run();
    for (name, body) in [
        (
            "scenario.yaml",
            b"schema: netdiag-lab/v1\nid: evidence-lock-test\n".as_slice(),
        ),
        ("acceptance.json", b"{}".as_slice()),
        ("comparison.json", b"{}".as_slice()),
        ("multi_source_evidence.json", b"{}".as_slice()),
        ("connector_health.json", b"[]".as_slice()),
    ] {
        fs::write(run.root.path().join(name), body).expect("lab input");
    }

    let acceptance = run.root.path().join("acceptance.json");
    let error = export_evidence_bundle_with_context(
        run.root.path(),
        &run.run_id,
        &acceptance,
        EvidenceContext::Lab,
        &[],
    )
    .expect_err("lab input must not be overwritten by an export");
    assert!(error.to_string().contains("protected run input"), "{error}");
    assert_eq!(fs::read(&acceptance).expect("acceptance preserved"), b"{}");

    let archive = run
        .root
        .path()
        .join(format!("netdiag-evidence-{}.zip", run.run_id));
    export_evidence_bundle_with_context(
        run.root.path(),
        &run.run_id,
        &archive,
        EvidenceContext::Lab,
        &[],
    )
    .expect("canonical lab archive target remains supported");
    assert!(archive.is_file());
}

#[test]
fn export_waits_for_transaction_targets_and_captures_one_generation() {
    let run = completed_run();
    let report_path = run.run_dir.join("report.json");
    let recommendations_path = run.run_dir.join("recommendations.json");
    let mut next_report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report")).expect("report JSON");
    next_report["snapshot_generation"] = serde_json::json!("next");
    let mut next_recommendations: serde_json::Value =
        serde_json::from_slice(&fs::read(&recommendations_path).expect("recommendations"))
            .expect("recommendations JSON");
    next_recommendations[0]["snapshot_generation"] = serde_json::json!("next");

    let location =
        crate::storage::resolve_run_location(run.root.path(), &run.run_id).expect("run location");
    let writer_run_id = run.run_id.clone();
    let writer_report_path = report_path.clone();
    let writer_recommendations_path = recommendations_path.clone();
    let (halfway_tx, halfway_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        crate::storage::with_transaction_target_locks(&location, &writer_run_id, || {
            crate::storage::save_json_atomic(&writer_report_path, &next_report)?;
            halfway_tx.send(()).expect("signal half-written generation");
            finish_rx.recv().expect("finish transaction signal");
            crate::storage::save_json_atomic(&writer_recommendations_path, &next_recommendations)?;
            Ok(())
        })
    });
    halfway_rx
        .recv()
        .expect("writer must hold all transaction target locks");

    let export_root = run.root.path().to_path_buf();
    let export_run_id = run.run_id.clone();
    let output = export_path(&run, "transaction-consistent.zip");
    let export_output = output.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (snapshots_tx, snapshots_rx) = mpsc::channel();
    let exporter = thread::spawn(move || {
        started_tx.send(()).expect("signal export attempt");
        export_standard_with_observer(
            &export_root,
            &export_run_id,
            &export_output,
            EvidenceContext::Plain,
            &[],
            || snapshots_tx.send(()).expect("signal captured snapshots"),
        )
    });
    started_rx.recv().expect("export thread started");
    assert!(
        matches!(
            snapshots_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ),
        "export must not snapshot a half-published transaction generation"
    );

    finish_tx
        .send(())
        .expect("allow writer to commit generation");
    writer
        .join()
        .expect("writer thread")
        .expect("transaction-like write");
    exporter
        .join()
        .expect("export thread")
        .expect("evidence export");
    snapshots_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("export snapshots after transaction locks are released");

    let archived_report: serde_json::Value =
        serde_json::from_slice(&read_zip_entry(&output, "report.json")).expect("archived report");
    let archived_recommendations: serde_json::Value =
        serde_json::from_slice(&read_zip_entry(&output, "recommendations.json"))
            .expect("archived recommendations");
    assert_eq!(archived_report["snapshot_generation"], "next");
    assert_eq!(archived_recommendations[0]["snapshot_generation"], "next");
}
