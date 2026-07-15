use super::*;
use crate::models::{RunManifest, percent_delta};
use serde_json::json;
use std::sync::{Arc, Barrier};

#[test]
fn percent_delta_is_stable_and_rejects_unrepresentable_results() {
    let normal = percent_delta(100.0, 110.0)
        .expect("normal delta")
        .expect("defined delta");
    assert!((normal - 10.0).abs() < 1e-12, "{normal}");
    assert_eq!(
        percent_delta(-f64::MAX, f64::MAX).expect("stable extreme delta"),
        Some(200.0)
    );
    assert_eq!(percent_delta(0.0, 1.0).expect("zero baseline"), None);

    let overflow =
        percent_delta(f64::EPSILON, f64::MAX).expect_err("unrepresentable percentage must fail");
    assert!(overflow.to_string().contains("finite range"), "{overflow}");

    let non_finite = percent_delta(f64::NAN, 1.0).expect_err("NaN input must fail");
    assert!(
        non_finite.to_string().contains("must be finite"),
        "{non_finite}"
    );
}

#[test]
fn concurrent_atomic_writes_use_independent_temporary_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = Arc::new(temp.path().join("shared.json"));
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|writer| {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for sequence in 0..25 {
                    save_json_atomic(
                        path.as_ref(),
                        &json!({"writer": writer, "sequence": sequence}),
                    )?;
                }
                Result::<()>::Ok(())
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().expect("writer thread").expect("atomic write");
    }

    let value = read_json(path.as_ref()).expect("final JSON");
    assert!(value.get("writer").and_then(Value::as_u64).is_some());
    assert!(value.get("sequence").and_then(Value::as_u64).is_some());
    let leftovers = std::fs::read_dir(temp.path())
        .expect("temp entries")
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name() != "shared.json")
        .collect::<Vec<_>>();
    assert!(
        leftovers.is_empty(),
        "temporary files leaked: {leftovers:?}"
    );
}

#[test]
fn public_json_reader_rejects_duplicate_keys_without_echoing_them() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("ambiguous.json");
    std::fs::write(&path, br#"{"private-key":"first","private-key":"second"}"#)
        .expect("ambiguous JSON");

    let error = read_json(&path).expect_err("duplicate key must fail");
    let message = error.to_string();
    assert!(message.contains("duplicate key"), "{message}");
    assert!(!message.contains("private-key"), "{message}");
    assert!(!message.contains("first"), "{message}");
    assert!(!message.contains("second"), "{message}");
}

#[test]
fn exclusive_file_lock_serializes_read_modify_write_updates() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = Arc::new(temp.path().join("counter.json"));
    save_json_atomic(path.as_ref(), &json!({"value": 0})).expect("initial counter");
    let barrier = Arc::new(Barrier::new(8));
    let handles = (0..8)
        .map(|_| {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..25 {
                    with_exclusive_file_lock(path.as_ref(), || {
                        let mut value = read_json(path.as_ref())?;
                        let current = value["value"].as_u64().ok_or_else(|| {
                            NetdiagError::InvalidTrace("counter is not an integer".to_string())
                        })?;
                        value["value"] = json!(current + 1);
                        save_json_atomic(path.as_ref(), &value)?;
                        Ok(())
                    })?;
                }
                Result::<()>::Ok(())
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle
            .join()
            .expect("counter thread")
            .expect("locked counter update");
    }

    assert_eq!(read_json(path.as_ref()).expect("counter")["value"], 200);
}

#[test]
fn exclusive_file_lock_is_released_after_action_failure() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state.json");
    let error = with_exclusive_file_lock(&path, || -> Result<()> {
        Err(NetdiagError::InvalidTrace("expected failure".to_string()))
    })
    .expect_err("action must fail");
    assert!(error.to_string().contains("expected failure"));

    with_exclusive_file_lock(&path, || {
        save_json_atomic(&path, &json!({"ok": true})).map(drop)
    })
    .expect("lock should be reusable");
    assert_eq!(read_json(&path).expect("state")["ok"], true);
}

#[test]
fn hil_metadata_updates_reject_missing_required_artifacts() {
    let temp = tempfile::tempdir().expect("tempdir");
    let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("data/samples/congestion.csv");
    let result = crate::pipeline::diagnose_file(sample, temp.path(), None).expect("diagnose");
    let recommendation = &result.recommendations[0];

    fs::remove_file(result.run_dir.join("report.json")).expect("remove report");
    let error = crate::hil_review::review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("missing report must not be treated as a successful review");
    assert!(error.to_string().contains("report is missing"));
}

#[test]
fn hil_run_index_update_rejects_absent_run_id() {
    let temp = tempfile::tempdir().expect("tempdir");
    let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("data/samples/congestion.csv");
    let result = crate::pipeline::diagnose_file(sample, temp.path(), None).expect("diagnose");
    save_json_atomic(
        temp.path().join("run_index.json"),
        &Vec::<RunIndexEntry>::new(),
    )
    .expect("empty run index");

    let recommendation = &result.recommendations[0];
    let error = crate::hil_review::review_recommendation(
        temp.path(),
        &result.run_id,
        &recommendation.recommendation_id,
        HilState::Accepted,
        "confirmed",
        "reviewer",
        recommendation.diagnosis_symptom,
    )
    .expect_err("absent run ID must fail");
    assert!(
        error
            .to_string()
            .contains(format!("run {} is absent", result.run_id).as_str())
    );
}

#[test]
fn run_location_rejects_path_like_run_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    for id in [
        "../outside",
        "nested/path",
        r"nested\path",
        ".hidden",
        "tail.",
    ] {
        let error = resolve_run_location(temp.path(), id).expect_err("unsafe run id must fail");
        assert!(error.to_string().contains("run id"), "{id:?}: {error}");
    }
}

#[test]
fn atomic_file_boundary_cleans_temporary_files_on_write_or_commit_failure() {
    let write_failure = tempfile::tempdir().expect("tempdir");
    let target = write_failure.path().join("state.json");
    let error = write_file_atomically(&target, "json", |file| -> Result<()> {
        file.write_all(b"partial").with_path(&target)?;
        Err(NetdiagError::InvalidTrace("writer failed".to_string()))
    })
    .expect_err("writer failure must propagate");
    assert!(error.to_string().contains("writer failed"));
    assert_eq!(
        error.atomic_publish_phase(),
        Some(crate::error::AtomicPublishPhase::NotPublished)
    );
    assert!(
        std::fs::read_dir(write_failure.path())
            .expect("temp entries")
            .next()
            .is_none()
    );

    let commit_failure = tempfile::tempdir().expect("tempdir");
    let target = commit_failure.path().join("state.json");
    std::fs::create_dir(&target).expect("conflicting target directory");
    let error = write_file_atomically(&target, "json", |file| {
        file.write_all(b"complete").with_path(&target)
    })
    .expect_err("commit failure must propagate");
    assert_eq!(
        error.atomic_publish_phase(),
        Some(crate::error::AtomicPublishPhase::NotPublished)
    );
    let entries = std::fs::read_dir(commit_failure.path())
        .expect("temp entries")
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("entries");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path(), target);
}

#[test]
fn stored_paths_are_confined_to_the_artifact_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("artifacts");
    let manifest = root.join("runs/run-1/manifest.json");
    std::fs::create_dir_all(manifest.parent().expect("manifest parent")).expect("run dir");
    std::fs::write(&manifest, b"{}").expect("manifest");

    assert_eq!(
        resolve_stored_path(&root, "runs/run-1/manifest.json").expect("relative stored path"),
        manifest
    );
    assert_eq!(
        resolve_stored_path(&root, "artifacts/runs/run-1/manifest.json")
            .expect("legacy root-prefixed path"),
        manifest
    );
    assert!(resolve_stored_path(&root, "../outside.json").is_err());
    assert!(
        resolve_stored_path(
            &root,
            &temp.path().join("outside.json").display().to_string()
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn stored_paths_reject_symlinks_that_resolve_outside_the_artifact_root() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("artifacts");
    let outside = temp.path().join("outside.json");
    std::fs::create_dir_all(&root).expect("artifact root");
    std::fs::write(&outside, b"{}").expect("outside file");
    symlink(&outside, root.join("escaped.json")).expect("symlink");

    let error = resolve_stored_path(&root, "escaped.json")
        .expect_err("symlink outside artifact root must fail");
    assert!(error.to_string().contains("outside the artifact root"));

    let outside_dir = temp.path().join("outside-dir");
    std::fs::create_dir_all(&outside_dir).expect("outside directory");
    symlink(&outside_dir, root.join("escaped-dir")).expect("directory symlink");
    let error = resolve_stored_path(&root, "escaped-dir/missing.json")
        .expect_err("nonexistent path below escaping symlink must fail");
    assert!(
        error
            .to_string()
            .contains("ancestor outside the artifact root")
    );
}

#[cfg(unix)]
#[test]
fn run_location_rejects_symlinked_run_directories() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("artifacts");
    let outside_run = temp.path().join("outside-run");
    std::fs::create_dir_all(root.join("runs")).expect("runs root");
    std::fs::create_dir_all(&outside_run).expect("outside run");
    std::fs::write(outside_run.join("manifest.json"), b"{}").expect("manifest");
    symlink(&outside_run, root.join("runs/run-1")).expect("run symlink");

    let error = resolve_run_location(&root, "run-1").expect_err("symlink must fail");
    assert!(error.to_string().contains("symbolic link"));
}

#[test]
fn run_index_corruption_and_duplicate_ids_fail_closed() {
    let corrupt = tempfile::tempdir().expect("tempdir");
    std::fs::write(corrupt.path().join("run_index.json"), b"not json").expect("corrupt index");
    assert!(list_run_index(corrupt.path()).is_err());

    let duplicate = tempfile::tempdir().expect("tempdir");
    let entry = RunIndexEntry {
        run_id: "run-1".to_string(),
        sample: "sample".to_string(),
        created_at: chrono::Utc::now(),
        status: "complete".to_string(),
        run_dir: "runs/run-1".to_string(),
    };
    save_json_atomic(
        duplicate.path().join("run_index.json"),
        &[entry.clone(), entry],
    )
    .expect("duplicate index");
    let error = list_run_index(duplicate.path()).expect_err("duplicate IDs must fail");
    assert!(error.to_string().contains("duplicate run id"));
}

#[test]
fn manifest_scan_does_not_default_missing_reports_to_complete() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir_path = temp.path().join("runs/run-1");
    std::fs::create_dir_all(&run_dir_path).expect("run dir");
    save_json_atomic(
        run_dir_path.join("manifest.json"),
        &RunManifest {
            run_id: "run-1".to_string(),
            sample: "sample".to_string(),
            created_at: chrono::Utc::now(),
            trace_rows: 1,
            artifact_paths: BTreeMap::new(),
        },
    )
    .expect("manifest");

    let error = list_run_index(temp.path()).expect_err("missing report must fail");
    assert!(error.to_string().contains("report.json"));
}

#[test]
fn manifest_run_id_must_match_its_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir_path = temp.path().join("runs/run-1");
    std::fs::create_dir_all(&run_dir_path).expect("run dir");
    save_json_atomic(
        run_dir_path.join("manifest.json"),
        &RunManifest {
            run_id: "other-run".to_string(),
            sample: "sample".to_string(),
            created_at: chrono::Utc::now(),
            trace_rows: 1,
            artifact_paths: BTreeMap::new(),
        },
    )
    .expect("manifest");

    let error = list_run_index(temp.path()).expect_err("identity mismatch must fail");
    assert!(error.to_string().contains("does not match directory"));
}

#[test]
fn manifest_artifact_paths_cannot_escape_the_run_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = crate::diagnose_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv"),
        temp.path(),
        None,
    )
    .expect("diagnosed run");
    let manifest_path = result.run_dir.join("manifest.json");
    let mut manifest: RunManifest =
        serde_json::from_value(read_json(&manifest_path).expect("manifest")).expect("manifest");
    let outside = temp.path().join("outside.json");
    std::fs::write(&outside, b"{}").expect("outside file");

    manifest
        .artifact_paths
        .insert("escape".to_string(), outside.display().to_string());
    save_json_atomic(&manifest_path, &manifest).expect("absolute manifest");
    assert!(run_artifacts(temp.path(), &result.run_id).is_err());

    manifest
        .artifact_paths
        .insert("escape".to_string(), "../../outside.json".to_string());
    save_json_atomic(&manifest_path, &manifest).expect("parent manifest");
    assert!(run_artifacts(temp.path(), &result.run_id).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(&outside, result.run_dir.join("escaped.json")).expect("artifact symlink");
        manifest
            .artifact_paths
            .insert("escape".to_string(), "escaped.json".to_string());
        save_json_atomic(&manifest_path, &manifest).expect("symlink manifest");
        let error = run_artifacts(temp.path(), &result.run_id).expect_err("symlink must fail");
        assert!(error.to_string().contains("outside the run directory"));
    }
}

#[test]
fn connector_health_does_not_hide_corrupt_manifests() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = crate::diagnose_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv"),
        temp.path(),
        None,
    )
    .expect("diagnosed run");
    std::fs::write(result.run_dir.join("manifest.json"), b"not json").expect("corrupt manifest");

    assert!(read_connector_health(temp.path(), &result.run_id).is_err());
}

#[test]
fn critical_run_documents_reject_oversized_files_before_parsing() {
    let manifest_root = tempfile::tempdir().expect("manifest root");
    let manifest_dir = manifest_root.path().join("runs/run-1");
    std::fs::create_dir_all(&manifest_dir).expect("manifest run dir");
    std::fs::File::create(manifest_dir.join("manifest.json"))
        .expect("manifest")
        .set_len(typed_json::MAX_RUN_MANIFEST_BYTES + 1)
        .expect("oversized manifest");
    let manifest_error = read_manifest(manifest_root.path(), "run-1")
        .expect_err("oversized manifest must fail closed");
    assert!(
        manifest_error.to_string().contains("read limit"),
        "{manifest_error}"
    );

    let report_root = tempfile::tempdir().expect("report root");
    let report_dir = report_root.path().join("runs/run-1");
    std::fs::create_dir_all(&report_dir).expect("report run dir");
    save_json_atomic(
        report_dir.join("manifest.json"),
        &RunManifest {
            run_id: "run-1".to_string(),
            sample: "sample".to_string(),
            created_at: chrono::Utc::now(),
            trace_rows: 1,
            artifact_paths: BTreeMap::new(),
        },
    )
    .expect("manifest");
    std::fs::File::create(report_dir.join("report.json"))
        .expect("report")
        .set_len(typed_json::MAX_RUN_REPORT_BYTES + 1)
        .expect("oversized report");
    let report_error =
        read_report(report_root.path(), "run-1").expect_err("oversized report must fail closed");
    assert!(
        report_error.to_string().contains("read limit"),
        "{report_error}"
    );
}

#[test]
fn persisted_run_index_enforces_its_byte_and_entry_contracts() {
    let oversized = tempfile::tempdir().expect("oversized root");
    std::fs::File::create(oversized.path().join("run_index.json"))
        .expect("run index")
        .set_len(typed_json::MAX_RUN_INDEX_BYTES + 1)
        .expect("oversized run index");
    let error = list_run_index(oversized.path()).expect_err("oversized index must fail");
    assert!(error.to_string().contains("read limit"), "{error}");

    let too_many = tempfile::tempdir().expect("entry root");
    let entries = (0..=typed_json::MAX_RUN_INDEX_ENTRIES)
        .map(|index| RunIndexEntry {
            run_id: format!("run-{index}"),
            sample: "sample".to_string(),
            created_at: chrono::Utc::now(),
            status: "complete".to_string(),
            run_dir: format!("runs/run-{index}"),
        })
        .collect::<Vec<_>>();
    save_json_atomic(too_many.path().join("run_index.json"), &entries).expect("run index");
    let error = list_run_index(too_many.path()).expect_err("oversized index count must fail");
    assert!(error.to_string().contains("51 entries"), "{error}");
}

#[cfg(unix)]
#[test]
fn critical_run_document_symbolic_links_fail_closed() {
    use std::os::unix::fs::symlink;

    let index_root = tempfile::tempdir().expect("index root");
    let outside_index = index_root.path().join("outside-index.json");
    save_json_atomic(&outside_index, &Vec::<RunIndexEntry>::new()).expect("outside index");
    symlink(&outside_index, index_root.path().join("run_index.json")).expect("index symlink");
    let index_error = list_run_index(index_root.path()).expect_err("index symlink must fail");
    assert!(
        index_error.to_string().contains("regular, non-symlink"),
        "{index_error}"
    );

    let report_root = tempfile::tempdir().expect("report root");
    let report_dir = report_root.path().join("runs/run-1");
    std::fs::create_dir_all(&report_dir).expect("run dir");
    save_json_atomic(
        report_dir.join("manifest.json"),
        &RunManifest {
            run_id: "run-1".to_string(),
            sample: "sample".to_string(),
            created_at: chrono::Utc::now(),
            trace_rows: 1,
            artifact_paths: BTreeMap::new(),
        },
    )
    .expect("manifest");
    let outside_report = report_root.path().join("outside-report.json");
    std::fs::write(&outside_report, b"{}").expect("outside report");
    symlink(&outside_report, report_dir.join("report.json")).expect("report symlink");
    let report_error =
        read_report(report_root.path(), "run-1").expect_err("report symlink must fail closed");
    assert!(
        report_error.to_string().contains("regular, non-symlink"),
        "{report_error}"
    );
}

#[test]
fn manifest_declared_connector_health_must_exist() {
    let temp = tempfile::tempdir().expect("tempdir");
    let result = crate::diagnose_file(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv"),
        temp.path(),
        None,
    )
    .expect("diagnosed run");
    std::fs::remove_file(result.run_dir.join("connector_health.json"))
        .expect("remove declared connector health");

    let error = read_connector_health(temp.path(), &result.run_id)
        .expect_err("declared missing health must not be inferred");
    assert!(
        error
            .to_string()
            .contains("manifest-declared connector health is missing"),
        "{error}"
    );
}
