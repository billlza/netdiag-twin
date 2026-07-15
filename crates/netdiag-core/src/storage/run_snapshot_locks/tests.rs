use super::location_identity::ResolvedRunLocation;
use super::{
    ACTION_VERIFICATION_JOURNAL_FILE_NAME, HIL_REVIEW_JOURNAL_FILE_NAME, SnapshotOutputTarget,
    snapshot_targets, with_resolved_run_snapshot_locks,
};
use crate::models::RunManifest;
use crate::storage::{RunLocation, resolve_run_location};
use chrono::Utc;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[cfg(unix)]
use crate::error::{IoContext, NetdiagError};
#[cfg(unix)]
use std::io::Write;

fn write_manifest(run_dir: &Path, run_id: &str) {
    crate::storage::save_json_atomic(
        run_dir.join("manifest.json"),
        &RunManifest {
            run_id: run_id.to_string(),
            sample: "snapshot-lock-test".to_string(),
            created_at: Utc::now(),
            trace_rows: 1,
            artifact_paths: BTreeMap::new(),
        },
    )
    .expect("manifest");
}

#[test]
fn detects_run_directory_replacement_at_the_same_path() {
    let root = tempfile::tempdir().expect("tempdir");
    let run_id = "run-location-swap";
    let run_dir = root.path().join("runs").join(run_id);
    fs::create_dir_all(&run_dir).expect("run directory");
    write_manifest(&run_dir, run_id);
    let initial = ResolvedRunLocation::capture(root.path(), run_id).expect("initial location");

    let displaced = root.path().join("displaced-run");
    fs::rename(&run_dir, &displaced).expect("displace run directory");
    fs::create_dir_all(&run_dir).expect("replacement run directory");
    write_manifest(&run_dir, run_id);
    let replacement =
        ResolvedRunLocation::capture(root.path(), run_id).expect("replacement location");

    let error = initial
        .ensure_same_location(&replacement)
        .expect_err("same-path directory replacement must fail closed");
    assert!(
        error.to_string().contains("run location changed"),
        "{error}"
    );
}

#[test]
fn resolved_location_locks_do_not_repeat_global_run_discovery() {
    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("artifacts");
    let run_id = "detached-run";
    let run_dir = root.path().join("detached").join(run_id);
    fs::create_dir_all(&artifact_root).expect("artifact root");
    fs::create_dir_all(&run_dir).expect("detached run directory");
    write_manifest(&run_dir, run_id);
    let location = RunLocation {
        artifact_root: artifact_root.clone(),
        run_dir: run_dir.clone(),
        lab_run_dir: None,
        lab_index_root: None,
    };
    resolve_run_location(&artifact_root, run_id).expect_err("detached run is not discoverable");

    with_resolved_run_snapshot_locks(&location, run_id, |locked| {
        assert_eq!(locked.run_dir, run_dir);
        Ok(())
    })
    .expect("pre-resolved location must not trigger global discovery");
}

#[test]
fn resolved_location_capture_revalidates_manifest_run_id() {
    let root = tempfile::tempdir().expect("tempdir");
    let run_id = "manifest-bound-run";
    let run_dir = root.path().join(run_id);
    fs::create_dir_all(&run_dir).expect("run directory");
    write_manifest(&run_dir, run_id);
    let location = RunLocation {
        artifact_root: root.path().to_path_buf(),
        run_dir: run_dir.clone(),
        lab_run_dir: None,
        lab_index_root: None,
    };
    ResolvedRunLocation::capture_resolved(&location, run_id).expect("initial capture");
    write_manifest(&run_dir, "different-run");

    let error = match ResolvedRunLocation::capture_resolved(&location, run_id) {
        Ok(_) => panic!("manifest replacement must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("manifest run id"), "{error}");
}

#[test]
fn transaction_lock_set_includes_all_transaction_journals() {
    let root = tempfile::tempdir().expect("tempdir");
    let run_id = "journal-lock-order";
    let run_dir = root.path().join(run_id);
    fs::create_dir_all(&run_dir).expect("run directory");
    write_manifest(&run_dir, run_id);
    let location = RunLocation {
        artifact_root: root.path().to_path_buf(),
        run_dir: run_dir.clone(),
        lab_run_dir: None,
        lab_index_root: None,
    };

    let targets = snapshot_targets(&location, run_id, &[], false).expect("transaction targets");
    let journal =
        super::target_path::resolve_target_path(&run_dir.join(HIL_REVIEW_JOURNAL_FILE_NAME))
            .expect("journal target");
    let action_journal = super::target_path::resolve_target_path(
        &run_dir.join(ACTION_VERIFICATION_JOURNAL_FILE_NAME),
    )
    .expect("action journal target");

    assert!(targets.contains(&journal));
    assert!(targets.contains(&action_journal));
}

#[test]
fn output_preparation_does_not_create_a_missing_parent() {
    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("artifacts");
    fs::create_dir(&artifact_root).expect("artifact root");
    let missing_parent = root.path().join("exports").join("nested");
    let output = missing_parent.join("feedback.jsonl");

    SnapshotOutputTarget::prepare(&artifact_root, &output).expect("prepare output target");

    assert!(
        !root.path().join("exports").exists(),
        "output preflight must not create user directories"
    );
}

#[test]
fn missing_protected_leaf_case_alias_is_rejected_without_creation() {
    let root = tempfile::tempdir().expect("tempdir");
    let missing_artifact_root = root.path().join("missing-artifacts");
    let output = missing_artifact_root.join("RUN_INDEX.JSON");

    let error = SnapshotOutputTarget::prepare(&missing_artifact_root, &output)
        .expect_err("a prospective case alias of a protected index must be rejected");

    assert!(error.to_string().contains("protected run input"), "{error}");
    assert!(
        !missing_artifact_root.exists(),
        "rejected preflight must not create the missing protected parent"
    );
}

#[test]
fn different_leaf_in_a_missing_artifact_root_is_allowed_without_creation() {
    let root = tempfile::tempdir().expect("tempdir");
    let missing_artifact_root = root.path().join("missing-artifacts");
    let output = missing_artifact_root.join("feedback.jsonl");

    SnapshotOutputTarget::prepare(&missing_artifact_root, &output)
        .expect("a sibling of the protected indexes is allowed");

    assert!(
        !missing_artifact_root.exists(),
        "allowed preflight must not create the missing output parent"
    );
}

#[test]
fn future_run_descendants_are_rejected_before_concurrent_creation() {
    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("artifacts");
    fs::create_dir(&artifact_root).expect("artifact root");

    for subtree in ["runs", "lab-runs", "pilot-runs"] {
        let output = artifact_root
            .join(subtree)
            .join("future-id")
            .join("report.json");
        let error = SnapshotOutputTarget::prepare(&artifact_root, &output)
            .expect_err("future run descendants are structurally reserved");
        assert!(error.to_string().contains("reserved artifact run subtree"));
        fs::create_dir_all(output.parent().expect("future run parent"))
            .expect("concurrent future run creation");
        fs::write(&output, b"protected").expect("future protected report");
        assert_eq!(fs::read(output).expect("future report"), b"protected");
    }

    SnapshotOutputTarget::prepare(&artifact_root, &artifact_root.join("feedback.jsonl"))
        .expect("artifact-root feedback sibling remains valid");
}

#[cfg(any(unix, windows))]
#[test]
fn existing_hard_link_alias_of_a_protected_index_is_rejected() {
    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("artifacts");
    let export_root = root.path().join("exports");
    fs::create_dir(&artifact_root).expect("artifact root");
    fs::create_dir(&export_root).expect("export root");
    let protected = artifact_root.join("run_index.json");
    fs::write(&protected, b"[]\n").expect("protected run index");
    let output = export_root.join("feedback.jsonl");
    fs::hard_link(&protected, &output).expect("hard-link alias");

    let error = SnapshotOutputTarget::prepare(&artifact_root, &output)
        .expect_err("the same opened file identity must be rejected");

    assert!(error.to_string().contains("protected run input"), "{error}");
    assert_eq!(fs::read(protected).expect("preserved index"), b"[]\n");
}

#[test]
fn lexical_alias_through_a_missing_component_is_rejected_without_creation() {
    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("artifacts");
    fs::create_dir(&artifact_root).expect("artifact root");
    let missing = artifact_root.join("unused");
    let output = missing.join("..").join("run_index.json");

    let error = SnapshotOutputTarget::prepare(&artifact_root, &output)
        .expect_err("a lexical parent alias must remain protected");

    assert!(error.to_string().contains("protected run input"), "{error}");
    assert!(
        !missing.exists(),
        "lexical validation must not create a directory"
    );
}

#[cfg(unix)]
#[test]
fn symlink_parent_alias_fails_closed_without_creating_output() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("artifacts");
    fs::create_dir(&artifact_root).expect("artifact root");
    let alias = root.path().join("artifact-alias");
    symlink(&artifact_root, &alias).expect("artifact root alias");
    let output = alias.join("feedback.jsonl");

    let error = SnapshotOutputTarget::prepare(&artifact_root, &output)
        .expect_err("an untrusted symlink alias must fail closed");

    assert!(error.to_string().contains("protected run input"), "{error}");
    assert!(error.to_string().contains("untrusted symlink"), "{error}");
    assert!(!output.exists(), "rejected output must not be created");
}

#[cfg(unix)]
#[test]
fn output_parent_replaced_by_run_symlink_before_binding_fails_closed() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("artifacts");
    let run_id = "protected-output-bind";
    let run_dir = artifact_root.join("runs").join(run_id);
    fs::create_dir_all(&run_dir).expect("run directory");
    write_manifest(&run_dir, run_id);
    let protected_report = run_dir.join("report.json");
    fs::write(&protected_report, b"protected").expect("protected report");
    let location = RunLocation {
        artifact_root: artifact_root.clone(),
        run_dir: run_dir.clone(),
        lab_run_dir: None,
        lab_index_root: None,
    };
    let output_parent = root.path().join("exports");
    let output = output_parent.join("report.json");
    let mut target = SnapshotOutputTarget::prepare(&artifact_root, &output).expect("preflight");
    target
        .validate_for_run(&location, run_id)
        .expect("capture protected scopes");
    symlink(&run_dir, &output_parent).expect("replace missing parent with run alias");

    let error = match target.bind_for_publication() {
        Ok(_) => panic!("untrusted replacement must fail before publication"),
        Err(error) => error,
    };

    let expected_symlink = root
        .path()
        .canonicalize()
        .expect("resolved temporary root")
        .join("exports");
    assert!(matches!(
        error,
        NetdiagError::FilesystemTrust {
            context: "atomic file target parent",
            source: netdiag_platform::DirectoryTrustError::UntrustedSymlink { path, .. },
        } if path == expected_symlink
    ));
    assert_eq!(
        fs::read(protected_report).expect("protected bytes"),
        b"protected"
    );
}

#[cfg(unix)]
#[test]
fn bound_snapshot_output_does_not_follow_a_later_run_symlink() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("artifacts");
    let run_id = "protected-output-commit";
    let run_dir = artifact_root.join("runs").join(run_id);
    fs::create_dir_all(&run_dir).expect("run directory");
    write_manifest(&run_dir, run_id);
    let protected_report = run_dir.join("report.json");
    fs::write(&protected_report, b"protected").expect("protected report");
    let location = RunLocation {
        artifact_root: artifact_root.clone(),
        run_dir: run_dir.clone(),
        lab_run_dir: None,
        lab_index_root: None,
    };
    let output_parent = root.path().join("exports");
    fs::create_dir(&output_parent).expect("output parent");
    let output = output_parent.join("report.json");
    let mut target = SnapshotOutputTarget::prepare(&artifact_root, &output).expect("preflight");
    target
        .validate_for_run(&location, run_id)
        .expect("capture protected scopes");
    let bound = target.bind_for_publication().expect("bound output");
    let displaced = root.path().join("displaced-exports");
    fs::rename(&output_parent, &displaced).expect("displace output parent");
    symlink(&run_dir, &output_parent).expect("replace output path with run alias");

    crate::storage::write_file_atomically_to_bound(&bound, target.path(), "json", |file| {
        file.write_all(b"exported").with_path(target.path())
    })
    .expect("publish through captured directory handle");

    assert_eq!(
        fs::read(protected_report).expect("protected bytes"),
        b"protected"
    );
    assert_eq!(
        fs::read(displaced.join("report.json")).expect("bound output"),
        b"exported"
    );
}

#[cfg(any(target_os = "macos", windows))]
#[test]
fn case_alias_of_a_protected_parent_uses_the_opened_directory_identity() {
    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("ArtifactRoot");
    fs::create_dir(&artifact_root).expect("artifact root");
    let alias = root.path().join("artifactroot");
    if !alias.exists() {
        return;
    }

    let error = SnapshotOutputTarget::prepare(&artifact_root, &alias.join("run_index.json"))
        .expect_err("a case alias of the protected parent must be rejected");

    assert!(error.to_string().contains("protected run input"), "{error}");
}

#[cfg(target_os = "macos")]
#[test]
fn unicode_alias_of_a_protected_parent_uses_the_opened_directory_identity() {
    let root = tempfile::tempdir().expect("tempdir");
    let artifact_root = root.path().join("caf\u{e9}");
    fs::create_dir(&artifact_root).expect("artifact root");
    let alias = root.path().join("cafe\u{301}");
    if !alias.exists() {
        return;
    }

    let error = SnapshotOutputTarget::prepare(&artifact_root, &alias.join("run_index.json"))
        .expect_err("a Unicode alias of the protected parent must be rejected");

    assert!(error.to_string().contains("protected run input"), "{error}");
}
