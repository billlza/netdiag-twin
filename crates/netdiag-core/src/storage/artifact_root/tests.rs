#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::clear::{ClearCrashPoint, clear_run_history_with_crash, clear_run_history_with_hooks};
use super::ownership::OWNERSHIP_FILE_NAME;
use super::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::error::NetdiagError;
use crate::migrate_legacy_artifact_root;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[test]
fn empty_root_is_claimed_with_a_versioned_canonical_identity() {
    let root = tempfile::tempdir().expect("temporary artifact root");

    ensure_artifact_root_owned(root.path()).expect("claim empty artifact root");

    let marker: Value = serde_json::from_slice(
        &fs::read(root.path().join(OWNERSHIP_FILE_NAME)).expect("ownership marker"),
    )
    .expect("ownership marker JSON");
    assert_eq!(marker["schema_version"], 1);
    assert_eq!(marker["product_id"], "netdiag_twin");
    let root_id = marker["root_id"].as_str().expect("root id string");
    assert_eq!(
        uuid::Uuid::parse_str(root_id)
            .expect("root id UUID")
            .to_string(),
        root_id
    );
}

#[cfg(unix)]
#[test]
fn authorized_capability_never_claims_a_replacement_root() {
    use std::os::unix::fs::DirBuilderExt;

    let parent = tempfile::tempdir().expect("temporary parent");
    let root = parent.path().join("artifacts");
    let displaced = parent.path().join("displaced-artifacts");
    let capability = prepare_artifact_root(&root).expect("authorize artifact root");
    fs::rename(&root, &displaced).expect("displace authorized root");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("replacement root");

    let error = with_artifact_root_capability(&capability, |_| Ok(()))
        .expect_err("replacement root must fail before ownership or recovery");

    assert!(error.to_string().contains("identity"), "{error}");
    assert!(displaced.join(OWNERSHIP_FILE_NAME).is_file());
    assert!(
        fs::read_dir(&root)
            .expect("replacement root entries")
            .next()
            .is_none(),
        "authorization reuse must not claim or mutate the replacement root"
    );
}

#[cfg(unix)]
#[test]
fn authorized_capability_rejects_a_replaced_marker_without_running_the_action() {
    let parent = tempfile::tempdir().expect("temporary parent");
    let root = parent.path().join("artifacts");
    let replacement_root = parent.path().join("replacement-artifacts");
    let capability = prepare_artifact_root(&root).expect("authorize artifact root");
    ensure_artifact_root_owned(&replacement_root).expect("claim replacement root");
    let marker_path = root.join(OWNERSHIP_FILE_NAME);
    let displaced_marker = root.join("displaced-ownership-marker.json");
    let original = fs::read(&marker_path).expect("original marker");
    let replacement =
        fs::read(replacement_root.join(OWNERSHIP_FILE_NAME)).expect("replacement marker");
    fs::rename(&marker_path, &displaced_marker).expect("displace marker");
    fs::write(&marker_path, &replacement).expect("replace marker");
    let action_ran = std::cell::Cell::new(false);

    let error = with_artifact_root_capability(&capability, |_| {
        action_ran.set(true);
        Ok(())
    })
    .expect_err("marker replacement must invalidate the capability");

    assert!(error.to_string().contains("identity changed"), "{error}");
    assert!(!action_ran.get(), "invalid capability executed its action");
    assert_eq!(
        fs::read(&marker_path).expect("replacement remains"),
        replacement
    );
    assert_eq!(
        fs::read(&displaced_marker).expect("original remains"),
        original
    );
}

#[test]
fn nonempty_legacy_root_is_never_claimed_or_cleared_implicitly() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let run = root.path().join("runs/legacy-run");
    fs::create_dir_all(&run).expect("legacy run directory");
    fs::write(run.join("manifest.json"), b"legacy").expect("legacy artifact");

    let error = clear_run_history(root.path())
        .expect_err("a nonempty unowned artifact root must be rejected");

    assert!(error.to_string().contains("explicit migration is required"));
    assert_eq!(
        fs::read(run.join("manifest.json")).expect("legacy artifact remains"),
        b"legacy"
    );
    assert!(!root.path().join(OWNERSHIP_FILE_NAME).exists());
}

#[cfg(unix)]
#[test]
fn ownership_marker_symlink_is_rejected_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary artifact root");
    let outside = tempfile::tempdir().expect("external marker root");
    let target = outside.path().join("marker.json");
    fs::write(&target, br#"{"schema_version":1}"#).expect("external marker");
    symlink(&target, root.path().join(OWNERSHIP_FILE_NAME)).expect("marker symlink");

    let error = clear_run_history(root.path()).expect_err("marker symlink must fail closed");

    assert!(
        error.to_string().contains("symlink/reparse point"),
        "{error}"
    );
    assert_eq!(
        fs::read(&target).expect("external marker remains"),
        br#"{"schema_version":1}"#
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn owned_history_is_tombstoned_persisted_and_removed() {
    let root = owned_history_root();

    clear_run_history(root.path()).expect("clear owned run history");

    assert!(!root.path().join("runs").exists());
    assert!(!root.path().join("run_index.json").exists());
    assert!(root.path().join(OWNERSHIP_FILE_NAME).is_file());
    assert_no_clear_tombstones(root.path());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn second_stage_failure_rolls_back_the_tombstoned_runs_directory() {
    let root = owned_history_root();
    let original_index = fs::read(root.path().join("run_index.json")).expect("original index");

    let error = clear_run_history_with_hooks(
        root.path(),
        || Ok(()),
        || {
            Err(NetdiagError::InvalidTrace(
                "injected index tombstone failure".to_string(),
            ))
        },
    )
    .expect_err("second transaction stage must fail");

    assert!(
        error
            .to_string()
            .contains("injected index tombstone failure")
    );
    assert!(root.path().join("runs/run-1/manifest.json").is_file());
    assert_eq!(
        fs::read(root.path().join("run_index.json")).expect("restored index"),
        original_index
    );
    assert_no_clear_tombstones(root.path());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn runs_replacement_after_capture_fails_before_mutating_either_directory() {
    let root = owned_history_root();
    let runs = root.path().join("runs");
    let displaced = root.path().join("displaced-runs");

    let error = clear_run_history_with_hooks(
        root.path(),
        || {
            fs::rename(&runs, &displaced).map_err(|source| NetdiagError::Io {
                path: runs.clone(),
                source,
            })?;
            fs::create_dir(&runs).map_err(|source| NetdiagError::Io {
                path: runs.clone(),
                source,
            })?;
            fs::write(runs.join("replacement.txt"), b"replacement").map_err(|source| {
                NetdiagError::Io {
                    path: runs.join("replacement.txt"),
                    source,
                }
            })?;
            Ok(())
        },
        || Ok(()),
    )
    .expect_err("captured runs replacement must fail closed");

    assert!(error.to_string().contains("identity"), "{error}");
    assert_eq!(
        fs::read(runs.join("replacement.txt")).expect("replacement remains"),
        b"replacement"
    );
    assert!(displaced.join("run-1/manifest.json").is_file());
    assert!(root.path().join("run_index.json").is_file());
    assert_no_clear_tombstones(root.path());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn index_content_change_after_capture_fails_before_history_mutation() {
    let root = owned_history_root();
    let index = root.path().join("run_index.json");

    let error = clear_run_history_with_hooks(
        root.path(),
        || {
            fs::write(&index, b"[ ]").map_err(|source| NetdiagError::Io {
                path: index.clone(),
                source,
            })
        },
        || Ok(()),
    )
    .expect_err("captured run index mutation must fail closed");

    assert!(error.to_string().contains("changed"), "{error}");
    assert_eq!(fs::read(&index).expect("mutated index remains"), b"[ ]");
    assert!(root.path().join("runs/run-1/manifest.json").is_file());
    assert_no_clear_tombstones(root.path());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn interrupted_clear_is_recovered_deterministically_at_every_durable_phase() {
    for (point, history_survives) in [
        (ClearCrashPoint::JournalPrepared, true),
        (ClearCrashPoint::RunsTombstoned, true),
        (ClearCrashPoint::IndexTombstoned, false),
        (ClearCrashPoint::JournalCommitted, false),
        (ClearCrashPoint::IndexDeleted, false),
        (ClearCrashPoint::RunsDeleted, false),
    ] {
        let root = owned_history_root();
        clear_run_history_with_crash(root.path(), point)
            .expect_err("injected crash must interrupt the clear transaction");

        ensure_artifact_root_owned(root.path()).expect("recover interrupted clear transaction");

        assert_eq!(root.path().join("runs").exists(), history_survives);
        assert_eq!(
            root.path().join("run_index.json").exists(),
            history_survives
        );
        assert_no_clear_tombstones(root.path());
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn recovery_rejects_a_replaced_tombstone_without_deleting_either_directory() {
    let root = owned_history_root();
    clear_run_history_with_crash(root.path(), ClearCrashPoint::RunsTombstoned)
        .expect_err("injected crash after runs tombstone");
    let tombstone = fs::read_dir(root.path())
        .expect("artifact root entries")
        .map(|entry| entry.expect("artifact root entry").path())
        .find(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().ends_with("-runs"))
        })
        .expect("runs tombstone");
    let displaced = root.path().join("displaced-journaled-runs");
    fs::rename(&tombstone, &displaced).expect("displace journaled tombstone");
    fs::create_dir(&tombstone).expect("replacement tombstone");
    fs::write(tombstone.join("replacement.txt"), b"replacement").expect("replacement data");

    let error = ensure_artifact_root_owned(root.path())
        .expect_err("replacement tombstone must fail recovery closed");

    assert!(error.to_string().contains("changed"), "{error}");
    assert_eq!(
        fs::read(tombstone.join("replacement.txt")).expect("replacement remains"),
        b"replacement"
    );
    assert!(displaced.join("run-1/manifest.json").is_file());
    assert!(root.path().join("run_index.json").is_file());
}

#[test]
fn explicit_migration_accepts_an_index_entry_bound_to_a_published_run() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let sample =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv");
    let run = crate::diagnose_file(sample, root.path(), None).expect("publish migration fixture");
    let entries = crate::storage::list_run_index(root.path()).expect("published run index");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].run_id, run.run_id);
    fs::remove_file(root.path().join(OWNERSHIP_FILE_NAME)).expect("remove current marker fixture");

    migrate_legacy_artifact_root(root.path()).expect("migrate verified legacy root");

    assert!(root.path().join(OWNERSHIP_FILE_NAME).is_file());
    assert!(root.path().join("runs").join(run.run_id).is_dir());
}

#[test]
fn explicit_migration_rejects_an_empty_run_index_as_ownership_proof() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    fs::write(root.path().join("run_index.json"), b"[]").expect("empty run index");

    let error = migrate_legacy_artifact_root(root.path())
        .expect_err("an empty run index must not prove product ownership");

    assert!(error.to_string().contains("no verifiable product artifact"));
    assert!(!root.path().join(OWNERSHIP_FILE_NAME).exists());
    assert_eq!(
        fs::read(root.path().join("run_index.json")).expect("index remains"),
        b"[]"
    );
}

#[test]
fn explicit_migration_rejects_an_unbound_run_index_entry() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    crate::storage::save_json_atomic(
        root.path().join("run_index.json"),
        &[crate::models::RunIndexEntry {
            run_id: "forged-run".to_string(),
            sample: "forged-sample".to_string(),
            created_at: chrono::Utc::now(),
            status: "complete".to_string(),
            run_dir: "runs/forged-run".to_string(),
        }],
    )
    .expect("forged run index");

    let error = migrate_legacy_artifact_root(root.path())
        .expect_err("an index entry without a trusted run must not prove ownership");

    assert!(error.to_string().contains("unknown run id"), "{error}");
    assert!(!root.path().join(OWNERSHIP_FILE_NAME).exists());
    assert!(!root.path().join("runs").exists());
}

#[test]
fn explicit_migration_rejects_an_empty_lab_index_as_ownership_proof() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    crate::storage::save_json_atomic(
        root.path().join("lab_run_index.json"),
        &crate::lab::LabRunIndex {
            schema: "netdiag-lab-run-index/v1".to_string(),
            generated_at: chrono::Utc::now(),
            runs: Vec::new(),
        },
    )
    .expect("empty lab index");

    let error = migrate_legacy_artifact_root(root.path())
        .expect_err("an empty lab index must not prove product ownership");

    assert!(error.to_string().contains("no verifiable product artifact"));
    assert!(!root.path().join(OWNERSHIP_FILE_NAME).exists());
}

#[test]
fn explicit_migration_rejects_an_unbound_lab_index_entry() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    crate::storage::save_json_atomic(
        root.path().join("lab_run_index.json"),
        &crate::lab::LabRunIndex {
            schema: "netdiag-lab-run-index/v1".to_string(),
            generated_at: chrono::Utc::now(),
            runs: vec![crate::lab::LabRunIndexEntry {
                run_id: "forged-run".to_string(),
                scenario_id: "forged-scenario".to_string(),
                scenario_name: "Forged scenario".to_string(),
                created_at: chrono::Utc::now(),
                lab_run_dir: "lab-runs/forged-scenario/forged-run".to_string(),
                pipeline_run_dir: "lab-runs/forged-scenario/forged-run/runs/forged-run".to_string(),
                acceptance_path: "lab-runs/forged-scenario/forged-run/acceptance.json".to_string(),
                comparison_path: "lab-runs/forged-scenario/forged-run/comparison.json".to_string(),
                scenario_path: "lab-runs/forged-scenario/forged-run/scenario.yaml".to_string(),
                passed: true,
            }],
        },
    )
    .expect("forged lab index");

    let error = migrate_legacy_artifact_root(root.path())
        .expect_err("a lab index entry without trusted artifacts must not prove ownership");

    assert!(
        error.to_string().contains("invalid filesystem type"),
        "{error}"
    );
    assert!(!root.path().join(OWNERSHIP_FILE_NAME).exists());
    assert!(!root.path().join("lab-runs").exists());
}

#[test]
fn explicit_migration_accepts_a_lab_index_bound_to_published_artifacts() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    crate::ml::rebuild_synthetic_model_bundle_in_artifact_root(root.path())
        .expect("synthetic model fixture");
    let scenario = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples/scenarios/lab-congestion-001.yaml");
    let result = crate::lab::run_lab_scenario(
        scenario,
        crate::lab::LabRunOptions {
            artifacts: root.path().to_path_buf(),
        },
    )
    .expect("published lab fixture");
    fs::remove_dir_all(root.path().join("model")).expect("remove independent model anchor");
    fs::remove_file(root.path().join(OWNERSHIP_FILE_NAME)).expect("remove current marker fixture");

    migrate_legacy_artifact_root(root.path()).expect("migrate verified lab artifacts");

    assert!(root.path().join(OWNERSHIP_FILE_NAME).is_file());
    assert!(
        Path::new(&result.pipeline_run_dir)
            .join("manifest.json")
            .is_file()
    );
    assert!(root.path().join("lab_run_index.json").is_file());
}

#[test]
fn explicit_migration_recognizes_v0_5_2_model_without_enabling_runtime_reads() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let model_dir = root.path().join("model");
    crate::ml::rebuild_synthetic_model_bundle(&model_dir).expect("create source model bundle");
    let current: Value = crate::storage::read_json(model_dir.join("current.json"))
        .expect("current model descriptor");
    let generation = current["generation"].as_str().expect("current generation");
    let generation_dir = model_dir.join("generations").join(generation);
    let model_bytes =
        fs::read(generation_dir.join("rust_logistic_model.json")).expect("source model bytes");
    let mut manifest: crate::models::ModelManifest = serde_json::from_slice(
        &fs::read(generation_dir.join("model_manifest.json")).expect("source manifest bytes"),
    )
    .expect("source model manifest");
    manifest.schema_version = "netdiag-model-manifest/v1".to_string();
    manifest.model_file_hash_sha256.clear();
    fs::write(model_dir.join("rust_logistic_model.json"), &model_bytes)
        .expect("legacy model fixture");
    crate::storage::save_json_atomic(model_dir.join("model_manifest.json"), &manifest)
        .expect("legacy manifest fixture");
    fs::remove_file(model_dir.join("current.json")).expect("remove v2 current descriptor");
    fs::remove_dir_all(model_dir.join("generations")).expect("remove v2 generations");
    let legacy_manifest_bytes =
        fs::read(model_dir.join("model_manifest.json")).expect("legacy manifest bytes");

    migrate_legacy_artifact_root(root.path()).expect("claim exact v0.5.2 model root");

    assert!(root.path().join(OWNERSHIP_FILE_NAME).is_file());
    assert_eq!(
        fs::read(model_dir.join("rust_logistic_model.json")).expect("unchanged legacy model"),
        model_bytes
    );
    assert_eq!(
        fs::read(model_dir.join("model_manifest.json")).expect("unchanged legacy manifest"),
        legacy_manifest_bytes
    );
    crate::ml::load_existing_model_bundle_identity(&model_dir)
        .expect_err("the runtime loader must continue rejecting v1");

    crate::ml::rebuild_synthetic_model_bundle_in_artifact_root(root.path())
        .expect("explicit writer migration");

    assert!(!model_dir.join("rust_logistic_model.json").exists());
    assert!(!model_dir.join("model_manifest.json").exists());
    assert!(model_dir.join("current.json").is_file());
    assert_eq!(
        fs::read_dir(model_dir.join("generations"))
            .expect("migrated generations")
            .count(),
        2
    );
    let identity =
        crate::ml::load_existing_model_bundle_identity(&model_dir).expect("current v2 model");
    assert_eq!(
        identity.manifest.schema_version,
        crate::ml::MODEL_MANIFEST_SCHEMA
    );
}

#[test]
fn explicit_migration_accepts_the_v0_5_2_feedback_export_layout() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let sample =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv");
    crate::diagnose_file(sample, root.path(), None).expect("publish migration fixture");
    let datasets = root.path().join("datasets");
    fs::create_dir(&datasets).expect("legacy datasets directory");
    write_legacy_feedback(&datasets);
    fs::remove_file(root.path().join(OWNERSHIP_FILE_NAME)).expect("remove current marker fixture");

    migrate_legacy_artifact_root(root.path()).expect("migrate v0.5.2 feedback layout");

    assert!(root.path().join(OWNERSHIP_FILE_NAME).is_file());
    assert!(datasets.join("lab-feedback.jsonl").is_file());
}

#[test]
fn explicit_migration_preserves_an_empty_v0_5_2_feedback_export_with_a_run_anchor() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let sample =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv");
    crate::diagnose_file(sample, root.path(), None).expect("publish migration fixture");
    let datasets = root.path().join("datasets");
    fs::create_dir(&datasets).expect("legacy datasets directory");
    fs::write(datasets.join("lab-feedback.jsonl"), b"").expect("empty legacy feedback export");
    fs::remove_file(root.path().join(OWNERSHIP_FILE_NAME)).expect("remove current marker fixture");

    migrate_legacy_artifact_root(root.path()).expect("migrate empty v0.5.2 feedback export");

    assert!(root.path().join(OWNERSHIP_FILE_NAME).is_file());
    assert_eq!(
        fs::read(datasets.join("lab-feedback.jsonl")).expect("feedback export remains"),
        b""
    );
}

#[test]
fn explicit_migration_does_not_treat_an_empty_feedback_file_as_ownership_proof() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let datasets = root.path().join("datasets");
    fs::create_dir(&datasets).expect("legacy datasets directory");
    fs::write(datasets.join("lab-feedback.jsonl"), b"").expect("empty feedback file");

    let error = migrate_legacy_artifact_root(root.path())
        .expect_err("an empty feedback file alone must not prove product ownership");

    assert!(error.to_string().contains("no verifiable product artifact"));
    assert!(!root.path().join(OWNERSHIP_FILE_NAME).exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn explicit_migration_validates_a_v0_5_2_registered_dataset_layout() {
    let parent = tempfile::tempdir().expect("temporary parent");
    let root = parent.path().join("artifacts");
    let dataset = parent.path().join("feedback.jsonl");
    write_legacy_feedback(parent.path());
    fs::rename(parent.path().join("lab-feedback.jsonl"), &dataset).expect("dataset fixture");
    crate::dataset::register_dataset_jsonl(
        &dataset,
        crate::dataset::DatasetRegisterOptions {
            artifacts: root.clone(),
            metadata: crate::dataset::DatasetManifestMetadata {
                dataset_id: Some("feedback".to_string()),
                ..crate::dataset::DatasetManifestMetadata::default()
            },
        },
    )
    .expect("registered dataset fixture");
    fs::remove_file(root.join(OWNERSHIP_FILE_NAME)).expect("remove current marker fixture");

    migrate_legacy_artifact_root(&root).expect("migrate registered dataset layout");

    assert!(root.join(OWNERSHIP_FILE_NAME).is_file());
    assert!(root.join("datasets/registry.json").is_file());
}

#[test]
fn explicit_migration_rejects_unknown_legacy_dataset_entries_without_claiming() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let datasets = root.path().join("datasets");
    fs::create_dir(&datasets).expect("legacy datasets directory");
    write_legacy_feedback(&datasets);
    fs::write(datasets.join("notes.txt"), b"unrelated").expect("unknown dataset entry");

    let error = migrate_legacy_artifact_root(root.path())
        .expect_err("unknown dataset entry must fail migration");

    assert!(error.to_string().contains("unsupported entry"), "{error}");
    assert!(!root.path().join(OWNERSHIP_FILE_NAME).exists());
    assert_eq!(
        fs::read(datasets.join("notes.txt")).expect("unknown entry remains"),
        b"unrelated"
    );
}

fn write_legacy_feedback(directory: &Path) {
    fs::write(
        directory.join("lab-feedback.jsonl"),
        concat!(
            r#"{"label":"normal","features":{"latency_mean":20.0,"latency_p95":30.0,"jitter_std":2.0,"loss_rate":0.0,"retrans_rate":0.0,"timeout":0.0,"retry":0.0,"throughput":100.0,"dns_events":0.0,"tls_events":0.0,"quic":0.0}}"#,
            "\n"
        ),
    )
    .expect("legacy feedback export");
}

#[test]
fn explicit_migration_rejects_arbitrary_nonempty_directories() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    fs::write(root.path().join("notes.txt"), b"not a product artifact").expect("unknown file");

    let error = migrate_legacy_artifact_root(root.path())
        .expect_err("an arbitrary directory must never be claimed");

    assert!(error.to_string().contains("unsupported entry"), "{error}");
    assert!(!root.path().join(OWNERSHIP_FILE_NAME).exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn owned_history_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("temporary artifact root");
    ensure_artifact_root_owned(root.path()).expect("claim artifact root");
    fs::create_dir_all(root.path().join("runs/run-1")).expect("run directory");
    fs::write(
        root.path().join("runs/run-1/manifest.json"),
        br#"{"run_id":"run-1"}"#,
    )
    .expect("run manifest");
    fs::write(root.path().join("run_index.json"), b"[]").expect("run index");
    root
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_no_clear_tombstones(root: &Path) {
    let tombstones = fs::read_dir(root)
        .expect("artifact root entries")
        .map(|entry| entry.expect("artifact root entry").file_name())
        .filter(|name| name.to_string_lossy().starts_with(".netdiag-clear-"))
        .collect::<Vec<_>>();
    assert!(
        tombstones.is_empty(),
        "clear tombstones leaked: {tombstones:?}"
    );
}
