use super::*;
use std::collections::BTreeSet;
use std::sync::Arc;

fn write_legacy_v1_bundle(
    model_dir: &Path,
    model: &RustMlModel,
    manifest: &ModelManifest,
) -> (Vec<u8>, Vec<u8>) {
    create_private_directory(model_dir);
    let model_path = model_dir.join(super::super::super::MODEL_FILE_NAME);
    let manifest_path = model_dir.join(super::super::super::MODEL_MANIFEST_FILE_NAME);
    save_json_atomic(&model_path, model).expect("legacy v1 model");
    let mut manifest = manifest.clone();
    manifest.schema_version = "netdiag-model-manifest/v1".to_string();
    manifest.model_file_hash_sha256.clear();
    save_json_atomic(&manifest_path, &manifest).expect("legacy v1 manifest");
    (
        std::fs::read(model_path).expect("legacy model bytes"),
        std::fs::read(manifest_path).expect("legacy manifest bytes"),
    )
}

#[test]
fn first_serialized_write_migrates_an_exact_v0_5_2_bundle_before_replacement() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (legacy_model, legacy_manifest) = test_bundle("v0.5.2-dataset");
    let (legacy_model_bytes, _) =
        write_legacy_v1_bundle(&model_dir, &legacy_model, &legacy_manifest);
    save_json_atomic(
        model_dir.join(super::super::super::MODEL_PROMOTION_GATE_FILE_NAME),
        &serde_json::json!({"schema": "netdiag-model-promotion-gate/v1", "passed": true}),
    )
    .expect("legacy promotion gate");
    load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("runtime loader must continue rejecting v1");
    let (replacement, replacement_manifest) = replacement_bundle(&legacy_model, "v0.5.3-dataset");

    write_model_bundle(&model_dir, &replacement, &replacement_manifest)
        .expect("serialized writer migration");

    assert!(
        model_dir
            .join(super::super::super::MODEL_CURRENT_FILE_NAME)
            .is_file()
    );
    assert!(
        !model_dir
            .join(super::super::super::MODEL_FILE_NAME)
            .exists()
    );
    assert!(
        !model_dir
            .join(super::super::super::MODEL_MANIFEST_FILE_NAME)
            .exists()
    );
    assert!(
        !model_dir
            .join(super::super::super::MODEL_PROMOTION_GATE_FILE_NAME)
            .exists()
    );
    assert_eq!(generation_count(&model_dir), 2);
    let mut migrated_legacy = false;
    for generation in std::fs::read_dir(generation_root(&model_dir)).expect("generations") {
        let generation = generation.expect("generation").path();
        let manifest: ModelManifest = serde_json::from_value(
            crate::storage::read_json(
                generation.join(super::super::super::MODEL_MANIFEST_FILE_NAME),
            )
            .expect("generation manifest"),
        )
        .expect("typed generation manifest");
        if manifest.dataset_hash_sha256.as_deref() == Some("v0.5.2-dataset") {
            assert_eq!(
                manifest.schema_version,
                super::super::super::MODEL_MANIFEST_SCHEMA
            );
            assert_eq!(
                manifest.model_file_hash_sha256,
                super::super::super::sha256_file(
                    &generation.join(super::super::super::MODEL_FILE_NAME),
                )
                .expect("bound legacy hash")
            );
            assert_eq!(
                std::fs::read(generation.join(super::super::super::MODEL_FILE_NAME))
                    .expect("migrated legacy model"),
                legacy_model_bytes
            );
            migrated_legacy = true;
        }
    }
    assert!(migrated_legacy, "the exact v1 model bytes must be retained");
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("v2 current bundle");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("v0.5.3-dataset")
    );
}

#[test]
fn interrupted_v1_pointer_publication_preserves_v1_and_retries_idempotently() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (legacy_model, legacy_manifest) = test_bundle("v0.5.2-dataset");
    let (model_bytes, manifest_bytes) =
        write_legacy_v1_bundle(&model_dir, &legacy_model, &legacy_manifest);
    let gate_path = model_dir.join(super::super::super::MODEL_PROMOTION_GATE_FILE_NAME);
    save_json_atomic(&gate_path, &serde_json::json!({"passed": true})).expect("legacy gate");
    let gate_bytes = std::fs::read(&gate_path).expect("legacy gate bytes");
    let (replacement, replacement_manifest) = replacement_bundle(&legacy_model, "v0.5.3-dataset");

    let error = with_model_bundle_lock(&model_dir, || {
        publish_locked_with(
            &model_dir,
            &replacement,
            &replacement_manifest,
            |path, _| Err(publish_error(path, AtomicPublishPhase::NotPublished)),
        )
    })
    .expect_err("pointer publication must fail");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert_eq!(
        std::fs::read(model_dir.join(super::super::super::MODEL_FILE_NAME))
            .expect("unchanged v1 model"),
        model_bytes
    );
    assert_eq!(
        std::fs::read(model_dir.join(super::super::super::MODEL_MANIFEST_FILE_NAME))
            .expect("unchanged v1 manifest"),
        manifest_bytes
    );
    assert_eq!(
        std::fs::read(&gate_path).expect("unchanged gate"),
        gate_bytes
    );
    assert!(
        !model_dir
            .join(super::super::super::MODEL_CURRENT_FILE_NAME)
            .exists()
    );
    assert_eq!(generation_count(&model_dir), 2);
    load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("runtime loader still rejects preserved v1");

    write_model_bundle(&model_dir, &replacement, &replacement_manifest).expect("idempotent retry");

    assert_eq!(generation_count(&model_dir), 2);
    assert!(
        !model_dir
            .join(super::super::super::MODEL_FILE_NAME)
            .exists()
    );
    assert!(!gate_path.exists());
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("recovered v2 bundle");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("v0.5.3-dataset")
    );
}

#[test]
fn uncertain_but_written_v1_pointer_is_recoverable_without_deleting_the_source() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (legacy_model, legacy_manifest) = test_bundle("v0.5.2-dataset");
    let (model_bytes, manifest_bytes) =
        write_legacy_v1_bundle(&model_dir, &legacy_model, &legacy_manifest);
    let gate_path = model_dir.join(super::super::super::MODEL_PROMOTION_GATE_FILE_NAME);
    save_json_atomic(&gate_path, &serde_json::json!({"passed": true})).expect("legacy gate");
    let gate_bytes = std::fs::read(&gate_path).expect("legacy gate bytes");
    let (replacement, replacement_manifest) = replacement_bundle(&legacy_model, "v0.5.3-dataset");

    let error = with_model_bundle_lock(&model_dir, || {
        publish_locked_with(
            &model_dir,
            &replacement,
            &replacement_manifest,
            |path, descriptor| {
                save_json_atomic(path, descriptor)?;
                Err(publish_error(
                    path,
                    AtomicPublishPhase::PublishedButDurabilityUncertain,
                ))
            },
        )
    })
    .expect_err("durability uncertainty must be explicit");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::PublishedButDurabilityUncertain)
    );
    assert_eq!(
        std::fs::read(model_dir.join(super::super::super::MODEL_FILE_NAME))
            .expect("preserved v1 model"),
        model_bytes
    );
    assert_eq!(
        std::fs::read(model_dir.join(super::super::super::MODEL_MANIFEST_FILE_NAME))
            .expect("preserved v1 manifest"),
        manifest_bytes
    );
    assert_eq!(
        std::fs::read(&gate_path).expect("preserved gate"),
        gate_bytes
    );
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("written v2 pointer");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("v0.5.3-dataset")
    );

    let (next, next_manifest) = replacement_bundle(&legacy_model, "next-dataset");
    write_model_bundle(&model_dir, &next, &next_manifest).expect("deterministic recovery write");

    assert!(
        !model_dir
            .join(super::super::super::MODEL_FILE_NAME)
            .exists()
    );
    assert!(
        !model_dir
            .join(super::super::super::MODEL_MANIFEST_FILE_NAME)
            .exists()
    );
    assert!(!gate_path.exists());
    assert_eq!(generation_count(&model_dir), 2);
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("recovered current");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("next-dataset")
    );
}

#[test]
fn v1_migration_rejects_corrupt_or_ambiguous_sources_before_staging() {
    for corruption in ["model", "extra", "gate"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_dir = temp.path().join("model");
        let (legacy_model, legacy_manifest) = test_bundle("v0.5.2-dataset");
        let (replacement, replacement_manifest) =
            replacement_bundle(&legacy_model, "v0.5.3-dataset");
        write_legacy_v1_bundle(&model_dir, &legacy_model, &legacy_manifest);
        match corruption {
            "model" => std::fs::write(
                model_dir.join(super::super::super::MODEL_FILE_NAME),
                br#"{"invalid":true}"#,
            )
            .expect("corrupt model"),
            "extra" => {
                std::fs::write(model_dir.join("notes.txt"), b"ambiguous").expect("extra entry")
            }
            "gate" => std::fs::write(
                model_dir.join(super::super::super::MODEL_PROMOTION_GATE_FILE_NAME),
                b"not-json",
            )
            .expect("corrupt gate"),
            _ => unreachable!(),
        }
        let before = std::fs::read_dir(&model_dir)
            .expect("legacy entries")
            .map(|entry| entry.expect("legacy entry").file_name())
            .collect::<BTreeSet<_>>();

        let error = write_model_bundle(&model_dir, &replacement, &replacement_manifest)
            .expect_err("invalid v1 source must fail before staging");

        assert!(
            !model_dir
                .join(super::super::super::MODEL_CURRENT_FILE_NAME)
                .exists()
        );
        assert!(!generation_root(&model_dir).exists());
        let after = std::fs::read_dir(&model_dir)
            .expect("unchanged legacy entries")
            .map(|entry| entry.expect("legacy entry").file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(after, before, "{corruption}: {error}");
    }
}

#[test]
fn concurrent_v1_writers_serialize_into_valid_v2_generations() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (legacy_model, legacy_manifest) = test_bundle("v0.5.2-dataset");
    write_legacy_v1_bundle(&model_dir, &legacy_model, &legacy_manifest);
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let mut writers = Vec::new();
    for dataset in ["concurrent-a", "concurrent-b"] {
        let model_dir = model_dir.clone();
        let barrier = Arc::clone(&barrier);
        let (model, manifest) = replacement_bundle(&legacy_model, dataset);
        writers.push(std::thread::spawn(move || {
            barrier.wait();
            write_model_bundle(&model_dir, &model, &manifest)
        }));
    }
    barrier.wait();

    for writer in writers {
        writer
            .join()
            .expect("writer thread")
            .expect("writer result");
    }

    assert!(
        !model_dir
            .join(super::super::super::MODEL_FILE_NAME)
            .exists()
    );
    assert_eq!(generation_count(&model_dir), 2);
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("concurrent current");
    assert!(matches!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("concurrent-a" | "concurrent-b")
    ));
}
