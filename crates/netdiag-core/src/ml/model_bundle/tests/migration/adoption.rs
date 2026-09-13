use super::*;

#[test]
fn explicit_migration_preserves_legacy_bytes_and_training_metadata_idempotently() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("existing-training-data");
    let (mut model_bytes, _) = write_legacy_v1_bundle(&model_dir, &model, &manifest);
    model_bytes.extend_from_slice(b"\n \n");
    std::fs::write(model_dir.join(crate::ml::MODEL_FILE_NAME), &model_bytes)
        .expect("noncanonical legacy model bytes");
    save_json_atomic(
        model_dir.join(crate::ml::MODEL_PROMOTION_GATE_FILE_NAME),
        &serde_json::json!({"passed": true}),
    )
    .expect("legacy promotion evidence");
    load_existing_model_bundle_snapshot(&model_dir).expect_err("runtime must reject v1");

    let identity = crate::ml::migrate_legacy_model_bundle(&model_dir).expect("explicit migration");
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("migrated runtime model");
    assert_eq!(current.model_file_bytes.as_ref(), model_bytes.as_slice());
    let mut expected_manifest = manifest;
    expected_manifest.model_file_hash_sha256 = identity.model_file_hash_sha256.clone();
    assert_eq!(
        serde_json::to_value(&current.manifest).expect("current metadata"),
        serde_json::to_value(expected_manifest).expect("original training metadata"),
    );
    assert!(
        !model_dir
            .join(crate::ml::MODEL_PROMOTION_GATE_FILE_NAME)
            .exists()
    );
    assert_eq!(generation_count(&model_dir), 2);

    let pointer =
        std::fs::read(model_dir.join(crate::ml::MODEL_CURRENT_FILE_NAME)).expect("pointer");
    let again = crate::ml::migrate_legacy_model_bundle(&model_dir).expect("idempotent migration");
    assert_eq!(again.generation, identity.generation);
    assert_eq!(
        again.model_manifest_hash_sha256,
        identity.model_manifest_hash_sha256
    );
    assert_eq!(generation_count(&model_dir), 2);
    assert_eq!(
        std::fs::read(model_dir.join(crate::ml::MODEL_CURRENT_FILE_NAME))
            .expect("unchanged pointer"),
        pointer,
    );
}

#[test]
fn explicit_migration_rejects_corrupt_missing_or_ambiguous_sources_without_publication() {
    for failure in ["model", "manifest", "missing", "unexpected"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_dir = temp.path().join("model");
        let (model, manifest) = test_bundle("legacy-data");
        write_legacy_v1_bundle(&model_dir, &model, &manifest);
        let model_path = model_dir.join(crate::ml::MODEL_FILE_NAME);
        let manifest_path = model_dir.join(crate::ml::MODEL_MANIFEST_FILE_NAME);
        match failure {
            "model" => std::fs::write(&model_path, b"{").expect("corrupt model"),
            "manifest" => std::fs::write(&manifest_path, b"{").expect("corrupt manifest"),
            "missing" => std::fs::remove_file(&manifest_path).expect("incomplete bundle"),
            "unexpected" => {
                std::fs::write(model_dir.join("notes.txt"), b"keep").expect("unknown file")
            }
            _ => unreachable!(),
        }
        let before_model = std::fs::read(&model_path).expect("model bytes");
        let before_manifest = std::fs::read(&manifest_path).ok();
        crate::ml::migrate_legacy_model_bundle(&model_dir).expect_err("invalid migration source");
        assert_eq!(
            std::fs::read(model_path).expect("unchanged model"),
            before_model
        );
        assert_eq!(std::fs::read(manifest_path).ok(), before_manifest);
        assert!(!model_dir.join(crate::ml::MODEL_CURRENT_FILE_NAME).exists());
        assert!(!generation_root(&model_dir).exists());
    }
}

#[test]
fn explicit_migration_adopts_a_valid_flat_v2_bundle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, mut manifest) = test_bundle("flat-v2-data");
    let (model_bytes, _) = write_legacy_v1_bundle(&model_dir, &model, &manifest);
    manifest.model_file_hash_sha256 =
        super::super::super::super::sha256_file(&model_dir.join(crate::ml::MODEL_FILE_NAME))
            .expect("legacy hash");
    save_json_atomic(
        model_dir.join(crate::ml::MODEL_MANIFEST_FILE_NAME),
        &manifest,
    )
    .expect("valid v2 manifest");

    let identity = crate::ml::migrate_legacy_model_bundle(&model_dir).expect("v2 migration");
    assert!(identity.generation.is_some());
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("current bundle");
    assert_eq!(current.model_file_bytes.as_ref(), model_bytes.as_slice());
    assert_eq!(
        identity.model_file_hash_sha256,
        manifest.model_file_hash_sha256
    );
}

#[cfg(unix)]
#[test]
fn explicit_migration_rejects_a_shared_model_directory_without_changing_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("legacy-data");
    let (model_bytes, _) = write_legacy_v1_bundle(&model_dir, &model, &manifest);
    std::fs::set_permissions(&model_dir, std::fs::Permissions::from_mode(0o755))
        .expect("shared mode");

    crate::ml::migrate_legacy_model_bundle(&model_dir).expect_err("private directory required");
    assert_eq!(
        std::fs::metadata(&model_dir)
            .expect("directory")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::read(model_dir.join(crate::ml::MODEL_FILE_NAME)).expect("model"),
        model_bytes
    );
    assert!(!model_dir.join(crate::ml::MODEL_CURRENT_FILE_NAME).exists());
}
