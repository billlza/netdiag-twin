use super::*;

#[cfg(unix)]
#[test]
fn post_publish_trust_failure_reports_exact_durable_publication_state() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    create_private_directory(&model_dir);
    let (model_a, mut manifest_a) = test_bundle("legacy-dataset");
    let legacy_model = model_dir.join(crate::ml::MODEL_FILE_NAME);
    save_json_atomic(&legacy_model, &model_a).expect("legacy model");
    manifest_a.model_file_hash_sha256 = crate::ml::sha256_file(&legacy_model).expect("hash");
    save_json_atomic(
        model_dir.join(crate::ml::MODEL_MANIFEST_FILE_NAME),
        &manifest_a,
    )
    .expect("legacy manifest");
    let original_mode = std::fs::metadata(&model_dir)
        .expect("model metadata")
        .permissions()
        .mode();
    let (model_b, manifest_b) = replacement_bundle(&model_a, "new-dataset");

    let result = with_model_bundle_lock(&model_dir, || {
        publish_locked_with(&model_dir, &model_b, &manifest_b, |path, descriptor| {
            save_json_atomic(path, descriptor)?;
            std::fs::set_permissions(&model_dir, std::fs::Permissions::from_mode(0o755))
                .expect("make model directory non-private");
            Ok(())
        })
    });
    std::fs::set_permissions(&model_dir, std::fs::Permissions::from_mode(original_mode))
        .expect("restore model directory permissions");
    let error = result.expect_err("post-publication trust failure must be explicit");
    let resolved_model_dir = model_dir.canonicalize().expect("resolved model directory");

    let NetdiagError::AtomicPublish {
        path,
        phase,
        source,
    } = &error
    else {
        panic!("expected structured publication state: {error}");
    };
    assert_eq!(
        path,
        &resolved_model_dir.join(crate::ml::MODEL_CURRENT_FILE_NAME)
    );
    assert_eq!(*phase, AtomicPublishPhase::Published);
    let NetdiagError::CombinedFailure {
        primary_context,
        primary,
        secondary_context,
        secondary,
    } = source.as_ref()
    else {
        panic!("expected both post-publication trust failures: {source:?}");
    };
    assert_eq!(*primary_context, "model bundle operation failed");
    assert_eq!(
        *secondary_context,
        "model bundle directory post-operation validation also failed"
    );
    for trust_failure in [primary.as_ref(), secondary.as_ref()] {
        assert!(matches!(
            trust_failure,
            NetdiagError::PrivateDirectoryMode {
                context: "model bundle directory",
                path,
                expected: 0o700,
                actual: 0o755,
            } if path == &resolved_model_dir
        ));
    }
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("published generation");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("new-dataset")
    );
}

#[cfg(unix)]
#[test]
fn post_publish_legacy_cleanup_failure_keeps_typed_io_source() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    create_private_directory(&model_dir);
    let (model_a, mut manifest_a) = test_bundle("legacy-dataset");
    let legacy_model = model_dir.join(crate::ml::MODEL_FILE_NAME);
    let legacy_manifest = model_dir.join(crate::ml::MODEL_MANIFEST_FILE_NAME);
    let resolved_legacy_model = model_dir
        .canonicalize()
        .expect("resolved model directory")
        .join(crate::ml::MODEL_FILE_NAME);
    save_json_atomic(&legacy_model, &model_a).expect("legacy model");
    manifest_a.model_file_hash_sha256 = crate::ml::sha256_file(&legacy_model).expect("hash");
    save_json_atomic(&legacy_manifest, &manifest_a).expect("legacy manifest");
    let (model_b, manifest_b) = replacement_bundle(&model_a, "new-dataset");

    let error = with_model_bundle_lock(&model_dir, || {
        publish_locked_with(&model_dir, &model_b, &manifest_b, |path, descriptor| {
            save_json_atomic(path, descriptor)?;
            std::fs::remove_file(&legacy_model).expect("remove legacy model fixture");
            std::fs::create_dir(&legacy_model).expect("unremovable legacy path fixture");
            Ok(())
        })
    })
    .expect_err("legacy cleanup failure must be explicit");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::Published)
    );
    let expected_kind = if cfg!(target_os = "linux") {
        std::io::ErrorKind::IsADirectory
    } else {
        std::io::ErrorKind::PermissionDenied
    };
    assert!(
        contains_io_failure(&error, &resolved_legacy_model, expected_kind),
        "{error:?}"
    );
    std::fs::remove_dir(&legacy_model).expect("remove cleanup fixture");
    std::fs::remove_file(&legacy_manifest).expect("remove legacy manifest");
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("published generation");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("new-dataset")
    );
}

#[test]
fn model_trust_error_preserves_platform_source() {
    let path = Path::new("model-root").to_path_buf();
    let error = super::super::trust::trust_error(netdiag_platform::DirectoryTrustError::Inspect {
        path: path.clone(),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "inspect denied"),
    });

    assert!(matches!(
        error,
        NetdiagError::FilesystemTrust {
            context: "model bundle directory",
            source: netdiag_platform::DirectoryTrustError::Inspect {
                path: source_path,
                source,
            },
        } if source_path == path
            && source.kind() == std::io::ErrorKind::PermissionDenied
            && source.to_string() == "inspect denied"
    ));
}

#[cfg(not(unix))]
#[test]
fn unsupported_platform_rebuild_fails_before_creating_or_cleaning_model_paths() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");

    let error = crate::ml::rebuild_synthetic_model_bundle(&model_dir)
        .expect_err("unsupported publication must fail");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!model_dir.exists());
}

#[cfg(windows)]
#[test]
fn windows_can_read_a_complete_existing_legacy_v2_bundle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    create_private_directory(&model_dir);
    let (model, mut manifest) = test_bundle("legacy-dataset");
    let model_path = model_dir.join(crate::ml::MODEL_FILE_NAME);
    std::fs::write(
        &model_path,
        serde_json::to_vec_pretty(&model).expect("model JSON"),
    )
    .expect("legacy model");
    manifest.model_file_hash_sha256 = crate::ml::sha256_file(&model_path).expect("model hash");
    std::fs::write(
        model_dir.join(crate::ml::MODEL_MANIFEST_FILE_NAME),
        serde_json::to_vec_pretty(&manifest).expect("manifest JSON"),
    )
    .expect("legacy manifest");

    let snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("legacy bundle");

    assert_eq!(
        snapshot.manifest.dataset_hash_sha256.as_deref(),
        Some("legacy-dataset")
    );
}
