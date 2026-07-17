use super::super::*;
use super::feature_payload;
use crate::storage::BoundAtomicFileTarget;

#[test]
fn dataset_register_compare_and_min_label_gate() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    let normal = serde_json::json!({
        "label": "normal",
        "features": feature_payload(10.0)
    });
    let congestion = serde_json::json!({
        "label": "congestion",
        "features": feature_payload(200.0)
    });
    std::fs::write(&dataset, format!("\n{normal}\n \n{congestion}\n")).expect("write dataset");

    let report = validate_dataset_jsonl_with_options(
        &dataset,
        DatasetValidationOptions {
            min_rows_per_label: 1,
        },
    )
    .expect("validation report");
    assert!(!report.passed);
    assert!(
        report
            .failures
            .iter()
            .any(|failure| failure.contains("random_loss")),
        "{:?}",
        report.failures
    );

    let registration = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts: temp.path().join("artifacts"),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("lab-feedback-test".to_string()),
                source_runs: vec!["run-a".to_string()],
                scenario_ids: vec!["lab-congestion-001".to_string()],
                operator: Some("lab-operator".to_string()),
                label_policy: Some("hil_final_label_required".to_string()),
                min_rows_per_label: Some(1),
                notes: Some("test dataset".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
    )
    .expect("register dataset");
    assert!(PathBuf::from(&registration.dataset_path).exists());
    assert!(PathBuf::from(&registration.registry_path).exists());
    assert_eq!(registration.manifest.rows, 2);
    assert_eq!(
        registration.manifest.label_distribution,
        BTreeMap::from([("congestion".to_string(), 1), ("normal".to_string(), 1)])
    );
    assert_eq!(registration.manifest.source_runs, vec!["run-a"]);
    assert_eq!(
        std::fs::read(&dataset).expect("source dataset"),
        std::fs::read(&registration.dataset_path).expect("registered dataset")
    );
    assert_eq!(
        registration.manifest.hash_sha256,
        crate::storage::sha256_stable_regular_file_bounded(
            Path::new(&registration.dataset_path),
            limits::MAX_INPUT_BYTES,
        )
        .expect("registered hash read")
        .expect("registered hash")
    );

    let comparison =
        compare_datasets(&dataset, &registration.manifest_path).expect("compare datasets");
    assert!(comparison.same_hash);
    assert_eq!(comparison.row_delta, 0);

    let case_conflict = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts: temp.path().join("artifacts"),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("LAB-FEEDBACK-TEST".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
    )
    .expect_err("case-insensitive dataset id collision must fail");
    assert!(case_conflict.to_string().contains("case-insensitive"));

    std::fs::write(&registration.dataset_path, b"corrupt").expect("corrupt registered dataset");
    let corrupt = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts: temp.path().join("artifacts"),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("lab-feedback-test".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
    )
    .expect_err("corrupt registered dataset must fail");
    assert!(corrupt.to_string().contains("hash mismatch"));
}

#[test]
fn concurrent_dataset_registrations_preserve_both_registry_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    let datasets = [("first", 10.0), ("second", 20.0)].map(|(id, latency_ms)| {
        let path = temp.path().join(format!("{id}.jsonl"));
        std::fs::write(
            &path,
            serde_json::json!({
                "label": "normal",
                "features": feature_payload(latency_ms)
            })
            .to_string(),
        )
        .expect("dataset");
        (id.to_string(), path)
    });
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles = datasets.map(|(id, dataset)| {
        let artifacts = artifacts.clone();
        let barrier = std::sync::Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            register_dataset_jsonl(
                dataset,
                DatasetRegisterOptions {
                    artifacts,
                    metadata: DatasetManifestMetadata {
                        dataset_id: Some(id),
                        ..DatasetManifestMetadata::default()
                    },
                },
            )
        })
    });
    for handle in handles {
        handle
            .join()
            .expect("registration thread")
            .expect("registration");
    }

    let registry =
        read_dataset_registry(&artifacts.join("datasets/registry.json")).expect("dataset registry");
    assert_eq!(registry.datasets.len(), 2);
    assert_eq!(
        registry
            .datasets
            .iter()
            .map(|entry| entry.dataset_id.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from(["first", "second"])
    );
}

#[test]
fn dataset_registration_does_not_overwrite_immutable_manifest_metadata() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write dataset");
    let artifacts = temp.path().join("artifacts");
    let metadata = |notes: &str| DatasetManifestMetadata {
        dataset_id: Some("immutable-feedback".to_string()),
        notes: Some(notes.to_string()),
        ..DatasetManifestMetadata::default()
    };
    let first = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts: artifacts.clone(),
            metadata: metadata("first registration"),
        },
    )
    .expect("first registration");
    let original_manifest = std::fs::read(&first.manifest_path).expect("original manifest");
    let original_registry = std::fs::read(&first.registry_path).expect("original registry");
    std::fs::remove_file(&first.dataset_path).expect("remove registered copy to exercise rollback");
    let dataset_directory = Path::new(&first.dataset_path)
        .parent()
        .expect("dataset parent");
    let original_entries = std::fs::read_dir(dataset_directory)
        .expect("dataset directory before conflict")
        .map(|entry| entry.expect("dataset entry before conflict").file_name())
        .collect::<std::collections::BTreeSet<_>>();

    let error = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts,
            metadata: metadata("conflicting metadata"),
        },
    )
    .expect_err("hash-addressed manifest metadata must be immutable");

    assert!(error.to_string().contains("immutable artifact"), "{error}");
    assert_eq!(
        std::fs::read(&first.manifest_path).expect("manifest after conflict"),
        original_manifest
    );
    assert_eq!(
        std::fs::read(&first.registry_path).expect("registry after conflict"),
        original_registry
    );
    assert!(
        !Path::new(&first.dataset_path).exists(),
        "new dataset copy was not rolled back after manifest conflict"
    );
    let final_entries = std::fs::read_dir(dataset_directory)
        .expect("dataset directory after conflict")
        .map(|entry| entry.expect("dataset entry after conflict").file_name())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        final_entries, original_entries,
        "manifest conflict left a new immutable or staging artifact"
    );
}

#[test]
fn dataset_registration_rolls_back_dependencies_when_registry_was_not_published() {
    use crate::error::AtomicPublishPhase;

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write source");
    let artifacts = temp.path().join("artifacts");
    let datasets_root = artifacts.join("datasets/not-published-feedback");

    let error = registration::register_with_registry_publisher(
        &dataset,
        DatasetRegisterOptions {
            artifacts: artifacts.clone(),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("not-published-feedback".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
        |registry_path, _registry| {
            Err(NetdiagError::AtomicPublish {
                path: registry_path.to_path_buf(),
                phase: AtomicPublishPhase::NotPublished,
                source: Box::new(NetdiagError::Io {
                    path: registry_path.to_path_buf(),
                    source: std::io::Error::other("injected pre-publish failure"),
                }),
            })
        },
    )
    .expect_err("a registry that was not published must fail registration");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!artifacts.join("datasets/registry.json").exists());
    let remaining = std::fs::read_dir(&datasets_root)
        .expect("dataset directory")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("dataset directory entries");
    assert!(
        remaining.is_empty(),
        "unreferenced dataset dependencies were not rolled back"
    );
}

#[test]
fn dataset_registration_preserves_dependencies_when_registry_publish_is_indeterminate() {
    use crate::error::AtomicPublishPhase;

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write source");
    let artifacts = temp.path().join("artifacts");
    let options = DatasetRegisterOptions {
        artifacts: artifacts.clone(),
        metadata: DatasetManifestMetadata {
            dataset_id: Some("indeterminate-feedback".to_string()),
            ..DatasetManifestMetadata::default()
        },
    };

    let error = registration::register_with_registry_publisher(
        &dataset,
        options.clone(),
        |registry_path, registry| {
            crate::storage::save_json(registry_path, registry)?;
            Err(NetdiagError::AtomicPublish {
                path: registry_path.to_path_buf(),
                phase: AtomicPublishPhase::PublishedButDurabilityUncertain,
                source: Box::new(NetdiagError::Io {
                    path: registry_path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .to_path_buf(),
                    source: std::io::Error::other("injected post-rename directory sync failure"),
                }),
            })
        },
    )
    .expect_err("indeterminate registry durability must be reported");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::PublishedButDurabilityUncertain)
    );
    assert!(
        error
            .to_string()
            .contains("published but durability is uncertain"),
        "{error}"
    );
    let registry_path = artifacts.join("datasets/registry.json");
    let published_registry = read_dataset_registry(&registry_path).expect("published registry");
    assert_eq!(published_registry.datasets.len(), 1);
    let published_entry = &published_registry.datasets[0];
    assert!(Path::new(&published_entry.dataset_path).is_file());
    assert!(Path::new(&published_entry.manifest_path).is_file());

    let recovered = register_dataset_jsonl(&dataset, options)
        .expect("the next locked registration must observe a consistent registry");
    assert_eq!(recovered.dataset_path, published_entry.dataset_path);
    assert_eq!(recovered.manifest_path, published_entry.manifest_path);
    let recovered_registry = read_dataset_registry(&registry_path).expect("recovered registry");
    assert_eq!(recovered_registry.datasets.len(), 1);
    assert_eq!(
        recovered_registry.datasets[0].hash_sha256,
        recovered.manifest.hash_sha256
    );
}

#[test]
fn unclassified_registry_failure_is_typed_and_preserves_dependencies() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write source");
    let artifacts = temp.path().join("artifacts");
    let datasets_root = artifacts.join("datasets/unclassified-feedback");
    let registry_path = artifacts.join("datasets/registry.json");
    crate::storage::ensure_artifact_root_owned(&artifacts).expect("owned artifacts root");
    let resolved_registry_path = BoundAtomicFileTarget::bind(&registry_path)
        .expect("bound registry target")
        .resolved_path()
        .to_path_buf();

    let error = registration::register_with_registry_publisher(
        &dataset,
        DatasetRegisterOptions {
            artifacts: artifacts.clone(),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("unclassified-feedback".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
        |path, _registry| {
            Err(NetdiagError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::other("injected unclassified publication failure"),
            })
        },
    )
    .expect_err("unclassified registry failure must fail closed");

    let NetdiagError::PublicationStateIndeterminate { path, source } = error else {
        panic!("expected typed indeterminate publication state");
    };
    assert_eq!(path, resolved_registry_path);
    assert!(matches!(
        source.as_ref(),
        NetdiagError::Io { path, source }
            if path == &resolved_registry_path
                && source.to_string() == "injected unclassified publication failure"
    ));
    assert!(!registry_path.exists());
    let preserved = std::fs::read_dir(&datasets_root)
        .expect("dataset directory")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("dataset entries");
    assert_eq!(
        preserved.len(),
        2,
        "immutable dependencies must be preserved"
    );
}

#[test]
fn wrong_target_registry_failure_is_indeterminate_and_preserves_dependencies() {
    use crate::error::AtomicPublishPhase;

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write source");
    let artifacts = temp.path().join("artifacts");
    let datasets_root = artifacts.join("datasets/wrong-target-feedback");
    let registry_path = artifacts.join("datasets/registry.json");
    crate::storage::ensure_artifact_root_owned(&artifacts).expect("owned artifacts root");
    let expected_registry_path = BoundAtomicFileTarget::bind(&registry_path)
        .expect("bound registry target")
        .resolved_path()
        .to_path_buf();
    let wrong_path = artifacts.join("datasets/not-the-registry.json");

    let error = registration::register_with_registry_publisher(
        &dataset,
        DatasetRegisterOptions {
            artifacts: artifacts.clone(),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("wrong-target-feedback".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
        |_registry_path, _registry| {
            Err(NetdiagError::AtomicPublish {
                path: wrong_path.clone(),
                phase: AtomicPublishPhase::NotPublished,
                source: Box::new(NetdiagError::Io {
                    path: wrong_path.clone(),
                    source: std::io::Error::other("injected wrong-target publication failure"),
                }),
            })
        },
    )
    .expect_err("a publication phase for another path must not authorize rollback");

    let NetdiagError::PublicationStateIndeterminate { path, source } = error else {
        panic!("expected typed indeterminate publication state");
    };
    assert_eq!(path, expected_registry_path);
    assert!(matches!(
        source.as_ref(),
        NetdiagError::AtomicPublish {
            path,
            phase: AtomicPublishPhase::NotPublished,
            source,
        } if path == &wrong_path
            && matches!(source.as_ref(), NetdiagError::Io { path, source }
                if path == &wrong_path
                    && source.to_string() == "injected wrong-target publication failure")
    ));
    assert!(!registry_path.exists());
    let preserved = std::fs::read_dir(&datasets_root)
        .expect("dataset directory")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("dataset entries");
    assert_eq!(
        preserved.len(),
        2,
        "wrong-target classification must preserve immutable dependencies"
    );
}

#[cfg(unix)]
#[test]
fn dataset_registration_rejects_concurrent_source_replacement_and_cleans_staging() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    let replacement = temp.path().join("replacement.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write source");
    std::fs::write(
        &replacement,
        serde_json::json!({
            "label": "congestion",
            "features": feature_payload(200.0)
        })
        .to_string(),
    )
    .expect("write replacement");
    let artifacts = temp.path().join("artifacts");
    let datasets_root = artifacts.join("datasets/concurrent-feedback");

    let error = registration::register_with_source_hooks(
        &dataset,
        DatasetRegisterOptions {
            artifacts: artifacts.clone(),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("concurrent-feedback".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
        || std::fs::rename(&replacement, &dataset).expect("replace source atomically"),
        || {},
    )
    .expect_err("source replacement during capture must fail closed");

    assert!(error.to_string().contains("changed while"), "{error}");
    assert!(!artifacts.join("datasets/registry.json").exists());
    let remaining = std::fs::read_dir(&datasets_root)
        .expect("staging directory")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("read staging directory");
    assert!(remaining.is_empty(), "staging files were not cleaned up");
}

#[test]
fn dataset_registration_rejects_same_length_change_with_restored_mtime() {
    use std::fs::{FileTimes, OpenOptions};
    use std::io::Write;

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    let original = serde_json::json!({
        "label": "normal",
        "features": feature_payload(10.0)
    })
    .to_string()
    .into_bytes();
    std::fs::write(&dataset, &original).expect("write source");
    let original_mtime = std::fs::metadata(&dataset)
        .and_then(|metadata| metadata.modified())
        .expect("source mtime");
    let artifacts = temp.path().join("artifacts");
    let datasets_root = artifacts.join("datasets/coarse-mtime-feedback");
    let changed = vec![b'X'; original.len()];

    let error = registration::register_with_source_hooks(
        &dataset,
        DatasetRegisterOptions {
            artifacts: artifacts.clone(),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("coarse-mtime-feedback".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
        || {},
        || {
            let mut source = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&dataset)
                .expect("open source for deterministic mutation");
            source.write_all(&changed).expect("replace source bytes");
            source.sync_all().expect("sync replacement bytes");
            source
                .set_times(FileTimes::new().set_modified(original_mtime))
                .expect("restore source mtime");
            source.sync_all().expect("sync restored source mtime");
            let metadata = source.metadata().expect("mutated source metadata");
            assert_eq!(metadata.len(), original.len() as u64);
            assert_eq!(
                metadata.modified().expect("mutated source mtime"),
                original_mtime
            );
        },
    )
    .expect_err("same-length content change with restored mtime must fail closed");

    assert!(error.to_string().contains("content changed"), "{error}");
    assert!(!artifacts.join("datasets/registry.json").exists());
    let remaining = std::fs::read_dir(&datasets_root)
        .expect("staging directory")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("read staging directory");
    assert!(remaining.is_empty(), "staging files were not cleaned up");
}

#[cfg(unix)]
#[test]
fn dataset_registration_rejects_symlink_sources() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target.jsonl");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &target,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write target");
    symlink(&target, &dataset).expect("create dataset symlink");

    let error = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts: temp.path().join("artifacts"),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("symlink-feedback".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
    )
    .expect_err("symlink source must fail closed");

    assert!(
        error.to_string().contains("regular, non-symlink"),
        "{error}"
    );
}

#[cfg(unix)]
#[test]
fn dataset_registration_rejects_symlink_replacing_existing_snapshot() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write source");
    let artifacts = temp.path().join("artifacts");
    let options = || DatasetRegisterOptions {
        artifacts: artifacts.clone(),
        metadata: DatasetManifestMetadata {
            dataset_id: Some("immutable-symlink-feedback".to_string()),
            ..DatasetManifestMetadata::default()
        },
    };
    let registration = register_dataset_jsonl(&dataset, options()).expect("first registration");
    let registered_path = PathBuf::from(&registration.dataset_path);
    std::fs::remove_file(&registered_path).expect("remove registered snapshot");
    symlink(&dataset, &registered_path).expect("replace snapshot with symlink");

    let error = register_dataset_jsonl(&dataset, options())
        .expect_err("a symlinked immutable snapshot must fail closed");

    assert!(
        error.to_string().contains("symlink/reparse point"),
        "{error}"
    );
}

#[test]
fn dataset_registration_rejects_non_portable_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = temp.path().join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write dataset");

    for id in [
        "../outside",
        "nested/path",
        r"nested\path",
        ".hidden",
        "tail.",
    ] {
        let error = register_dataset_jsonl(
            &dataset,
            DatasetRegisterOptions {
                artifacts: temp.path().join("artifacts"),
                metadata: DatasetManifestMetadata {
                    dataset_id: Some(id.to_string()),
                    ..DatasetManifestMetadata::default()
                },
            },
        )
        .expect_err("unsafe dataset id must fail");
        assert!(error.to_string().contains("dataset id"), "{id:?}: {error}");
    }
}

#[test]
fn dataset_registry_rejects_corruption_instead_of_resetting_state() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry = temp.path().join("registry.json");
    std::fs::write(&registry, b"{not-json").expect("corrupt registry");

    let error = read_dataset_registry(&registry).expect_err("corrupt registry must fail closed");

    assert!(error.to_string().contains("dataset registry"), "{error}");
    assert!(error.to_string().contains(&registry.display().to_string()));
}

#[test]
fn dataset_registry_rejects_more_than_the_publication_limit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("registry.json");
    let entry = DatasetRegistryEntry {
        dataset_id: "bounded-dataset".to_string(),
        hash_sha256: "a".repeat(64),
        rows: 1,
        label_distribution: BTreeMap::from([("normal".to_string(), 1)]),
        dataset_path: "datasets/bounded.jsonl".to_string(),
        manifest_path: "datasets/bounded.manifest.json".to_string(),
        registered_at: Utc::now(),
        source_runs: Vec::new(),
        scenario_ids: Vec::new(),
        operator: None,
        label_policy: None,
        min_rows_per_label: None,
    };
    let registry = DatasetRegistry {
        schema: "netdiag-dataset-registry/v1".to_string(),
        generated_at: Utc::now(),
        datasets: vec![entry; crate::storage::typed_json::MAX_DATASET_REGISTRY_ENTRIES + 1],
    };
    crate::storage::save_json_atomic(&registry_path, &registry)
        .expect("oversized registry fixture");

    let error = read_dataset_registry(&registry_path)
        .expect_err("registry entry count must be bounded before retention");

    assert!(error.to_string().contains("201 entries"), "{error}");
}
