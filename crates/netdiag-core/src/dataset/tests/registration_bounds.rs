use super::super::*;
use chrono::Utc;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[cfg(unix)]
#[test]
fn newly_created_dataset_root_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = write_source(temp.path());
    let registration = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts: temp.path().join("artifacts"),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("private-root".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
    )
    .expect("registration");
    let dataset_root = Path::new(&registration.dataset_path)
        .parent()
        .expect("dataset root");

    assert_eq!(
        std::fs::metadata(dataset_root)
            .expect("dataset root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
}

#[cfg(target_os = "linux")]
#[test]
fn unsafe_default_acl_is_rejected_before_dataset_directory_creation() {
    use rustix::fs::{XattrFlags, setxattr};

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = write_source(temp.path());
    let artifacts = temp.path().join("artifacts");
    std::fs::create_dir(&artifacts).expect("artifacts directory");
    setxattr(
        &artifacts,
        "system.posix_acl_default",
        &base_default_acl(),
        XattrFlags::empty(),
    )
    .expect("set default ACL fixture");

    let error = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts: artifacts.clone(),
            metadata: DatasetManifestMetadata {
                dataset_id: Some("unsafe-default-acl".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
    )
    .expect_err("inheritable ACL must fail before staging");

    assert!(
        error.to_string().contains("inheritable POSIX default ACL"),
        "{error}"
    );
    assert!(
        !artifacts.join("datasets").exists(),
        "trust rejection must not create the dataset hierarchy"
    );
}

#[cfg(target_os = "linux")]
fn base_default_acl() -> Vec<u8> {
    const ACL_UNDEFINED_ID: u32 = u32::MAX;
    let mut acl = 2_u32.to_le_bytes().to_vec();
    for (tag, permissions) in [(0x01_u16, 0x07_u16), (0x04, 0x07), (0x20, 0x00)] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permissions.to_le_bytes());
        acl.extend_from_slice(&ACL_UNDEFINED_ID.to_le_bytes());
    }
    acl
}

#[cfg(unix)]
#[test]
fn symlinked_artifacts_ancestor_is_rejected_before_staging_side_effects() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = write_source(temp.path());
    let outside = temp.path().join("outside");
    let artifacts = temp.path().join("artifacts-link");
    std::fs::create_dir(&outside).expect("outside directory");
    symlink(&outside, &artifacts).expect("artifacts symlink");

    let error = register_dataset_jsonl(
        &dataset,
        DatasetRegisterOptions {
            artifacts,
            metadata: DatasetManifestMetadata {
                dataset_id: Some("ancestor-symlink".to_string()),
                ..DatasetManifestMetadata::default()
            },
        },
    )
    .expect_err("an untrusted artifacts ancestor must fail before staging");

    assert!(error.to_string().contains("untrusted symlink"), "{error}");
    assert!(!outside.join("datasets").exists());
    assert_eq!(
        std::fs::read_dir(&outside)
            .expect("outside directory")
            .count(),
        0,
        "lock rejection must not create directories or files through the symlink"
    );
}

#[test]
fn oversized_exact_registry_does_not_publish_or_accumulate_dependencies() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = write_source(temp.path());
    let artifacts = temp.path().join("artifacts");
    let registry_path = artifacts.join("datasets/registry.json");
    let mut registry = DatasetRegistry {
        schema: "netdiag-dataset-registry/v1".to_string(),
        generated_at: Utc::now(),
        datasets: vec![registry_entry()],
    };
    let empty_bytes = serde_json::to_vec_pretty(&registry).expect("empty registry fixture");
    let byte_limit = usize::try_from(crate::storage::typed_json::MAX_DATASET_REGISTRY_BYTES)
        .expect("registry byte limit fits usize");
    let padding = byte_limit
        .checked_sub(empty_bytes.len() + 1)
        .expect("registry fixture has room for padding");
    registry.datasets[0].source_runs = vec!["x".repeat(padding)];
    let original_registry = serde_json::to_vec_pretty(&registry).expect("registry fixture");
    assert_eq!(original_registry.len(), byte_limit - 1);
    crate::storage::ensure_artifact_root_owned(&artifacts).expect("owned artifacts root");
    crate::storage::typed_json::save_json_atomic_bounded(
        &registry_path,
        &registry,
        crate::storage::typed_json::MAX_DATASET_REGISTRY_BYTES,
        "dataset registry",
    )
    .expect("bounded existing registry");

    assert_repeated_preflight_failure(
        &dataset,
        &artifacts,
        DatasetManifestMetadata {
            dataset_id: Some("oversized-registry".to_string()),
            ..DatasetManifestMetadata::default()
        },
        "serialized dataset registry exceeds",
    );
    assert_eq!(
        std::fs::read(&registry_path).expect("registry after retries"),
        original_registry
    );
}

#[test]
fn oversized_manifest_does_not_publish_or_accumulate_dependencies() {
    let temp = tempfile::tempdir().expect("tempdir");
    let dataset = write_source(temp.path());
    let artifacts = temp.path().join("artifacts");
    let oversized_notes = "x".repeat(
        usize::try_from(crate::storage::typed_json::MAX_DATASET_MANIFEST_BYTES)
            .expect("manifest byte limit fits usize"),
    );

    assert_repeated_preflight_failure(
        &dataset,
        &artifacts,
        DatasetManifestMetadata {
            dataset_id: Some("oversized-manifest".to_string()),
            notes: Some(oversized_notes),
            ..DatasetManifestMetadata::default()
        },
        "serialized dataset manifest exceeds",
    );
    assert!(!artifacts.join("datasets/registry.json").exists());
}

fn assert_repeated_preflight_failure(
    dataset: &Path,
    artifacts: &Path,
    metadata: DatasetManifestMetadata,
    expected_error: &str,
) {
    let dataset_id = metadata.dataset_id.as_deref().expect("fixture dataset id");
    let datasets_root = artifacts.join("datasets").join(dataset_id);
    for attempt in 1..=2 {
        let error = register_dataset_jsonl(
            dataset,
            DatasetRegisterOptions {
                artifacts: artifacts.to_path_buf(),
                metadata: metadata.clone(),
            },
        )
        .expect_err("oversized metadata must fail before immutable publication");
        assert!(
            error.to_string().contains(expected_error),
            "attempt {attempt}: {error}"
        );
        let remaining = std::fs::read_dir(&datasets_root)
            .expect("dataset staging directory")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("dataset staging entries");
        assert!(
            remaining.is_empty(),
            "attempt {attempt} left unpublished dataset or manifest dependencies"
        );
    }
}

fn registry_entry() -> DatasetRegistryEntry {
    DatasetRegistryEntry {
        dataset_id: "existing-dataset".to_string(),
        hash_sha256: "a".repeat(64),
        rows: 1,
        label_distribution: BTreeMap::from([("normal".to_string(), 1)]),
        dataset_path: "datasets/existing.jsonl".to_string(),
        manifest_path: "datasets/existing-manifest.json".to_string(),
        registered_at: Utc::now(),
        source_runs: vec![String::new()],
        scenario_ids: Vec::new(),
        operator: None,
        label_policy: None,
        min_rows_per_label: None,
    }
}

fn write_source(root: &Path) -> PathBuf {
    let dataset = root.join("feedback.jsonl");
    std::fs::write(
        &dataset,
        serde_json::json!({
            "label": "normal",
            "features": super::feature_payload(10.0)
        })
        .to_string(),
    )
    .expect("write source");
    dataset
}
