use super::layout::{CurrentDescriptor, generation_root, resolve_bundle_paths};
use super::publication::{MAX_GENERATION_ENTRIES, publish_locked_with};
use super::*;
use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::storage::save_json_atomic;

mod migration;
mod publication_failures;

fn test_bundle(dataset_hash: &str) -> (RustMlModel, ModelManifest) {
    let (model, mut manifest) = synthetic_model_bundle().expect("synthetic model");
    manifest.training_source = "generation-publication-test".to_string();
    manifest.dataset_hash_sha256 = Some(dataset_hash.to_string());
    manifest.synthetic_fallback = false;
    (model, manifest)
}

fn replacement_bundle(source: &RustMlModel, dataset_hash: &str) -> (RustMlModel, ModelManifest) {
    let mut model = source.clone();
    model.means[0] += 1.0;
    let (_, mut manifest) = test_bundle(dataset_hash);
    manifest.labels = super::super::class_labels(&model).expect("labels");
    (model, manifest)
}

fn publish_error(path: &Path, phase: AtomicPublishPhase) -> NetdiagError {
    NetdiagError::AtomicPublish {
        path: path.to_path_buf(),
        phase,
        source: Box::new(NetdiagError::Ml(
            "injected pointer publication failure".to_string(),
        )),
    }
}

fn generation_count(model_dir: &Path) -> usize {
    std::fs::read_dir(generation_root(model_dir))
        .expect("generation root")
        .count()
}

fn generation_names(model_dir: &Path) -> Vec<std::ffi::OsString> {
    let mut names = std::fs::read_dir(generation_root(model_dir))
        .expect("generation root")
        .map(|entry| entry.expect("generation entry").file_name())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[cfg(unix)]
fn contains_private_directory_mode(error: &NetdiagError, path: &Path, actual: u32) -> bool {
    match error {
        NetdiagError::PrivateDirectoryMode {
            path: error_path,
            actual: error_mode,
            ..
        } => error_path == path && *error_mode == actual,
        NetdiagError::AtomicPublish { source, .. } => {
            contains_private_directory_mode(source, path, actual)
        }
        NetdiagError::CombinedFailure {
            primary, secondary, ..
        } => {
            contains_private_directory_mode(primary, path, actual)
                || contains_private_directory_mode(secondary, path, actual)
        }
        _ => false,
    }
}

#[cfg(unix)]
fn contains_io_failure(error: &NetdiagError, path: &Path, kind: std::io::ErrorKind) -> bool {
    match error {
        NetdiagError::Io {
            path: error_path,
            source,
        } => error_path == path && source.kind() == kind,
        NetdiagError::AtomicPublish { source, .. } => contains_io_failure(source, path, kind),
        NetdiagError::CombinedFailure {
            primary, secondary, ..
        } => contains_io_failure(primary, path, kind) || contains_io_failure(secondary, path, kind),
        _ => false,
    }
}

fn create_private_directory(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .expect("private directory");
    }
    #[cfg(windows)]
    {
        netdiag_platform::open_or_create_trusted_directory_chain(path).expect("private directory");
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir_all(path).expect("private directory");
    }
}

#[test]
fn crash_before_current_pointer_keeps_previous_generation_readable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model_a, manifest_a) = test_bundle("dataset-a");
    write_model_bundle(&model_dir, &model_a, &manifest_a).expect("bundle A");
    let old = load_existing_model_bundle_snapshot(&model_dir).expect("old snapshot");
    let (model_b, manifest_b) = replacement_bundle(&model_a, "dataset-b");

    let error = with_model_bundle_lock(&model_dir, || {
        publish_locked_with(&model_dir, &model_b, &manifest_b, |path, _| {
            Err(publish_error(path, AtomicPublishPhase::NotPublished))
        })
    })
    .expect_err("pointer publication must fail");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("old bundle survives");
    assert_eq!(current.generation, old.generation);
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("dataset-a")
    );
    assert_eq!(generation_count(&model_dir), 2);
}

#[test]
fn pointer_durability_uncertainty_leaves_both_recovery_states_valid() {
    for publish_new_pointer in [false, true] {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_dir = temp.path().join("model");
        let (model_a, manifest_a) = test_bundle("dataset-a");
        write_model_bundle(&model_dir, &model_a, &manifest_a).expect("bundle A");
        let (model_b, manifest_b) = replacement_bundle(&model_a, "dataset-b");

        let error = with_model_bundle_lock(&model_dir, || {
            publish_locked_with(&model_dir, &model_b, &manifest_b, |path, descriptor| {
                if publish_new_pointer {
                    save_json_atomic(path, descriptor)?;
                }
                Err(publish_error(
                    path,
                    AtomicPublishPhase::PublishedButDurabilityUncertain,
                ))
            })
        })
        .expect_err("durability uncertainty must be returned");

        assert_eq!(
            error.atomic_publish_phase(),
            Some(AtomicPublishPhase::PublishedButDurabilityUncertain)
        );
        let current =
            load_existing_model_bundle_snapshot(&model_dir).expect("valid recovery state");
        let expected = if publish_new_pointer {
            "dataset-b"
        } else {
            "dataset-a"
        };
        assert_eq!(
            current.manifest.dataset_hash_sha256.as_deref(),
            Some(expected)
        );
    }
}

#[test]
fn next_publish_collects_orphan_and_retains_only_current_and_previous() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model_a, manifest_a) = test_bundle("dataset-a");
    write_model_bundle(&model_dir, &model_a, &manifest_a).expect("bundle A");
    let orphan = generation_root(&model_dir).join(format!("generation-{:032x}", 1));
    create_private_directory(&orphan);
    std::fs::write(orphan.join("partial"), b"crash residue").expect("partial generation");
    let (model_b, manifest_b) = replacement_bundle(&model_a, "dataset-b");

    write_model_bundle(&model_dir, &model_b, &manifest_b).expect("bundle B");

    assert!(!orphan.exists());
    assert_eq!(generation_count(&model_dir), 2);
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("current");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("dataset-b")
    );
}

#[test]
fn publishing_a_new_generation_durably_invalidates_the_existing_promotion_gate() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model_a, manifest_a) = test_bundle("dataset-a");
    write_model_bundle(&model_dir, &model_a, &manifest_a).expect("bundle A");
    let gate_path = model_dir.join(super::super::MODEL_PROMOTION_GATE_FILE_NAME);
    save_json_atomic(&gate_path, &serde_json::json!({"passed": true})).expect("promotion gate");
    let (model_b, manifest_b) = replacement_bundle(&model_a, "dataset-b");

    write_model_bundle(&model_dir, &model_b, &manifest_b).expect("bundle B");

    assert!(!gate_path.exists(), "stale promotion gate must be removed");
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("current bundle");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("dataset-b")
    );
}

#[test]
fn promotion_gate_invalidation_failure_keeps_the_current_pointer_unchanged() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model_a, manifest_a) = test_bundle("dataset-a");
    write_model_bundle(&model_dir, &model_a, &manifest_a).expect("bundle A");
    let old = load_existing_model_bundle_snapshot(&model_dir).expect("old bundle");
    let gate_path = model_dir.join(super::super::MODEL_PROMOTION_GATE_FILE_NAME);
    std::fs::create_dir(&gate_path).expect("non-removable promotion gate path");
    let (model_b, manifest_b) = replacement_bundle(&model_a, "dataset-b");

    let error = write_model_bundle(&model_dir, &model_b, &manifest_b)
        .expect_err("gate invalidation failure must abort before pointer publication");

    assert!(
        error.to_string().contains(&gate_path.display().to_string()),
        "{error}"
    );
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("old current");
    assert!(old.same_identity(&current));
    assert_eq!(old.generation, current.generation);
    assert!(gate_path.is_dir());
}

#[test]
fn oversized_manifest_aborts_without_changing_current_or_leaving_a_generation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model_a, manifest_a) = test_bundle("dataset-a");
    write_model_bundle(&model_dir, &model_a, &manifest_a).expect("bundle A");
    let old = load_existing_model_bundle_snapshot(&model_dir).expect("old bundle");
    let current_path = model_dir.join(super::super::MODEL_CURRENT_FILE_NAME);
    let current_bytes = std::fs::read(&current_path).expect("current descriptor");
    let gate_path = model_dir.join(super::super::MODEL_PROMOTION_GATE_FILE_NAME);
    save_json_atomic(&gate_path, &serde_json::json!({"passed": true})).expect("existing gate");
    let gate_bytes = std::fs::read(&gate_path).expect("existing gate bytes");
    let generations = generation_names(&model_dir);
    let (model_b, mut manifest_b) = replacement_bundle(&model_a, "dataset-b");
    manifest_b.training_source = "x".repeat(MAX_MODEL_MANIFEST_BYTES as usize);

    let error = write_model_bundle(&model_dir, &model_b, &manifest_b)
        .expect_err("oversized manifest must fail before pointer publication");

    assert!(
        error
            .to_string()
            .contains("serialized model generation manifest exceeds the 2097152-byte limit"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(&current_path).expect("unchanged current descriptor"),
        current_bytes
    );
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("old current");
    assert!(old.same_identity(&current));
    assert_eq!(old.generation, current.generation);
    assert_eq!(
        std::fs::read(&gate_path).expect("unchanged gate"),
        gate_bytes
    );
    assert_eq!(generation_names(&model_dir), generations);
}

#[test]
fn missing_or_tampered_current_generation_fails_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
    let paths = resolve_bundle_paths(&model_dir)
        .expect("resolve bundle")
        .expect("bundle paths");
    let model_path = paths.model_path;
    std::fs::remove_file(&model_path).expect("remove current model");
    let missing = load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("missing current generation file must fail");
    assert!(
        missing
            .to_string()
            .contains(&model_path.display().to_string())
    );

    save_json_atomic(&model_path, &model).expect("restore model");
    let mut tampered = manifest;
    tampered.model_file_hash_sha256 = "0".repeat(64);
    save_json_atomic(&paths.manifest_path, &tampered).expect("tamper manifest");
    let error = load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("tampered current generation must fail");
    assert!(error.to_string().contains("model bundle hash mismatch"));
}

#[test]
fn first_write_migrates_valid_legacy_v2_without_top_level_mirrors() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    create_private_directory(&model_dir);
    let (model_a, mut manifest_a) = test_bundle("legacy-dataset");
    let legacy_model = model_dir.join(super::super::MODEL_FILE_NAME);
    save_json_atomic(&legacy_model, &model_a).expect("legacy model");
    manifest_a.model_file_hash_sha256 = super::super::sha256_file(&legacy_model).expect("hash");
    save_json_atomic(
        model_dir.join(super::super::MODEL_MANIFEST_FILE_NAME),
        &manifest_a,
    )
    .expect("legacy manifest");
    load_existing_model_bundle_snapshot(&model_dir).expect("legacy reader");
    let (model_b, manifest_b) = replacement_bundle(&model_a, "new-dataset");

    write_model_bundle(&model_dir, &model_b, &manifest_b).expect("generation migration");

    assert!(
        model_dir
            .join(super::super::MODEL_CURRENT_FILE_NAME)
            .is_file()
    );
    assert!(!legacy_model.exists());
    assert!(
        !model_dir
            .join(super::super::MODEL_MANIFEST_FILE_NAME)
            .exists()
    );
    assert_eq!(generation_count(&model_dir), 2);
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("generation bundle");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("new-dataset")
    );
}

#[test]
fn writer_refuses_generation_roots_above_strict_cleanup_bound() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset-a");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle A");
    for index in 0..MAX_GENERATION_ENTRIES {
        let path = generation_root(&model_dir).join(format!("generation-{:032x}", index + 100));
        create_private_directory(&path);
    }
    let (_, replacement) = test_bundle("dataset-b");

    let error = write_model_bundle(&model_dir, &model, &replacement)
        .expect_err("over-bound cleanup must fail before publication");

    assert!(error.to_string().contains("strict 16 entry cleanup bound"));
    let current = load_existing_model_bundle_snapshot(&model_dir).expect("old current");
    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("dataset-a")
    );
}

#[test]
fn readers_resolve_only_current_pointer_without_scanning_generation_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
    std::fs::write(
        generation_root(&model_dir).join("unexpected-entry"),
        b"ignored",
    )
    .expect("unrelated entry");

    let current = load_existing_model_bundle_snapshot(&model_dir).expect("direct current load");

    assert_eq!(
        current.manifest.dataset_hash_sha256.as_deref(),
        Some("dataset")
    );
}

#[test]
fn malformed_current_descriptor_is_not_repaired_from_legacy_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
    let descriptor = CurrentDescriptor {
        schema_version: super::super::MODEL_CURRENT_SCHEMA.to_string(),
        generation: "../escape".to_string(),
    };
    save_json_atomic(
        model_dir.join(super::super::MODEL_CURRENT_FILE_NAME),
        &descriptor,
    )
    .expect("tampered current descriptor");

    let error = load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("invalid pointer must fail closed");

    assert!(error.to_string().contains("invalid generation name"));
}

#[test]
fn oversized_current_model_is_rejected_before_json_deserialization() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
    let model_path = resolve_bundle_paths(&model_dir)
        .expect("resolve bundle")
        .expect("bundle paths")
        .model_path;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&model_path)
        .expect("current model");
    file.set_len(MAX_MODEL_FILE_BYTES + 1)
        .expect("oversized model fixture");

    let error = load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("oversized model must fail closed");

    assert!(error.to_string().contains("16777216-byte read limit"));
}

#[test]
fn writer_revalidates_current_generation_after_a_prior_read() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model_a, manifest_a) = test_bundle("dataset-a");
    write_model_bundle(&model_dir, &model_a, &manifest_a).expect("bundle A");
    load_existing_model_bundle_snapshot(&model_dir).expect("prior read");
    let paths = resolve_bundle_paths(&model_dir)
        .expect("resolve bundle")
        .expect("bundle paths");
    let mut tampered = manifest_a;
    tampered.model_file_hash_sha256 = "0".repeat(64);
    save_json_atomic(&paths.manifest_path, &tampered).expect("tamper manifest");
    let (model_b, manifest_b) = replacement_bundle(&model_a, "dataset-b");

    let error = write_model_bundle(&model_dir, &model_b, &manifest_b)
        .expect_err("writer must revalidate the prior generation");

    assert!(error.to_string().contains("model bundle hash mismatch"));
}

#[cfg(unix)]
#[test]
fn publication_creates_private_bundle_generation_directories() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
    let paths = resolve_bundle_paths(&model_dir)
        .expect("resolve bundle")
        .expect("bundle paths");
    let generation_dir = paths.model_path.parent().expect("generation directory");
    let generations_dir = generation_root(&model_dir);

    for directory in [
        model_dir.as_path(),
        generations_dir.as_path(),
        generation_dir,
    ] {
        let mode = std::fs::metadata(directory)
            .expect("trusted directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "unexpected mode on {}", directory.display());
    }
}

#[cfg(unix)]
#[test]
fn publication_creates_the_entire_missing_private_directory_chain() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    let nested = artifacts.join("nested");
    let model_dir = nested.join("model");
    let (model, manifest) = test_bundle("dataset");

    write_model_bundle(&model_dir, &model, &manifest).expect("nested bundle publication");

    let paths = resolve_bundle_paths(&model_dir)
        .expect("resolve bundle")
        .expect("bundle paths");
    let generation_dir = paths.model_path.parent().expect("generation directory");
    for directory in [
        artifacts.as_path(),
        nested.as_path(),
        model_dir.as_path(),
        generation_root(&model_dir).as_path(),
        generation_dir,
    ] {
        let mode = std::fs::metadata(directory)
            .expect("created directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "unexpected mode on {}", directory.display());
    }
}

#[cfg(unix)]
#[test]
fn ordinary_model_directory_open_never_creates_a_missing_read_path() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing").join("model");

    let error = match super::trust::TrustedModelDirectory::open(&missing) {
        Ok(_) => panic!("ordinary open must reject a missing read path"),
        Err(error) => error,
    };

    assert!(matches!(error, NetdiagError::FilesystemTrust { .. }));
    assert!(!missing.exists());
    assert!(!missing.parent().expect("missing parent").exists());
}

#[cfg(unix)]
#[test]
fn reader_rejects_nonprivate_modes_on_every_bundle_directory_boundary() {
    use std::os::unix::fs::PermissionsExt;

    for boundary in 0..3 {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_dir = temp.path().join("model");
        let (model, manifest) = test_bundle("dataset");
        write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
        let paths = resolve_bundle_paths(&model_dir)
            .expect("resolve bundle")
            .expect("bundle paths");
        let generation_dir = paths
            .model_path
            .parent()
            .expect("generation directory")
            .to_path_buf();
        drop(paths);
        let target = match boundary {
            0 => model_dir.clone(),
            1 => generation_root(&model_dir),
            _ => generation_dir,
        };
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750))
            .expect("make model directory nonprivate");

        let error = load_existing_model_bundle_snapshot(&model_dir)
            .expect_err("nonprivate model directory must fail closed");
        let resolved_target = target.canonicalize().expect("resolved nonprivate boundary");

        assert!(
            contains_private_directory_mode(&error, &resolved_target, 0o750),
            "{error:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn reader_rejects_symlinked_bundle_directory_boundaries() {
    use std::os::unix::fs::symlink;

    for boundary in 0..3 {
        let temp = tempfile::tempdir().expect("tempdir");
        let model_dir = temp.path().join("model");
        let (model, manifest) = test_bundle("dataset");
        write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
        let paths = resolve_bundle_paths(&model_dir)
            .expect("resolve bundle")
            .expect("bundle paths");
        let generation_dir = paths
            .model_path
            .parent()
            .expect("generation directory")
            .to_path_buf();
        drop(paths);
        let target = match boundary {
            0 => model_dir.clone(),
            1 => generation_root(&model_dir),
            _ => generation_dir,
        };
        let relocated = target.with_extension("trusted-original");
        std::fs::rename(&target, &relocated).expect("relocate trusted directory");
        symlink(&relocated, &target).expect("untrusted directory symlink");

        let error = load_existing_model_bundle_snapshot(&model_dir)
            .expect_err("symlinked model directory boundary must fail closed");

        assert!(error.to_string().contains("untrusted symlink"), "{error}");
    }
}

#[test]
fn subsequent_load_rejects_in_place_model_tampering() {
    use std::io::Write;

    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
    load_existing_model_bundle_snapshot(&model_dir).expect("initial load");
    let paths = resolve_bundle_paths(&model_dir)
        .expect("resolve bundle")
        .expect("bundle paths");
    std::fs::OpenOptions::new()
        .append(true)
        .open(&paths.model_path)
        .expect("open model for in-place tamper")
        .write_all(b"\n")
        .expect("tamper model in place");

    let error = load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("a new load must revalidate the current model bytes");

    assert!(error.to_string().contains("model bundle hash mismatch"));
}

#[test]
fn subsequent_load_rejects_same_generation_manifest_tampering() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
    load_existing_model_bundle_snapshot(&model_dir).expect("initial load");
    let paths = resolve_bundle_paths(&model_dir)
        .expect("resolve bundle")
        .expect("bundle paths");
    let mut tampered = manifest;
    tampered.model_file_hash_sha256 = "0".repeat(64);
    save_json_atomic(&paths.manifest_path, &tampered).expect("tamper manifest");

    let error = load_existing_model_bundle_snapshot(&model_dir)
        .expect_err("a new load must revalidate the current manifest bytes");

    assert!(error.to_string().contains("model bundle hash mismatch"));
}

#[test]
fn manifest_only_update_preserves_the_validated_model_bytes_and_hash() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let (model, manifest) = test_bundle("dataset");
    write_model_bundle(&model_dir, &model, &manifest).expect("bundle");
    let paths = resolve_bundle_paths(&model_dir)
        .expect("resolve bundle")
        .expect("bundle paths");
    let mut source_bytes = std::fs::read(&paths.model_path).expect("source model bytes");
    source_bytes.extend_from_slice(b"\n ");
    std::fs::write(&paths.model_path, &source_bytes).expect("alternate valid JSON encoding");
    let mut rebound_manifest = manifest;
    rebound_manifest.model_file_hash_sha256 = super::loading::sha256_bytes(&source_bytes);
    save_json_atomic(&paths.manifest_path, &rebound_manifest).expect("rebound manifest");
    let source = load_existing_model_bundle_snapshot(&model_dir).expect("source snapshot");
    let source_generation = source.generation.clone();
    let mut updated_manifest = source.manifest.clone();
    updated_manifest.training_source = "manifest-only-update".to_string();

    let updated = replace_manifest_if_current(
        &model_dir,
        &source.model_manifest_hash_sha256,
        &updated_manifest,
    )
    .expect("manifest-only update");
    let updated_paths = resolve_bundle_paths(&model_dir)
        .expect("resolve updated bundle")
        .expect("updated bundle paths");

    assert_ne!(updated.generation, source_generation);
    assert_eq!(
        updated.model_file_hash_sha256,
        source.model_file_hash_sha256
    );
    assert_ne!(
        updated.model_manifest_hash_sha256,
        source.model_manifest_hash_sha256
    );
    assert_eq!(
        std::fs::read(updated_paths.model_path).expect("updated model bytes"),
        source_bytes
    );
    assert_eq!(updated.model_file_bytes.as_ref(), source_bytes.as_slice());
    assert_eq!(
        updated.manifest.model_file_hash_sha256,
        updated.model_file_hash_sha256
    );
}
