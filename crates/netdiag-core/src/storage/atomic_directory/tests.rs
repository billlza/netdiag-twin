use super::*;
use crate::error::{AtomicPublishPhase, NetdiagError};

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn staged(root: &Path, stage: &str, target: &str) -> StagedAtomicDirectory {
    let parent = netdiag_platform::open_or_create_durable_trusted_directory_chain(root)
        .expect("trusted parent");
    StagedAtomicDirectory::create(
        Arc::new(parent),
        stage.into(),
        target.into(),
        root.join(target),
        "test staged directory",
    )
    .expect("staged directory")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn failed_operation_removes_the_nested_stage_without_publishing() {
    let root = tempfile::tempdir().expect("temporary root");
    let staged = staged(root.path(), ".stage", "run");
    let staging_path = staged.staging_path().to_path_buf();
    let target_path = staged.target_path().to_path_buf();
    std::fs::create_dir_all(staging_path.join("runs/id/nested")).expect("nested tree");
    std::fs::write(staging_path.join("runs/id/nested/artifact"), b"artifact")
        .expect("nested artifact");

    let error = staged
        .finish::<()>(Err(NetdiagError::InvalidTrace(
            "injected operation failure".to_string(),
        )))
        .expect_err("operation must fail");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!staging_path.exists());
    assert!(!target_path.exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn successful_discard_removes_the_nested_stage_without_publishing() {
    let root = tempfile::tempdir().expect("temporary root");
    let staged = staged(root.path(), ".stage", "run");
    let staging_path = staged.staging_path().to_path_buf();
    let target_path = staged.target_path().to_path_buf();
    std::fs::create_dir_all(staging_path.join("nested")).expect("nested stage");
    std::fs::write(staging_path.join("nested/artifact"), b"temporary").expect("temporary artifact");

    let value = staged.discard(Ok(42)).expect("discard temporary stage");

    assert_eq!(value, 42);
    assert!(!staging_path.exists());
    assert!(!target_path.exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn collision_preserves_the_target_and_removes_the_nested_stage() {
    let root = tempfile::tempdir().expect("temporary root");
    let staged = staged(root.path(), ".stage", "run");
    let staging_path = staged.staging_path().to_path_buf();
    std::fs::create_dir_all(staging_path.join("nested")).expect("nested stage");
    std::fs::write(staging_path.join("nested/artifact"), b"staged").expect("staged artifact");
    std::fs::create_dir(root.path().join("run")).expect("existing target");
    std::fs::write(root.path().join("run/sentinel"), b"existing").expect("target sentinel");

    let error = staged.publish().expect_err("collision must fail closed");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert_eq!(
        std::fs::read(root.path().join("run/sentinel")).expect("preserved sentinel"),
        b"existing"
    );
    assert!(!staging_path.exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cleanup_remains_bound_when_the_parent_path_is_replaced() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary root");
    let parent_path = root.path().join("runs");
    let replacement = root.path().join("replacement");
    std::fs::create_dir(&parent_path).expect("parent");
    std::fs::create_dir(&replacement).expect("replacement");
    let staged = staged(&parent_path, ".stage", "run");
    std::fs::create_dir_all(staged.staging_path().join("nested")).expect("nested stage");
    std::fs::write(staged.staging_path().join("nested/artifact"), b"artifact").expect("artifact");
    let displaced = root.path().join("displaced");
    std::fs::rename(&parent_path, &displaced).expect("displace parent");
    symlink(&replacement, &parent_path).expect("replace parent path");

    let error = staged.abort(NetdiagError::InvalidTrace(
        "injected operation failure".to_string(),
    ));

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(!displaced.join(".stage").exists());
    assert!(!replacement.join(".stage").exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn cleanup_refuses_to_remove_a_replacement_stage_entry() {
    let root = tempfile::tempdir().expect("temporary root");
    let staged = staged(root.path(), ".stage", "run");
    std::fs::create_dir_all(staged.staging_path().join("nested")).expect("nested stage");
    std::fs::write(staged.staging_path().join("nested/artifact"), b"original")
        .expect("original artifact");
    std::fs::rename(
        root.path().join(".stage"),
        root.path().join(".original-stage"),
    )
    .expect("move original stage entry");
    std::fs::create_dir(root.path().join(".stage")).expect("replacement stage");
    std::fs::write(root.path().join(".stage/sentinel"), b"replacement")
        .expect("replacement sentinel");

    let error = staged.abort(NetdiagError::InvalidTrace(
        "injected operation failure".to_string(),
    ));

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert!(error.to_string().contains("cleanup also failed"), "{error}");
    assert_eq!(
        std::fs::read(root.path().join(".stage/sentinel")).expect("replacement preserved"),
        b"replacement"
    );
    assert_eq!(
        std::fs::read(root.path().join(".original-stage/nested/artifact"))
            .expect("original stage preserved for explicit recovery"),
        b"original"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn durability_uncertain_failure_never_cleans_the_stage() {
    let root = tempfile::tempdir().expect("temporary root");
    let staged = staged(root.path(), ".stage", "run");
    let staging_path = staged.staging_path().to_path_buf();
    std::fs::write(staging_path.join("artifact"), b"possibly visible").expect("staged artifact");

    let error = staged
        .fail_with_publication_phase(
            AtomicPublishPhase::PublishedButDurabilityUncertain,
            NetdiagError::InvalidTrace("injected parent sync failure".to_string()),
        )
        .expect_err("uncertain publication must fail explicitly");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::PublishedButDurabilityUncertain)
    );
    assert!(
        staging_path.exists(),
        "uncertain publication must not delete the only retained identity"
    );
}
