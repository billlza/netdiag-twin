use super::*;
use chrono::Utc;

#[test]
fn directories_are_unique_for_the_same_millisecond() {
    let temp = tempfile::tempdir().expect("tempdir");
    let created_at = Utc::now();
    let capability = crate::storage::prepare_artifact_root(temp.path()).expect("artifact root");

    let first = crate::storage::with_artifact_root_capability(&capability, |owned| {
        create_staged_pilot_run(owned, "pilot", created_at)
    })
    .expect("first stage");
    let second = crate::storage::with_artifact_root_capability(&capability, |owned| {
        create_staged_pilot_run(owned, "pilot", created_at)
    })
    .expect("second stage");

    assert_ne!(first.target_path(), second.target_path());
    assert!(first.staging_path().is_dir());
    assert!(second.staging_path().is_dir());
    assert!(!first.target_path().exists());
    assert!(!second.target_path().exists());
    let first_name = first
        .target_path()
        .file_name()
        .expect("first name")
        .to_string_lossy();
    assert!(first_name.contains('.'), "{first_name}");
    assert!(first_name.contains('-'), "{first_name}");

    let primary = crate::error::NetdiagError::InvalidTrace("injected failure".to_string());
    let first_error = first.abort(primary);
    assert_eq!(
        first_error.atomic_publish_phase(),
        Some(crate::error::AtomicPublishPhase::NotPublished)
    );
    let second_error = second.abort(crate::error::NetdiagError::InvalidTrace(
        "injected failure".to_string(),
    ));
    assert_eq!(
        second_error.atomic_publish_phase(),
        Some(crate::error::AtomicPublishPhase::NotPublished)
    );
    assert_eq!(
        std::fs::read_dir(temp.path().join("pilot-runs/pilot"))
            .expect("pilot root")
            .count(),
        0,
        "aborted pilot stages must not leak hidden directories"
    );
}
