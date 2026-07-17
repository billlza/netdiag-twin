use super::*;
use std::ffi::OsStr;
use std::sync::Arc;

#[test]
fn validated_existing_target_is_reported_as_published() {
    let (_temp, target) = target();
    let error = preserve_failed_noclobber_state(&target, collision_cleanup(&target), || Ok(()));

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::Published)
    );
    assert!(matches!(
        error,
        NetdiagError::AtomicPublish { path, .. } if path == target.resolved_path()
    ));
}

#[test]
fn conflicting_existing_target_is_reported_as_indeterminate_with_both_failures() {
    let (_temp, target) = target();
    let error = preserve_failed_noclobber_state(&target, collision_cleanup(&target), || {
        Err(NetdiagError::InvalidTrace(
            "injected existing target mismatch".to_string(),
        ))
    });

    let NetdiagError::PublicationStateIndeterminate { path, source } = error else {
        panic!("expected indeterminate existing target state");
    };
    assert_eq!(path, target.resolved_path());
    assert!(matches!(
        source.as_ref(),
        NetdiagError::AtomicPublish { source, .. }
            if matches!(
                source.as_ref(),
                NetdiagError::CombinedFailure { primary, secondary, .. }
                    if matches!(
                        primary.as_ref(),
                        NetdiagError::ExistingTargetCollisionCleanup { .. }
                    ) && matches!(
                        secondary.as_ref(),
                        NetdiagError::InvalidTrace(message)
                            if message == "injected existing target mismatch"
                    )
            )
    ));
}

fn target() -> (tempfile::TempDir, BoundAtomicFileTarget) {
    let temp = tempfile::tempdir().expect("temporary directory");
    let directory = netdiag_platform::open_or_create_trusted_directory_chain(temp.path())
        .expect("trusted directory");
    let target =
        BoundAtomicFileTarget::from_directory(Arc::new(directory), OsStr::new("state.json"))
            .expect("bound target");
    (temp, target)
}

fn collision_cleanup(target: &BoundAtomicFileTarget) -> NetdiagError {
    NetdiagError::atomic_publish(
        target.resolved_path().to_path_buf(),
        AtomicPublishPhase::NotPublished,
        NetdiagError::ExistingTargetCollisionCleanup {
            path: target.resolved_path().to_path_buf(),
            collision: Box::new(NetdiagError::Io {
                path: target.resolved_path().to_path_buf(),
                source: std::io::Error::new(std::io::ErrorKind::AlreadyExists, "collision"),
            }),
            cleanup: Box::new(NetdiagError::Io {
                path: target.resolved_path().with_extension("tmp"),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "cleanup"),
            }),
        },
    )
}
