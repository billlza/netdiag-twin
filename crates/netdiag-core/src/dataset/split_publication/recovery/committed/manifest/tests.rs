use super::*;
use std::ffi::OsStr;
use std::sync::Arc;

#[test]
fn created_manifest_verification_failure_preserves_published_target_and_phase() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let directory = netdiag_platform::open_or_create_trusted_directory_chain(temp.path())
        .expect("trusted directory");
    let target = BoundAtomicFileTarget::from_directory(
        Arc::new(directory),
        OsStr::new("dataset_manifest.json"),
    )
    .expect("bound manifest target");
    std::fs::write(target.resolved_path(), b"visible manifest").expect("visible manifest fixture");
    let error = created_verification(
        &target,
        Err(NetdiagError::InvalidTrace(
            "injected stable manifest verification failure".to_string(),
        )),
    )
    .expect_err("visible manifest failure must remain published");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::Published)
    );
    assert!(matches!(
        error,
        NetdiagError::AtomicPublish { path, source, .. }
            if path == target.resolved_path()
                && matches!(
                    source.as_ref(),
                    NetdiagError::InvalidTrace(message)
                        if message == "injected stable manifest verification failure"
                )
    ));
    assert_eq!(
        std::fs::read(target.resolved_path()).expect("published manifest remains visible"),
        b"visible manifest"
    );
}
