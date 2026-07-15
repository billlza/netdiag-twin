use super::*;
#[cfg(any(unix, windows))]
use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::storage::BoundAtomicFileTarget;
use std::ffi::OsStr;
#[cfg(any(unix, windows))]
use std::io::Write;

#[test]
fn reservation_never_reuses_an_existing_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let target_path = directory.path().join("state.json");
    let target = BoundAtomicFileTarget::bind(&target_path).expect("bound target");
    let name = OsStr::new("state.tmp");
    let path = directory.path().join(name);
    std::fs::write(&path, b"existing").expect("existing file");

    let result = StagedAtomicFile::reserve_named_for_test(target.directory_arc(), name);
    assert!(result.is_err(), "existing file must not be reused");

    assert_eq!(std::fs::read(path).expect("existing contents"), b"existing");
}

#[cfg(unix)]
#[test]
fn unix_reservation_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temporary directory");
    let target_path = directory.path().join("state.json");
    let target = BoundAtomicFileTarget::bind(&target_path).expect("bound target");
    let staged =
        StagedAtomicFile::reserve_in(target.directory_arc(), OsStr::new("state.json"), "tmp")
            .expect("private temporary file");

    assert_eq!(
        staged
            .metadata_for_test()
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    staged.finish(Ok(())).expect("staged cleanup");
}

#[cfg(any(unix, windows))]
#[test]
fn independently_reopened_directory_handle_cannot_publish_staged_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let target_path = directory.path().join("state.json");
    let staging_target = BoundAtomicFileTarget::bind(&target_path).expect("staging target");
    let publication_target =
        BoundAtomicFileTarget::bind(&target_path).expect("independently rebound target");
    let resolved_target = publication_target.resolved_path().to_path_buf();
    let mut staged = StagedAtomicFile::reserve_in(
        staging_target.directory_arc(),
        OsStr::new("state.json"),
        "tmp",
    )
    .expect("staged file");
    let staged_path = staged.path().to_path_buf();
    staged.file_mut().write_all(b"staged").expect("stage bytes");

    let error = staged
        .publish_noclobber(&publication_target)
        .expect_err("equal paths must not substitute for one trusted directory handle");

    assert!(
        matches!(
            &error,
            NetdiagError::AtomicPublish {
                path,
                phase: AtomicPublishPhase::NotPublished,
                source,
            } if path == &resolved_target
                && matches!(source.as_ref(), NetdiagError::InvalidTrace(message)
                    if message.contains("do not share one trusted directory handle"))
        ),
        "{error:?}"
    );
    assert!(!target_path.exists(), "rejected publish created its target");
    assert!(
        !staged_path.exists(),
        "rejected publish leaked its staging file"
    );
}

#[cfg(any(unix, windows))]
#[test]
fn existing_target_disposition_removes_staged_file_without_changing_target() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let target_path = directory.path().join("state.json");
    std::fs::write(&target_path, b"existing").expect("existing target");
    let target = BoundAtomicFileTarget::bind(&target_path).expect("bound target");
    let mut staged =
        StagedAtomicFile::reserve_in(target.directory_arc(), OsStr::new("state.json"), "tmp")
            .expect("staged file");
    let staged_path = staged.path().to_path_buf();
    staged
        .file_mut()
        .write_all(b"replacement")
        .expect("stage bytes");

    let disposition = staged
        .publish_noclobber(&target)
        .expect("existing immutable target is a successful no-clobber outcome");

    assert_eq!(disposition, NoClobberDisposition::Existing);
    assert_eq!(
        std::fs::read(&target_path).expect("target contents"),
        b"existing"
    );
    assert!(
        !staged_path.exists(),
        "Existing outcome leaked staging file"
    );
}
