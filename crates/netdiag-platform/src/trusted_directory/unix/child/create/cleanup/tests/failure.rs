use super::super::finish_preparation;
use crate::DirectoryTrustError;
use std::ffi::OsStr;
use std::io;

#[test]
fn nonempty_candidate_preserves_validation_and_cleanup_failures() {
    let root = tempfile::tempdir().expect("tempdir");
    let candidate = root.path().join("candidate");
    std::fs::create_dir(&candidate).expect("candidate directory");
    let sentinel = candidate.join("sentinel");
    std::fs::write(&sentinel, b"fixture").expect("nonempty candidate fixture");
    let parent = std::fs::File::open(root.path()).expect("opened parent");
    let validation = DirectoryTrustError::IdentityChanged {
        path: candidate.clone(),
    };

    let error = finish_preparation(
        &parent,
        OsStr::new("candidate"),
        candidate.clone(),
        Err(validation),
    )
    .expect_err("validation and cleanup failures must remain errors");

    assert!(matches!(
        &error,
        DirectoryTrustError::ValidationAndCleanup {
            path,
            validation,
            cleanup,
        } if path == &candidate
            && matches!(
                validation.as_ref(),
                DirectoryTrustError::IdentityChanged { path } if path == &candidate
            )
            && cleanup.kind() == io::ErrorKind::DirectoryNotEmpty
    ));
    assert_eq!(
        std::fs::read(&sentinel).expect("preserved sentinel"),
        b"fixture",
        "failed cleanup must not mutate the nonempty candidate"
    );
}
