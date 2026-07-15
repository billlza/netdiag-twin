use super::super::finish_preparation;
use crate::DirectoryTrustError;
use std::ffi::OsStr;

#[test]
fn empty_candidate_cleanup_returns_the_original_validation_error() {
    let root = tempfile::tempdir().expect("tempdir");
    let candidate = root.path().join("candidate");
    std::fs::create_dir(&candidate).expect("empty candidate");
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
    .expect_err("validation failure must remain an error");

    assert!(matches!(
        error,
        DirectoryTrustError::IdentityChanged { path } if path == candidate
    ));
    assert!(
        !candidate.exists(),
        "empty failed candidate must be removed"
    );
}
