use crate::{
    DirectoryTrustError, open_or_create_durable_trusted_directory_chain,
    open_or_create_durable_trusted_subdirectory, open_trusted_directory_chain,
};
use std::ffi::OsStr;

#[test]
fn durable_chain_fails_before_creating_a_windows_directory() {
    let root = tempfile::tempdir().expect("temporary directory");
    let missing = root.path().join("durable-chain");
    let error = open_or_create_durable_trusted_directory_chain(&missing)
        .expect_err("Windows durable chain must be unavailable");

    assert!(matches!(
        error,
        DirectoryTrustError::DurabilityUnavailable { path } if path == missing
    ));
    assert!(!missing.exists());
}

#[test]
fn durable_child_fails_before_creating_a_windows_directory() {
    let root = tempfile::tempdir().expect("temporary directory");
    let parent = open_trusted_directory_chain(root.path()).expect("trusted parent");
    let child = root.path().join("durable-child");
    let error = open_or_create_durable_trusted_subdirectory(&parent, OsStr::new("durable-child"))
        .expect_err("Windows durable child must be unavailable");

    assert!(matches!(
        error,
        DirectoryTrustError::DurabilityUnavailable { path } if path == child
    ));
    assert!(!child.exists());
}
