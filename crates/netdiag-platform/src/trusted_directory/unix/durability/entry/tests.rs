use super::persist_directory_entry_with;
use crate::{DirectoryPersistenceStage, DirectoryTrustError};
use std::cell::RefCell;
use std::io;
use std::path::Path;

#[test]
fn created_directory_is_synced_before_its_parent() {
    let calls = RefCell::new(Vec::new());
    persist_directory_entry_with(
        Path::new("/parent"),
        Path::new("/parent/child"),
        || {
            calls.borrow_mut().push("child");
            Ok(())
        },
        || {
            calls.borrow_mut().push("parent");
            Ok(())
        },
    )
    .expect("directory persistence");
    assert_eq!(calls.into_inner(), ["child", "parent"]);
}

#[test]
fn child_sync_failure_stops_before_parent_sync() {
    let error = persist_directory_entry_with(
        Path::new("/parent"),
        Path::new("/parent/child"),
        || Err(io::Error::other("child sync failure")),
        || panic!("parent sync must not run after a child sync failure"),
    )
    .expect_err("child sync failure must propagate");

    assert!(matches!(
        error,
        DirectoryTrustError::Persist {
            path,
            stage: DirectoryPersistenceStage::Directory,
            source,
        } if path == Path::new("/parent/child") && source.to_string() == "child sync failure"
    ));
}

#[test]
fn parent_sync_failure_preserves_parent_context() {
    let error = persist_directory_entry_with(
        Path::new("/parent"),
        Path::new("/parent/child"),
        || Ok(()),
        || Err(io::Error::other("parent sync failure")),
    )
    .expect_err("parent sync failure must propagate");

    assert!(matches!(
        error,
        DirectoryTrustError::Persist {
            path,
            stage: DirectoryPersistenceStage::ParentDirectory,
            source,
        } if path == Path::new("/parent") && source.to_string() == "parent sync failure"
    ));
}
