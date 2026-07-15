use super::super::super::persist_directory_chain_with;
use crate::{DirectoryPersistenceStage, DirectoryTrustError};
use std::cell::Cell;
use std::io;
use std::path::{Path, PathBuf};

#[test]
fn leaf_sync_failure_preserves_path_stage_and_source() {
    let calls = Cell::new(0_u8);
    let error = persist_directory_chain_with(
        &(),
        Path::new("/parent/child"),
        &[((), PathBuf::from("/parent"))],
        |_, _, stage| {
            calls.set(calls.get() + 1);
            assert_eq!(stage, DirectoryPersistenceStage::Directory);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "leaf sync fixture",
            ))
        },
    )
    .expect_err("leaf persistence failure must fail closed");

    assert_eq!(calls.get(), 1, "ancestors must not sync after leaf failure");
    assert!(matches!(
        error,
        DirectoryTrustError::Persist {
            path,
            stage: DirectoryPersistenceStage::Directory,
            source,
        } if path == Path::new("/parent/child")
            && source.kind() == io::ErrorKind::PermissionDenied
    ));
}
