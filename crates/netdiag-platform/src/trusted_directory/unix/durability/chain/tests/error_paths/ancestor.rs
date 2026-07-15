use super::super::super::persist_directory_chain_with;
use crate::{DirectoryPersistenceStage, DirectoryTrustError};
use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};

#[test]
fn ancestor_sync_failure_preserves_path_stage_and_stops_at_failure() {
    let ancestors = [((), PathBuf::from("/")), ((), PathBuf::from("/parent"))];
    let calls = RefCell::new(Vec::new());
    let error = persist_directory_chain_with(
        &(),
        Path::new("/parent/child"),
        &ancestors,
        |_, path, stage| {
            calls.borrow_mut().push((path.to_path_buf(), stage));
            if stage == DirectoryPersistenceStage::ParentDirectory {
                Err(io::Error::new(
                    io::ErrorKind::ReadOnlyFilesystem,
                    "ancestor sync fixture",
                ))
            } else {
                Ok(())
            }
        },
    )
    .expect_err("ancestor persistence failure must fail closed");

    assert_eq!(
        calls.into_inner(),
        [
            (
                PathBuf::from("/parent/child"),
                DirectoryPersistenceStage::Directory,
            ),
            (
                PathBuf::from("/parent"),
                DirectoryPersistenceStage::ParentDirectory,
            ),
        ],
        "persistence must stop before the next ancestor"
    );
    assert!(matches!(
        error,
        DirectoryTrustError::Persist {
            path,
            stage: DirectoryPersistenceStage::ParentDirectory,
            source,
        } if path == Path::new("/parent")
            && source.kind() == io::ErrorKind::ReadOnlyFilesystem
    ));
}
