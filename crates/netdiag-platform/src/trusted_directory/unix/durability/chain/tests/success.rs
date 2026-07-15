use super::super::{persist_directory_chain_with, persist_if_required};
use crate::{DirectoryPersistenceStage, DirectoryTrustError};
use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};

#[test]
fn durable_chain_syncs_each_directory_once_from_leaf_to_root() {
    let ancestors = [((), PathBuf::from("/")), ((), PathBuf::from("/parent"))];
    let calls = RefCell::new(Vec::new());
    persist_directory_chain_with(
        &(),
        Path::new("/parent/child"),
        &ancestors,
        |_, path, stage| {
            calls.borrow_mut().push((path.to_path_buf(), stage));
            Ok(())
        },
    )
    .expect("directory chain persistence");

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
            (
                PathBuf::from("/"),
                DirectoryPersistenceStage::ParentDirectory,
            ),
        ]
    );
}

#[test]
fn non_durable_open_never_invokes_persistence() {
    persist_if_required(false, || {
        panic!("non-durable open must not sync directories")
    })
    .expect("non-durable operation");
}

#[test]
fn durable_retry_reinvokes_persistence_after_failure() {
    let attempts = Cell::new(0_u8);
    let first = persist_if_required(true, || {
        attempts.set(attempts.get() + 1);
        Err(DirectoryTrustError::DurabilityUnavailable {
            path: PathBuf::from("/parent/child"),
        })
    });
    assert!(first.is_err());

    persist_if_required(true, || {
        attempts.set(attempts.get() + 1);
        Ok(())
    })
    .expect("durable retry");
    assert_eq!(attempts.get(), 2);
}
