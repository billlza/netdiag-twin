use super::*;
use crate::evidence_bundle::source::open_required_source;
use std::fs;

fn source(path: &Path) -> SourceFile {
    open_required_source(path, None).expect("source")
}

#[test]
fn rejects_same_inode_same_length_mutation_during_snapshot_capture() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("source.json");
    fs::write(&path, b"first-generation").expect("source");
    let mut store = SnapshotStore::new().expect("store");
    let store_path = store.path().to_path_buf();

    let error = store
        .capture_with_after_copy(source(&path), |source_path| {
            fs::write(source_path, b"other-generation").expect("same-length mutation");
        })
        .expect_err("same-inode same-length mutation must fail closed");
    let error = store
        .finish::<()>(Err(error))
        .expect_err("capture failure must be preserved");

    assert!(error.to_string().contains("source changed"));
    assert!(!store_path.exists());
}

#[test]
fn enforces_source_count_budget_before_creating_an_extra_snapshot() {
    let temp = tempfile::tempdir().expect("tempdir");
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::write(&first, []).expect("first");
    fs::write(&second, []).expect("second");
    let mut store = SnapshotStore::with_limits(1, 16, 16).expect("store");
    let store_path = store.path().to_path_buf();
    store.capture(source(&first)).expect("first snapshot");

    let error = store
        .capture(source(&second))
        .expect_err("second source must exceed count budget");
    let error = store
        .finish::<()>(Err(error))
        .expect_err("budget failure must be preserved");

    assert!(error.to_string().contains("source count limit"));
    assert!(!store_path.exists());
}

#[test]
fn enforces_per_file_and_total_snapshot_byte_budgets() {
    let temp = tempfile::tempdir().expect("tempdir");
    let oversized = temp.path().join("oversized");
    fs::write(&oversized, b"12345").expect("oversized");
    let mut per_file = SnapshotStore::with_limits(2, 4, 8).expect("store");
    let per_file_error = per_file
        .capture(source(&oversized))
        .expect_err("per-file budget");
    let per_file_error = per_file
        .finish::<()>(Err(per_file_error))
        .expect_err("per-file failure must be preserved");
    assert!(per_file_error.to_string().contains("single source file"));

    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::write(&first, b"123").expect("first");
    fs::write(&second, b"456").expect("second");
    let mut total = SnapshotStore::with_limits(2, 4, 5).expect("store");
    total.capture(source(&first)).expect("first snapshot");
    let total_error = total.capture(source(&second)).expect_err("total budget");
    let total_error = total
        .finish::<()>(Err(total_error))
        .expect_err("total failure must be preserved");
    assert!(total_error.to_string().contains("total source snapshot"));
}

#[test]
fn incomplete_snapshot_cleanup_preserves_both_failures() {
    use std::error::Error;

    let directory = tempfile::tempdir().expect("tempdir");
    let operation = NetdiagError::InvalidTrace("snapshot operation".to_string());
    let error = cleanup::after_capture_failure(directory.path(), operation);

    let (operation, cleanup) = match &error {
        NetdiagError::EvidenceSnapshotOperationAndCleanup {
            operation, cleanup, ..
        } => (operation, cleanup),
        other => panic!("expected structured snapshot cleanup failure: {other}"),
    };
    assert!(operation.to_string().contains("snapshot operation"));
    assert_ne!(cleanup.kind(), std::io::ErrorKind::NotFound);
    assert_eq!(
        error.source().expect("operation source").to_string(),
        operation.to_string()
    );
}
