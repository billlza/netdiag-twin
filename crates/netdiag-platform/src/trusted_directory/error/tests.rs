use super::*;
use std::error::Error;

#[test]
fn windows_acl_error_shape_preserves_its_io_source() {
    let error = DirectoryTrustError::Acl {
        path: PathBuf::from("acl.fixture"),
        source: io::Error::new(io::ErrorKind::PermissionDenied, "ACL fixture"),
    };

    assert!(error.to_string().contains("acl.fixture"));
    assert!(matches!(
        error.source(),
        Some(source) if source.downcast_ref::<io::Error>().is_some()
    ));
}

#[test]
fn persistence_error_preserves_stage_path_and_io_source() {
    let path = PathBuf::from("durable-directory");
    let error = DirectoryTrustError::Persist {
        path: path.clone(),
        stage: DirectoryPersistenceStage::ParentDirectory,
        source: io::Error::other("sync failure"),
    };

    assert!(error.to_string().contains("trusted parent directory entry"));
    assert!(error.to_string().contains("durable-directory"));
    assert!(matches!(
        error.source(),
        Some(source)
            if source.downcast_ref::<io::Error>().is_some_and(|source| source.to_string() == "sync failure")
    ));
}
