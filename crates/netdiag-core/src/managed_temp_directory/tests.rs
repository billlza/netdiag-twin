use super::ManagedTempDirectory;
use crate::error::NetdiagError;

#[test]
fn finish_removes_directory_after_success_and_operation_failure() {
    let successful = ManagedTempDirectory::create("managed temp test", "netdiag-managed-ok-")
        .expect("successful directory");
    let successful_path = successful.path().to_path_buf();
    assert_eq!(successful.finish(Ok(7_u8)).expect("successful finish"), 7);
    assert!(!successful_path.exists());

    let failed = ManagedTempDirectory::create("managed temp test", "netdiag-managed-error-")
        .expect("failed operation directory");
    let failed_path = failed.path().to_path_buf();
    let error = failed
        .finish::<()>(Err(NetdiagError::InvalidTrace("operation".to_string())))
        .expect_err("operation must fail");
    assert!(matches!(error, NetdiagError::InvalidTrace(_)));
    assert!(!failed_path.exists());
}

#[test]
fn creation_errors_remain_structured() {
    let error = ManagedTempDirectory::create("managed temp test", "invalid/prefix")
        .expect_err("invalid prefix must fail");
    assert!(matches!(
        error,
        NetdiagError::TrustedTemporaryDirectory {
            source: netdiag_platform::TrustedTempDirectoryError::InvalidPrefix,
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn identity_errors_remain_structured() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let directory = ManagedTempDirectory::create("managed temp test", "netdiag-managed-identity-")
        .expect("managed directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced-identity");
    fs::rename(&path, &displaced).expect("displace managed directory");
    fs::create_dir(&path).expect("replacement directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("replacement mode");

    let error = directory
        .validate_identity()
        .expect_err("replacement must change identity");
    assert!(matches!(
        error,
        NetdiagError::TrustedTemporaryDirectory {
            source: netdiag_platform::TrustedTempDirectoryError::IdentityChanged { .. },
            ..
        }
    ));

    fs::remove_dir(&path).expect("remove replacement fixture");
    fs::rename(&displaced, &path).expect("restore managed directory");
    directory.finish(Ok(())).expect("finish restored directory");
}

#[cfg(unix)]
#[test]
fn cleanup_after_success_remains_machine_distinguishable() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let directory = ManagedTempDirectory::create("managed temp test", "netdiag-managed-cleanup-")
        .expect("managed directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced-cleanup");
    fs::rename(&path, &displaced).expect("displace managed directory");
    fs::create_dir(&path).expect("replacement directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    let error = directory
        .finish(Ok(()))
        .expect_err("cleanup after successful operation must fail");
    fs::remove_dir_all(&path).expect("remove replacement fixture");
    fs::remove_dir_all(&displaced).expect("remove displaced fixture");

    assert!(matches!(
        error,
        NetdiagError::TrustedTemporaryDirectoryCleanupAfterSuccess {
            source: netdiag_platform::TrustedTempDirectoryError::CleanupSkipped { .. },
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn finish_preserves_operation_and_cleanup_failures() {
    use std::error::Error;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let directory = ManagedTempDirectory::create("managed temp test", "netdiag-managed-dual-")
        .expect("managed directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced");
    fs::rename(&path, &displaced).expect("displace managed directory");
    fs::create_dir(&path).expect("replacement directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("replacement mode");
    let error = directory
        .finish::<()>(Err(NetdiagError::InvalidTrace("operation".to_string())))
        .expect_err("operation and cleanup must fail");
    fs::remove_dir_all(&path).expect("remove replacement fixture");
    fs::remove_dir_all(&displaced).expect("remove displaced fixture");

    let (operation, cleanup) = match &error {
        NetdiagError::TrustedTemporaryDirectoryOperationAndCleanup {
            operation, cleanup, ..
        } => (operation, cleanup),
        other => panic!("expected structured dual failure: {other}"),
    };
    assert!(matches!(operation.as_ref(), NetdiagError::InvalidTrace(_)));
    assert!(matches!(
        cleanup,
        netdiag_platform::TrustedTempDirectoryError::CleanupSkipped { .. }
    ));
    assert_eq!(
        error.source().expect("operation source").to_string(),
        operation.to_string()
    );
}
