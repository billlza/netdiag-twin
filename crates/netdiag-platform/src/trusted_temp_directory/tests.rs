use super::*;
use std::cell::Cell;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

#[test]
fn system_temporary_root_failure_is_preserved_as_the_error_source() {
    let platform_error = crate::SystemTemporaryRootError::Query {
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "query denied"),
    };
    let error = TrustedTempDirectoryError::SystemTemporaryRoot {
        source: platform_error,
    };

    assert!(
        error
            .to_string()
            .contains("trusted temporary directory root")
    );
    assert!(matches!(
        error.source(),
        Some(source) if source.downcast_ref::<crate::SystemTemporaryRootError>().is_some()
    ));
}

#[derive(Debug)]
struct OperationFixture;

impl fmt::Display for OperationFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operation fixture")
    }
}

impl Error for OperationFixture {}

fn unique_candidate_fixture() -> (TrustedTempDirectory, PathBuf, String, String) {
    let anchor = TrustedTempDirectory::create("ndt-").expect("unique fixture anchor");
    let root = anchor
        .path()
        .parent()
        .expect("temporary root")
        .to_path_buf();
    let anchor_name = anchor
        .path()
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .expect("ASCII anchor name");
    let prefix = format!("{anchor_name}-");
    let candidate = format!("{prefix}{}", "0".repeat(32));
    (anchor, root, prefix, candidate)
}

fn create_with(
    prefix: &str,
    root: &Path,
    mut next_name: impl FnMut() -> Result<String, TrustedTempDirectoryError>,
    mut create_entry: impl FnMut(&Path) -> Result<bool, TrustedTempDirectoryError>,
    mut after_create: impl FnMut(&Path),
) -> Result<TrustedTempDirectory, TrustedTempDirectoryError> {
    create::create_with(
        prefix,
        root,
        &mut next_name,
        &mut create_entry,
        &mut after_create,
    )
}

#[test]
fn creates_private_directory_and_removes_it_explicitly() {
    let directory = TrustedTempDirectory::create("netdiag-platform-test-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    assert!(path.is_dir());
    directory.validate_identity().expect("stable identity");
    directory.close().expect("explicit cleanup");
    assert!(!path.exists());
}

#[test]
fn rejects_unsafe_prefixes_before_creation() {
    for prefix in ["", "../escape-", "nested/name-", &"a".repeat(65)] {
        let error = TrustedTempDirectory::create(prefix)
            .expect_err("unsafe prefix must fail before directory creation");
        assert!(matches!(error, TrustedTempDirectoryError::InvalidPrefix));
    }
}

#[test]
fn generated_names_are_validated_before_creation() {
    let (anchor, root, prefix, _) = unique_candidate_fixture();
    for invalid in [
        format!("{prefix}../escape"),
        format!("{prefix}{}", "A".repeat(32)),
        format!("{prefix}{}", "0".repeat(31)),
    ] {
        let after_create_called = Cell::new(false);
        let error = create_with(
            &prefix,
            &root,
            || Ok(invalid.clone()),
            create::create_candidate,
            |_| after_create_called.set(true),
        )
        .expect_err("invalid generated name must fail before creation");
        assert!(matches!(
            error,
            TrustedTempDirectoryError::InvalidGeneratedName
        ));
        assert!(!after_create_called.get());
    }
    anchor.close().expect("anchor cleanup");
}

#[test]
fn candidate_creation_distinguishes_success_collision_and_io_failure() {
    let (anchor, _, _, _) = unique_candidate_fixture();
    let candidate = anchor.path().join("direct-candidate");
    assert!(create::create_candidate(&candidate).expect("candidate creation"));
    assert!(!create::create_candidate(&candidate).expect("candidate collision"));

    let missing_parent_candidate = anchor.path().join("missing").join("candidate");
    let error = create::create_candidate(&missing_parent_candidate)
        .expect_err("missing parent must remain an I/O error");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::Io {
            context: "trusted temporary directory creation",
            ..
        }
    ));
    anchor.close().expect("anchor cleanup");
}

#[test]
fn generated_name_and_candidate_creation_errors_stop_before_the_post_create_hook() {
    let (anchor, root, prefix, candidate) = unique_candidate_fixture();

    let name_after_create_called = Cell::new(false);
    let name_error = create_with(
        &prefix,
        &root,
        || {
            Err(TrustedTempDirectoryError::StateUnavailable {
                path: PathBuf::from("generated-name-fixture"),
            })
        },
        create::create_candidate,
        |_| name_after_create_called.set(true),
    )
    .expect_err("name generation failure must propagate");
    assert!(matches!(
        name_error,
        TrustedTempDirectoryError::StateUnavailable { .. }
    ));
    assert!(!name_after_create_called.get());

    let creation_after_create_called = Cell::new(false);
    let creation_error = create_with(
        &prefix,
        &root,
        || Ok(candidate.clone()),
        |path| {
            Err(TrustedTempDirectoryError::Io {
                context: "injected candidate creation",
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "creation fixture",
                ),
            })
        },
        |_| creation_after_create_called.set(true),
    )
    .expect_err("candidate creation failure must propagate");
    assert!(matches!(
        creation_error,
        TrustedTempDirectoryError::Io {
            context: "injected candidate creation",
            ..
        }
    ));
    assert!(!creation_after_create_called.get());
    assert!(!root.join(candidate).exists());
    anchor.close().expect("anchor cleanup");
}

#[test]
fn repeated_collisions_fail_at_the_bounded_limit_without_replacing_the_entry() {
    let (anchor, root, prefix, candidate) = unique_candidate_fixture();
    let collision_path = root.join(&candidate);
    assert!(create::create_candidate(&collision_path).expect("collision fixture"));

    let error = create_with(
        &prefix,
        &root,
        || Ok(candidate.clone()),
        create::create_candidate,
        |_| {},
    )
    .expect_err("bounded repeated collisions must fail");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::NameCollisionLimit { .. }
    ));
    assert!(collision_path.is_dir(), "collision entry must be preserved");

    std::fs::remove_dir(&collision_path).expect("collision fixture cleanup");
    anchor.close().expect("anchor cleanup");
}

#[test]
fn creation_failure_cleanup_preserves_primary_and_secondary_errors() {
    let parent = tempfile::tempdir().expect("cleanup fixture parent");
    let empty = parent.path().join("empty");
    std::fs::create_dir(&empty).expect("empty fixture");
    let validation = TrustedTempDirectoryError::IdentityChanged {
        path: empty.clone(),
    };
    let error = cleanup::after_creation_failure(empty.clone(), validation);
    assert!(matches!(
        error,
        TrustedTempDirectoryError::IdentityChanged { .. }
    ));
    assert!(!empty.exists());

    let nonempty = parent.path().join("nonempty");
    std::fs::create_dir(&nonempty).expect("nonempty fixture");
    std::fs::write(nonempty.join("entry"), b"fixture").expect("nonempty entry");
    let validation = TrustedTempDirectoryError::IdentityChanged {
        path: nonempty.clone(),
    };
    let error = cleanup::after_creation_failure(nonempty.clone(), validation);
    assert!(matches!(
        &error,
        TrustedTempDirectoryError::ValidationAndCleanup { path, .. } if path == &nonempty
    ));
    assert!(matches!(
        error.source(),
        Some(source) if source.to_string().contains("identity changed")
    ));
    std::fs::remove_dir_all(nonempty).expect("nonempty fixture cleanup");
}

#[test]
fn cleanup_rejects_a_non_directory_without_deleting_it() {
    let parent = tempfile::tempdir().expect("cleanup fixture parent");
    let file = parent.path().join("regular-file");
    std::fs::write(&file, b"fixture").expect("regular file fixture");
    let error = cleanup::finish(file.clone()).expect_err("non-directory cleanup must fail");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::Io {
            context: "trusted temporary directory cleanup",
            ..
        }
    ));
    assert!(file.is_file(), "cleanup must not remove a non-directory");
}

#[test]
fn validation_and_cleanup_error_keeps_validation_as_source() {
    let validation = TrustedTempDirectoryError::IdentityChanged {
        path: std::path::PathBuf::from("fixture"),
    };
    let error = TrustedTempDirectoryError::ValidationAndCleanup {
        path: std::path::PathBuf::from("fixture"),
        validation: Box::new(validation),
        cleanup: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "cleanup fixture"),
    };
    assert!(matches!(
        error.source(),
        Some(source) if source.to_string().contains("identity changed")
    ));
}

#[cfg(unix)]
#[test]
fn unix_directory_is_atomically_private() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let directory = TrustedTempDirectory::create("netdiag-platform-mode-test-")
        .expect("trusted temporary directory");
    let metadata = std::fs::metadata(directory.path()).expect("temporary metadata");
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    directory.close().expect("explicit cleanup");
}

#[cfg(unix)]
#[test]
fn unix_creation_hook_observes_owner_only_mode_before_identity_open() {
    use std::os::unix::fs::PermissionsExt;

    let (anchor, root, prefix, candidate) = unique_candidate_fixture();
    let observed_mode = Cell::new(None);
    let directory = create_with(
        &prefix,
        &root,
        || Ok(candidate.clone()),
        create::create_candidate,
        |path| {
            let mode = std::fs::symlink_metadata(path)
                .expect("fresh directory metadata")
                .permissions()
                .mode()
                & 0o7777;
            observed_mode.set(Some(mode));
        },
    );
    assert_eq!(observed_mode.get(), Some(0o700));
    directory
        .expect("fresh owner-only directory")
        .close()
        .expect("candidate cleanup");
    anchor.close().expect("anchor cleanup");
}

#[cfg(unix)]
#[test]
fn unix_child_policy_failure_removes_an_empty_candidate() {
    use std::os::unix::fs::PermissionsExt;

    let (anchor, root, prefix, candidate) = unique_candidate_fixture();
    let candidate_path = root.join(&candidate);
    let error = create_with(
        &prefix,
        &root,
        || Ok(candidate.clone()),
        create::create_candidate,
        |path| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500))
                .expect("restrict candidate mode");
        },
    )
    .expect_err("non-0700 child must fail closed");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::ChildPolicy { .. }
    ));
    assert!(
        !candidate_path.exists(),
        "empty failed candidate is cleaned"
    );
    anchor.close().expect("anchor cleanup");
}

#[cfg(unix)]
#[test]
fn unix_child_policy_and_nonempty_cleanup_failures_are_both_preserved() {
    use std::os::unix::fs::PermissionsExt;

    let (anchor, root, prefix, candidate) = unique_candidate_fixture();
    let candidate_path = root.join(&candidate);
    let error = create_with(
        &prefix,
        &root,
        || Ok(candidate.clone()),
        create::create_candidate,
        |path| {
            std::fs::write(path.join("entry"), b"fixture").expect("nonempty candidate");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o500))
                .expect("restrict candidate mode");
        },
    )
    .expect_err("validation and cleanup failures must both surface");
    std::fs::set_permissions(&candidate_path, std::fs::Permissions::from_mode(0o700))
        .expect("restore fixture mode");
    std::fs::remove_dir_all(&candidate_path).expect("failed candidate cleanup");

    assert!(matches!(
        &error,
        TrustedTempDirectoryError::ValidationAndCleanup { path, .. } if path == &candidate_path
    ));
    assert!(matches!(
        error.source(),
        Some(source) if source.to_string().contains("child policy failed")
    ));
    anchor.close().expect("anchor cleanup");
}

#[cfg(unix)]
#[test]
fn unix_user_owned_root_fails_the_system_temporary_root_policy() {
    let root = tempfile::tempdir().expect("user-owned root");
    let prefix = "ndt-root-policy-";
    let candidate = format!("{prefix}{}", "0".repeat(32));
    let error = create_with(
        prefix,
        root.path(),
        || Ok(candidate.clone()),
        create::create_candidate,
        |_| {},
    )
    .expect_err("user-owned root must not impersonate the system temporary root");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::RootPolicy { .. }
    ));
    assert!(!root.path().join(candidate).exists());
}

#[cfg(unix)]
#[test]
fn unix_missing_root_is_a_structured_trust_error() {
    let parent = tempfile::tempdir().expect("missing-root parent");
    let missing = parent.path().join("missing");
    let prefix = "ndt-missing-root-";
    let candidate = format!("{prefix}{}", "0".repeat(32));
    let error = create_with(
        prefix,
        &missing,
        || Ok(candidate.clone()),
        create::create_candidate,
        |_| {},
    )
    .expect_err("missing root must fail explicitly");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::Trust {
            context: "trusted temporary root open",
            ..
        }
    ));
}

#[cfg(unix)]
#[test]
fn unix_root_boundary_preserves_security_and_metadata_errors() {
    use std::os::unix::fs::PermissionsExt;

    let parent = tempfile::tempdir().expect("root-boundary parent");
    let root_path = parent.path().join("opened-root");
    std::fs::create_dir(&root_path).expect("opened root fixture");
    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700))
        .expect("private root fixture");
    let root = crate::open_trusted_directory_chain(&root_path).expect("opened root handle");

    let metadata = create::platform::validate_root_metadata(
        &root,
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "metadata fixture",
        )),
    )
    .expect_err("metadata inspection failure must stay structured");
    assert!(matches!(
        metadata,
        TrustedTempDirectoryError::Io {
            context: "trusted temporary root metadata inspection",
            ..
        }
    ));

    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o777))
        .expect("make root unsafe");
    let security = create::validate_root(&root).expect_err("root security change must fail closed");
    assert!(matches!(
        security,
        TrustedTempDirectoryError::Trust {
            context: "trusted temporary root security validation",
            ..
        }
    ));
    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700))
        .expect("restore root fixture");
}

#[cfg(unix)]
#[test]
fn unix_identity_replacement_is_detected() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TrustedTempDirectory::create("netdiag-platform-identity-test-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced");
    std::fs::rename(&path, &displaced).expect("displace temporary directory");
    std::fs::create_dir(&path).expect("replacement directory");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("replacement mode");
    let error = directory
        .validate_identity()
        .expect_err("replacement must be detected");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::IdentityChanged { .. }
    ));
    drop(directory);
    std::fs::remove_dir_all(path).expect("replacement cleanup");
    std::fs::remove_dir_all(displaced).expect("displaced cleanup");
}

#[cfg(unix)]
#[test]
fn unix_missing_child_path_is_distinct_from_identity_replacement() {
    let directory = TrustedTempDirectory::create("netdiag-platform-missing-child-test-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced-missing");
    std::fs::rename(&path, &displaced).expect("displace temporary directory");

    let error = directory
        .validate_identity()
        .expect_err("missing child path must fail explicitly");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::Trust {
            context: "trusted temporary child identity validation",
            ..
        }
    ));
    drop(directory);
    std::fs::remove_dir_all(displaced).expect("displaced cleanup");
}

#[cfg(unix)]
#[test]
fn unix_prepare_detects_replacement_between_open_and_identity_validation() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TrustedTempDirectory::create("netdiag-platform-prepare-race-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced-prepare");
    let root = directory.root.as_ref().expect("root handle");
    let mut replace_after_open = || {
        std::fs::rename(&path, &displaced).expect("displace opened child");
        std::fs::create_dir(&path).expect("replacement child");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("replacement mode");
    };
    let error = create::prepare_child_with(root, &path, &mut replace_after_open)
        .expect_err("opened child replacement must fail validation");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::IdentityChanged { .. }
    ));
    drop(directory);
    std::fs::remove_dir_all(path).expect("replacement cleanup");
    std::fs::remove_dir_all(displaced).expect("displaced cleanup");
}

#[cfg(unix)]
#[test]
fn close_after_identity_replacement_does_not_delete_replacement() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TrustedTempDirectory::create("netdiag-platform-close-identity-test-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced-close");
    std::fs::rename(&path, &displaced).expect("displace temporary directory");
    std::fs::create_dir(&path).expect("replacement directory");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("replacement mode");

    let error = directory
        .close()
        .expect_err("untrusted replacement must prevent path cleanup");
    assert!(matches!(
        error,
        TrustedTempDirectoryError::CleanupSkipped { .. }
    ));
    assert!(
        path.is_dir(),
        "replacement path must not be recursively removed"
    );
    assert!(displaced.is_dir(), "original directory remains recoverable");
    std::fs::remove_dir_all(path).expect("replacement cleanup");
    std::fs::remove_dir_all(displaced).expect("displaced cleanup");
}

#[test]
fn drop_is_a_best_effort_panic_safety_fallback() {
    let directory = TrustedTempDirectory::create("netdiag-platform-drop-test-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    drop(directory);
    assert!(!path.exists());
}

#[test]
fn finish_preserves_success_and_operation_only_failure() {
    let successful = TrustedTempDirectory::create("netdiag-platform-finish-success-")
        .expect("successful directory");
    let successful_path = successful.path().to_path_buf();
    assert_eq!(
        successful
            .finish::<_, OperationFixture>(Ok(7))
            .expect("successful operation and cleanup"),
        7
    );
    assert!(!successful_path.exists());

    let failed = TrustedTempDirectory::create("netdiag-platform-finish-operation-")
        .expect("failed-operation directory");
    let failed_path = failed.path().to_path_buf();
    let error = failed
        .finish::<(), _>(Err(OperationFixture))
        .expect_err("operation error must propagate after cleanup");
    assert!(matches!(
        error,
        TrustedTempDirectoryFinishError::Operation(OperationFixture)
    ));
    assert!(!failed_path.exists());
}

#[test]
fn finish_error_display_and_sources_preserve_each_failure_shape() {
    let operation = TrustedTempDirectoryFinishError::Operation(OperationFixture);
    assert_eq!(operation.to_string(), "operation fixture");
    assert!(matches!(
        operation.source(),
        Some(source) if source.to_string() == "operation fixture"
    ));

    let cleanup = TrustedTempDirectoryError::StateUnavailable {
        path: PathBuf::from("cleanup-fixture"),
    };
    let cleanup_only = TrustedTempDirectoryFinishError::<OperationFixture>::Cleanup(cleanup);
    assert!(cleanup_only.to_string().contains("state is unavailable"));
    assert!(matches!(
        cleanup_only.source(),
        Some(source) if source.to_string().contains("state is unavailable")
    ));

    let both = TrustedTempDirectoryFinishError::OperationAndCleanup {
        operation: OperationFixture,
        cleanup: TrustedTempDirectoryError::StateUnavailable {
            path: PathBuf::from("double-failure-fixture"),
        },
    };
    let rendered = both.to_string();
    assert!(rendered.contains("operation failed: operation fixture"));
    assert!(rendered.contains("cleanup also failed"));
    assert!(matches!(
        both.source(),
        Some(source) if source.to_string() == "operation fixture"
    ));
}

#[cfg(unix)]
#[test]
fn finish_keeps_operation_as_source_when_identity_blocks_cleanup() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TrustedTempDirectory::create("netdiag-platform-finish-double-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced-finish");
    std::fs::rename(&path, &displaced).expect("displace temporary directory");
    std::fs::create_dir(&path).expect("replacement directory");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("replacement mode");

    let error = directory
        .finish::<(), _>(Err(OperationFixture))
        .expect_err("operation and cleanup must both remain visible");
    assert!(matches!(
        &error,
        TrustedTempDirectoryFinishError::OperationAndCleanup {
            operation: OperationFixture,
            cleanup: TrustedTempDirectoryError::CleanupSkipped { .. },
        }
    ));
    assert!(matches!(
        error.source(),
        Some(source) if source.to_string() == "operation fixture"
    ));
    assert!(path.is_dir());
    std::fs::remove_dir_all(path).expect("replacement cleanup");
    std::fs::remove_dir_all(displaced).expect("displaced cleanup");
}

#[cfg(unix)]
#[test]
fn finish_reports_cleanup_only_failure_and_preserves_replacement() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TrustedTempDirectory::create("netdiag-platform-finish-cleanup-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    let displaced = path.with_extension("displaced-cleanup-only");
    std::fs::rename(&path, &displaced).expect("displace temporary directory");
    std::fs::create_dir(&path).expect("replacement directory");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("replacement mode");

    let error = directory
        .finish::<_, OperationFixture>(Ok(7))
        .expect_err("cleanup-only failure must remain structured");
    assert!(matches!(
        &error,
        TrustedTempDirectoryFinishError::Cleanup(TrustedTempDirectoryError::CleanupSkipped { .. })
    ));
    assert!(matches!(
        error.source(),
        Some(source) if source.to_string().contains("cleanup was skipped")
    ));
    assert!(path.is_dir(), "replacement path must be preserved");
    std::fs::remove_dir_all(path).expect("replacement cleanup");
    std::fs::remove_dir_all(displaced).expect("displaced cleanup");
}

#[cfg(unix)]
#[test]
fn unix_open_and_validation_failures_remain_distinguishable() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TrustedTempDirectory::create("netdiag-platform-identity-errors-")
        .expect("trusted temporary directory");
    let path = directory.path().to_path_buf();
    let root = directory.root.as_ref().expect("root handle");

    let no_name = identity::open(root, Path::new("/")).expect_err("missing final component");
    assert!(matches!(
        no_name,
        TrustedTempDirectoryError::ChildPolicy { .. }
    ));
    let missing = path.with_extension("missing-child");
    let missing_error = identity::open(root, &missing).expect_err("missing child");
    assert!(matches!(
        missing_error,
        TrustedTempDirectoryError::Trust {
            context: "trusted temporary child open",
            ..
        }
    ));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777))
        .expect("make opened child unsafe");
    let validation_error = directory
        .validate_identity()
        .expect_err("opened handle security change must fail");
    assert!(matches!(
        validation_error,
        TrustedTempDirectoryError::Trust {
            context: "trusted temporary child handle validation",
            ..
        }
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .expect("restore child mode");
    directory.close().expect("directory cleanup");
}
