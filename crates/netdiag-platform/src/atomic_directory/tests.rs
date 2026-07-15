use super::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::{create_new_private_trusted_subdirectory, open_trusted_directory_chain};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn new_staging_directories_are_owner_private_and_never_reuse_collisions() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("temporary root");
    let parent = open_trusted_directory_chain(root.path()).expect("trusted parent");
    let staged = create_new_private_trusted_subdirectory(&parent, OsStr::new("stage"))
        .expect("private stage");
    assert_eq!(
        staged
            .as_file()
            .metadata()
            .expect("stage metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    std::fs::write(staged.resolved_path().join("sentinel"), b"existing").expect("sentinel");

    let error = create_new_private_trusted_subdirectory(&parent, OsStr::new("stage"))
        .expect_err("an existing stage must be a collision");

    assert!(matches!(
        error,
        crate::DirectoryTrustError::Inspect { source, .. }
            if source.kind() == io::ErrorKind::AlreadyExists
    ));
    assert_eq!(
        std::fs::read(staged.resolved_path().join("sentinel")).expect("preserved sentinel"),
        b"existing"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn target_collision_preserves_both_existing_target_and_staged_source() {
    let root = tempfile::tempdir().expect("temporary root");
    let parent = open_trusted_directory_chain(root.path()).expect("trusted parent");
    let staged = create_new_private_trusted_subdirectory(&parent, OsStr::new("stage"))
        .expect("private stage");
    std::fs::create_dir(root.path().join("run")).expect("existing target");
    std::fs::write(root.path().join("run/sentinel"), b"existing").expect("sentinel");

    let error =
        publish_directory_noclobber_at(&parent, &staged, OsStr::new("stage"), OsStr::new("run"))
            .expect_err("collision must not clobber");

    assert_eq!(error.state(), crate::AtomicPublicationState::NotPublished);
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read(root.path().join("run/sentinel")).expect("preserved sentinel"),
        b"existing"
    );
    assert!(root.path().join("stage").is_dir());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn publication_stays_bound_after_parent_path_replacement() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary root");
    let parent_path = root.path().join("runs");
    let replacement = root.path().join("replacement");
    std::fs::create_dir(&parent_path).expect("runs parent");
    std::fs::create_dir(&replacement).expect("replacement parent");
    let parent = open_trusted_directory_chain(&parent_path).expect("trusted runs parent");
    let staged = create_new_private_trusted_subdirectory(&parent, OsStr::new("stage"))
        .expect("private stage");
    std::fs::write(staged.resolved_path().join("artifact"), b"published").expect("staged artifact");

    let displaced = root.path().join("displaced");
    std::fs::rename(&parent_path, &displaced).expect("displace runs parent");
    symlink(&replacement, &parent_path).expect("replace runs path");

    publish_directory_noclobber_at(&parent, &staged, OsStr::new("stage"), OsStr::new("run"))
        .expect("bound directory publication");

    assert_eq!(
        std::fs::read(displaced.join("run/artifact")).expect("published artifact"),
        b"published"
    );
    assert!(!replacement.join("run").exists());
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn unsupported_platform_fails_before_publication() {
    let error = ensure_directory_noclobber_publication_supported()
        .expect_err("unsupported platform must fail closed");
    assert_eq!(error.state(), crate::AtomicPublicationState::NotPublished);
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
}
