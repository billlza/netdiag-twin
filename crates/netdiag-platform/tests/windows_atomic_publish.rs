#![cfg(windows)]

use netdiag_platform::{
    create_new_private_file, move_file_noreplace_write_through, open_private_coordination_file,
    replace_file_write_through, validate_private_coordination_file,
};
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::fs::symlink_file;
use std::path::PathBuf;

#[test]
fn write_through_publish_replaces_an_existing_file() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let temporary = directory.path().join("state.json.pending");
    let target = directory.path().join("state.json");
    fs::write(&temporary, b"new").expect("temporary contents");
    fs::write(&target, b"old").expect("target contents");

    replace_file_write_through(&temporary, &target).expect("write-through publish");

    assert_eq!(fs::read(&target).expect("published contents"), b"new");
    assert!(!temporary.exists());
}

#[test]
fn write_through_publish_replaces_a_file_symlink_without_touching_its_target() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let temporary = directory.path().join("state.json.pending");
    let victim = directory.path().join("victim.json");
    let target = directory.path().join("state.json");
    fs::write(&temporary, b"new").expect("temporary contents");
    fs::write(&victim, b"preserve").expect("victim contents");
    symlink_file(&victim, &target).expect("file symlink fixture");

    replace_file_write_through(&temporary, &target).expect("write-through publish");

    assert_eq!(fs::read(&target).expect("published contents"), b"new");
    assert_eq!(fs::read(&victim).expect("preserved victim"), b"preserve");
    assert!(
        fs::symlink_metadata(&target)
            .expect("target metadata")
            .file_type()
            .is_file()
    );
    assert!(!temporary.exists());
}

#[test]
fn failed_publish_preserves_a_readonly_target() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let temporary = directory.path().join("state.json.pending");
    let target = directory.path().join("state.json");
    fs::write(&temporary, b"new").expect("temporary contents");
    fs::write(&target, b"old").expect("target contents");
    let writable_permissions = fs::metadata(&temporary)
        .expect("temporary metadata")
        .permissions();
    let mut permissions = fs::metadata(&target)
        .expect("target metadata")
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&target, permissions).expect("readonly target");

    replace_file_write_through(&temporary, &target).expect_err("readonly target must fail closed");

    assert_eq!(fs::read(&target).expect("preserved target"), b"old");
    assert_eq!(fs::read(&temporary).expect("preserved source"), b"new");
    fs::set_permissions(&target, writable_permissions).expect("restore writable target");
}

#[test]
fn write_through_noreplace_publish_preserves_an_existing_target() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let temporary = directory.path().join("state.json.pending");
    let target = directory.path().join("state.json");
    fs::write(&temporary, b"new").expect("temporary contents");
    fs::write(&target, b"old").expect("target contents");

    move_file_noreplace_write_through(&temporary, &target)
        .expect_err("no-replace publish must reject a collision");

    assert_eq!(fs::read(&target).expect("preserved target"), b"old");
    assert_eq!(fs::read(&temporary).expect("preserved source"), b"new");
}

#[test]
fn write_through_noreplace_publish_moves_to_an_absent_target() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let temporary = directory.path().join("state.json.pending");
    let target = directory.path().join("state.json");
    fs::write(&temporary, b"new").expect("temporary contents");

    move_file_noreplace_write_through(&temporary, &target).expect("no-replace publish");

    assert_eq!(fs::read(&target).expect("published target"), b"new");
    assert!(!temporary.exists());
}

#[test]
fn interior_nul_path_is_rejected_before_calling_windows() {
    let invalid = PathBuf::from(OsString::from_wide(&[b'a' as u16, 0, b'b' as u16]));
    let error = replace_file_write_through(&invalid, PathBuf::from("target").as_path())
        .expect_err("interior NUL must be rejected");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}

#[test]
fn private_file_creation_is_exclusive_and_preserves_collisions() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("state.pending");
    fs::write(&path, b"existing").expect("existing contents");

    let error = create_new_private_file(&path).expect_err("collision must fail closed");

    assert_eq!(error.kind(), ErrorKind::AlreadyExists);
    assert_eq!(fs::read(path).expect("preserved contents"), b"existing");
}

#[test]
fn private_file_creation_applies_a_validated_protected_dacl() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("state.pending");
    drop(create_new_private_file(&path).expect("private file"));

    let file = open_private_coordination_file(&path).expect("reopen private file");
    validate_private_coordination_file(&path, &file).expect("protected private DACL");
}

#[test]
fn private_file_creation_rejects_interior_nul_paths() {
    let invalid = PathBuf::from(OsString::from_wide(&[b'a' as u16, 0, b'b' as u16]));
    let error = create_new_private_file(&invalid).expect_err("interior NUL must fail closed");

    assert_eq!(error.kind(), ErrorKind::InvalidInput);
}
