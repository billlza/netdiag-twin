#![cfg(target_os = "macos")]

use netdiag_platform::validate_fd_acl_trust;
use rustix::process::geteuid;
use std::fs::{self, File};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn add_acl(path: &Path, entry: &str) {
    let output = Command::new("/bin/chmod")
        .args(["+a", entry])
        .arg(path)
        .output()
        .expect("run macOS chmod ACL fixture");
    assert!(
        output.status.success(),
        "chmod +a failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn remove_acl(path: &Path) {
    let status = Command::new("/bin/chmod")
        .arg("-N")
        .arg(path)
        .status()
        .expect("remove macOS ACL fixture");
    assert!(status.success(), "chmod -N failed");
}

#[test]
fn opened_file_without_extended_acl_is_accepted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("adapter.py");
    fs::write(&path, b"print('safe')\n").expect("adapter");
    let file = File::open(&path).expect("opened adapter");

    validate_fd_acl_trust(file.as_fd(), geteuid().as_raw())
        .expect("absence of an extended ACL must remain valid");
}

#[test]
fn named_user_write_allow_is_rejected_despite_read_only_mode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("adapter.py");
    fs::write(&path, b"print('safe')\n").expect("adapter");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("read-only mode");
    add_acl(
        &path,
        "user:nobody allow write,append,delete,writeattr,writeextattr,writesecurity,chown",
    );
    let file = File::open(&path).expect("opened adapter");

    let result = validate_fd_acl_trust(file.as_fd(), geteuid().as_raw());
    remove_acl(&path);
    let error = result.expect_err("untrusted named-user write grant must fail closed");
    assert!(error.to_string().contains("untrusted uid"), "{error}");
}

#[test]
fn directory_write_allow_is_rejected_despite_nonwritable_mode() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("trusted");
    fs::create_dir(&path).expect("trusted directory");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o555)).expect("nonwritable mode");
    add_acl(
        &path,
        "group:everyone allow add_file,add_subdirectory,delete_child,writeattr,writeextattr,writesecurity,chown",
    );
    let file = File::open(&path).expect("opened directory");

    let result = validate_fd_acl_trust(file.as_fd(), geteuid().as_raw());
    remove_acl(&path);
    let error = result.expect_err("untrusted directory write grant must fail closed");
    assert!(error.to_string().contains("untrusted gid"), "{error}");
}

#[test]
fn restrictive_everyone_deny_delete_is_accepted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("adapter.py");
    fs::write(&path, b"print('safe')\n").expect("adapter");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("read-only mode");
    add_acl(&path, "group:everyone deny delete");
    let file = File::open(&path).expect("opened adapter");

    let result = validate_fd_acl_trust(file.as_fd(), geteuid().as_raw());
    remove_acl(&path);
    result.expect("restrictive deny ACL must remain valid");
}
