#![cfg(target_os = "linux")]

use netdiag_platform::validate_fd_acl_trust;
use rustix::process::geteuid;
use std::fs::File;
use std::io::ErrorKind;
use std::os::fd::AsFd;
use std::process::Command;

#[test]
fn inheritable_default_acl_is_rejected_when_supported() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = match Command::new("setfacl")
        .args(["-d", "-m", "u::rwx,g::rwx,o::---"])
        .arg(temp.path())
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == ErrorKind::NotFound => return,
        Err(error) => panic!("failed to run setfacl fixture: {error}"),
    };
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr).contains("Operation not supported")
    {
        return;
    }
    assert!(
        output.status.success(),
        "setfacl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let directory = File::open(temp.path()).expect("opened ACL directory");

    let error = validate_fd_acl_trust(directory.as_fd(), geteuid().as_raw())
        .expect_err("inheritable default ACL must fail closed");
    assert!(error.to_string().contains("default ACL"), "{error}");
}
