use super::*;
use crate::python_runtime::tests::trusted_tempdir;
use std::fs;
use std::os::unix::fs::PermissionsExt;
#[cfg(target_os = "macos")]
use std::process::Command;

#[test]
fn trusted_interpreter_validation_covers_identity_permissions_and_executable_bits() {
    let no_parent = validate_trusted_interpreter(Path::new("/"))
        .expect_err("root path has no interpreter parent");
    assert!(no_parent.to_string().contains("no parent directory"));

    let temp = trusted_tempdir();
    let missing = temp.path().join("missing-python");
    let missing_error = validate_trusted_interpreter(&missing)
        .expect_err("missing interpreter must fail inspection");
    assert!(matches!(
        &missing_error,
        NetdiagError::FilesystemTrust {
            context: "Python interpreter",
            ..
        }
    ));
    assert!(missing_error.to_string().contains("failed to inspect"));
    assert!(std::error::Error::source(&missing_error).is_some());

    let candidate = temp.path().join("python3");
    fs::write(&candidate, b"#!/bin/sh\n").expect("candidate file");
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o644))
        .expect("non-executable permissions");
    let not_executable =
        validate_trusted_interpreter(&candidate).expect_err("non-executable interpreter must fail");
    assert!(not_executable.to_string().contains("not executable"));

    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o777))
        .expect("writable permissions");
    let writable =
        validate_trusted_interpreter(&candidate).expect_err("writable interpreter must fail");
    assert!(writable.to_string().contains("group/world-writable"));

    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))
        .expect("trusted executable permissions");
    validate_trusted_interpreter(&candidate).expect("trusted executable");
}

#[test]
fn trusted_directory_chain_rejects_missing_files_and_writable_components() {
    let temp = trusted_tempdir();
    let missing = temp.path().join("missing");
    let missing_error = validate_trusted_directory_chain(&missing)
        .expect_err("missing directory must fail inspection");
    assert!(
        missing_error
            .to_string()
            .contains("failed to inspect trusted path")
    );

    let file = temp.path().join("not-a-directory");
    fs::write(&file, b"file").expect("file component");
    let file_error =
        validate_trusted_directory_chain(&file).expect_err("file cannot be a PATH directory");
    assert!(file_error.to_string().contains("not a directory"));

    let writable = temp.path().join("writable");
    fs::create_dir(&writable).expect("writable directory");
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
        .expect("writable permissions");
    let writable_error =
        validate_trusted_directory_chain(&writable).expect_err("writable PATH component must fail");
    assert!(writable_error.to_string().contains("group/world-writable"));
}

#[cfg(target_os = "macos")]
#[test]
fn interpreter_rejects_named_user_write_acl_hidden_by_mode() {
    let temp = trusted_tempdir();
    let candidate = temp.path().join("python");
    fs::write(&candidate, b"#!/bin/sh\n").expect("candidate file");
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o555)).expect("executable mode");
    let status = Command::new("/bin/chmod")
        .args(["+a", "user:nobody allow write,append,writesecurity,chown"])
        .arg(&candidate)
        .status()
        .expect("set interpreter ACL fixture");
    assert!(status.success());

    let result = validate_trusted_interpreter(&candidate);
    let status = Command::new("/bin/chmod")
        .arg("-N")
        .arg(&candidate)
        .status()
        .expect("clear interpreter ACL fixture");
    assert!(status.success());
    let error = result.expect_err("interpreter write ACL must fail closed");
    assert!(error.to_string().contains("unsafe ACL"), "{error}");
}
