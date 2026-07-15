use super::*;
use crate::python_runtime::tests::trusted_tempdir;

#[test]
fn configured_interpreter_must_be_absolute() {
    let error = resolve_configured_interpreter("python3")
        .expect_err("relative configured interpreter must fail");
    assert!(error.to_string().contains("must be an absolute path"));
}

#[test]
fn configured_interpreter_rejects_empty_oversized_missing_and_non_files() {
    for invalid in [
        "",
        "   ",
        &"x".repeat(MAX_CONFIGURED_INTERPRETER_PATH_BYTES + 1),
    ] {
        let error = resolve_configured_interpreter(invalid)
            .expect_err("empty or oversized configured path must fail");
        assert!(error.to_string().contains("must contain"), "{error}");
    }

    let temp = trusted_tempdir();
    let missing = temp.path().join("missing-python");
    let missing_error =
        resolve_configured_interpreter(missing.to_str().expect("Unicode temporary path"))
            .expect_err("missing configured interpreter must fail");
    assert!(missing_error.to_string().contains("failed to canonicalize"));

    let directory_error =
        validate_interpreter(temp.path()).expect_err("directory cannot be used as an interpreter");
    assert!(directory_error.to_string().contains("regular file"));
    let relative_error = validate_interpreter(Path::new("python3"))
        .expect_err("relative interpreter validation must fail");
    assert!(relative_error.to_string().contains("absolute regular file"));

    let root_error = resolve_configured_interpreter("/")
        .expect_err("filesystem root cannot supply an interpreter parent");
    assert!(root_error.to_string().contains("has no parent directory"));
}

#[cfg(unix)]
#[test]
fn configured_interpreter_requires_trusted_executable_and_returns_sanitized_path() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temp = trusted_tempdir();
    let candidate = temp.path().join("python3");
    fs::write(&candidate, b"#!/bin/sh\n").expect("candidate");
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o644))
        .expect("non-executable permissions");
    let not_executable =
        validate_interpreter(&candidate).expect_err("non-executable configured file must fail");
    assert!(not_executable.to_string().contains("not executable"));

    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o777))
        .expect("writable permissions");
    let writable =
        validate_interpreter(&candidate).expect_err("writable configured interpreter must fail");
    assert!(writable.to_string().contains("group/world-writable"));

    let executable = std::env::current_exe().expect("current executable");
    let resolved =
        resolve_configured_interpreter(executable.to_str().expect("Unicode executable path"))
            .expect("current executable is a trusted regular executable");
    assert_eq!(
        resolved.path,
        executable.canonicalize().expect("canonical exe")
    );
    assert_eq!(
        resolved.runtime_path,
        executable
            .canonicalize()
            .expect("canonical exe")
            .parent()
            .expect("executable parent")
            .to_str()
            .expect("Unicode parent")
    );
}
