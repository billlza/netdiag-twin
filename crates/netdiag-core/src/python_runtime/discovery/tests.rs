use super::*;
use crate::python_runtime::tests::trusted_tempdir;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

fn path_for(path: &std::path::Path) -> std::ffi::OsString {
    env::join_paths([path]).expect("single path entry")
}

#[test]
fn discovery_requires_path_and_reports_empty_trusted_search() {
    let missing = resolve_from_path(None).expect_err("missing PATH must fail closed");
    assert!(missing.to_string().contains("PATH is not set"));

    let temp = trusted_tempdir();
    let path = path_for(temp.path());
    let empty =
        resolve_from_path(Some(&path)).expect_err("trusted directory without python3 must fail");
    assert!(empty.to_string().contains("contained no python3 candidate"));
}

#[test]
fn discovery_rejects_non_file_and_untrusted_python_candidates() {
    let temp = trusted_tempdir();
    let candidate = temp.path().join("python3");
    fs::create_dir(&candidate).expect("directory candidate");
    let path = path_for(temp.path());
    let directory =
        resolve_from_path(Some(&path)).expect_err("directory candidate must not be executable");
    assert!(directory.to_string().contains("regular file"));

    fs::remove_dir(&candidate).expect("remove directory candidate");
    fs::write(&candidate, b"#!/bin/sh\n").expect("candidate file");
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o644))
        .expect("non-executable permissions");
    let non_executable =
        resolve_from_path(Some(&path)).expect_err("non-executable candidate must fail");
    assert!(non_executable.to_string().contains("not executable"));
}

#[test]
fn discovery_accepts_trusted_canonical_python_candidate() {
    let temp = trusted_tempdir();
    let executable = env::current_exe().expect("current executable");
    symlink(&executable, temp.path().join("python3")).expect("python3 symlink");
    let path = path_for(temp.path());

    let resolved = resolve_from_path(Some(&path)).expect("trusted candidate");

    assert_eq!(
        resolved.path,
        executable.canonicalize().expect("canonical exe")
    );
    assert_eq!(
        resolved.runtime_path,
        temp.path()
            .canonicalize()
            .expect("canonical temporary path")
            .to_str()
            .expect("Unicode path")
    );
}

#[test]
fn discovery_rejects_inaccessible_path_without_falling_back_to_untrusted_code() {
    let temp = trusted_tempdir();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o000))
        .expect("inaccessible directory");
    let path = path_for(temp.path());
    let error =
        resolve_from_path(Some(&path)).expect_err("inaccessible candidate lookup must fail closed");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))
        .expect("restore temporary directory permissions");

    assert!(error.to_string().contains("no trusted executable"));
}

#[test]
fn discovery_records_candidate_symlink_loop_as_canonicalization_error() {
    let temp = trusted_tempdir();
    let candidate = temp.path().join("python3");
    symlink("python3", &candidate).expect("self-referential candidate symlink");
    let path = path_for(temp.path());

    let error = resolve_from_path(Some(&path))
        .expect_err("candidate canonicalization errors must fail without fallback");

    let message = error.to_string();
    assert!(
        message.contains("interpreter_canonicalize_error"),
        "{message}"
    );
    assert!(
        message.contains(&candidate.display().to_string()),
        "{message}"
    );
}
