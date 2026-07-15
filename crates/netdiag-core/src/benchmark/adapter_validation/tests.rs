use super::unix::execute_validator;
use crate::bounded_process::ProcessLimits;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const RESPONSIVE_VALIDATOR_TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn executable_script(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).expect("write fake Python");
    let mut permissions = fs::metadata(&path).expect("fake metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).expect("mark fake executable");
    path
}

fn limits(timeout: Duration, stdout_bytes: usize, stderr_bytes: usize) -> ProcessLimits {
    ProcessLimits {
        timeout,
        stdout_bytes,
        stderr_bytes,
    }
}

fn placeholder_script(directory: &Path) -> PathBuf {
    let path = directory.join("validator.py");
    fs::write(&path, b"# controlled placeholder\n").expect("placeholder validator");
    path
}

#[test]
fn validator_timeout_is_bounded_and_names_the_script_without_leaking_stderr() {
    let directory = tempfile::tempdir().expect("tempdir");
    let sentinel = "validator-timeout-private-sentinel";
    let executable = executable_script(
        directory.path(),
        "slow-python",
        &format!("printf '{sentinel}' >&2; exec /bin/sleep 60"),
    );
    let script = placeholder_script(directory.path());
    let started = Instant::now();

    let error = execute_validator(
        &executable,
        "/usr/bin:/bin",
        &script,
        directory.path(),
        "slow-validator.py",
        limits(Duration::from_millis(40), 128, 128),
    )
    .expect_err("slow validator must time out");

    let message = error.to_string();
    assert!(message.contains("slow-validator.py"), "{message}");
    assert!(message.contains("reason=timeout"), "{message}");
    assert!(!message.contains(sentinel), "{message}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn validator_output_limit_is_explicit_and_does_not_leak_output() {
    let directory = tempfile::tempdir().expect("tempdir");
    let sentinel = "123456789";
    let executable = executable_script(
        directory.path(),
        "noisy-python",
        &format!("printf '{sentinel}'; exec /bin/sleep 60"),
    );
    let script = placeholder_script(directory.path());

    let error = execute_validator(
        &executable,
        "/usr/bin:/bin",
        &script,
        directory.path(),
        "noisy-validator.py",
        limits(RESPONSIVE_VALIDATOR_TEST_TIMEOUT, 8, 128),
    )
    .expect_err("noisy validator must exceed its output limit");

    let message = error.to_string();
    assert!(message.contains("noisy-validator.py"), "{message}");
    assert!(message.contains("stream=stdout"), "{message}");
    assert!(message.contains("limit_bytes=8"), "{message}");
    assert!(!message.contains(sentinel), "{message}");
}

#[test]
fn validator_process_receives_only_the_minimal_environment_allowlist() {
    let directory = tempfile::tempdir().expect("tempdir");
    let executable = executable_script(
        directory.path(),
        "environment-python",
        "printf '%s|%s|%s|%s|%s' \"$PATH\" \"$PYTHONNOUSERSITE\" \"$PYTHONDONTWRITEBYTECODE\" \"${HOME-unset}\" \"$*\"",
    );
    let script = placeholder_script(directory.path());

    let output = execute_validator(
        &executable,
        "/trusted/runtime",
        &script,
        directory.path(),
        "environment-validator.py",
        limits(RESPONSIVE_VALIDATOR_TEST_TIMEOUT, 1024, 128),
    )
    .expect("fake validator environment");

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 fake output");
    assert_eq!(
        stdout,
        format!("/trusted/runtime|1|1|unset|-E -B -s {}", script.display())
    );
}
