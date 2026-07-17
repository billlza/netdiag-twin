use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const RESPONSIVE_PROCESS_TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn executable_script(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).expect("write fake netstat");
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

#[test]
fn nonzero_netstat_status_never_echoes_stderr() {
    let directory = tempfile::tempdir().expect("tempdir");
    let sentinel = "netstat-private-stderr-sentinel";
    let program = executable_script(
        directory.path(),
        "nonzero",
        &format!("printf '{sentinel}' >&2; exit 7"),
    );

    let error = run_netstat(
        &program,
        &CaptureControl::default(),
        limits(RESPONSIVE_PROCESS_TEST_TIMEOUT, 128, 128),
    )
    .expect_err("nonzero fake netstat must fail");

    let message = error.to_string();
    assert!(message.contains("status"), "{message}");
    assert!(!message.contains(sentinel), "{message}");
}

#[test]
fn fake_netstat_receives_only_fixed_locale_and_arguments() {
    let directory = tempfile::tempdir().expect("tempdir");
    let program = executable_script(
        directory.path(),
        "environment",
        "printf '%s/%s/%s/%s/%s' \"$LC_ALL\" \"$LANG\" \"${HOME-unset}\" \"$#\" \"$1\"",
    );

    let output = run_netstat(
        &program,
        &CaptureControl::default(),
        limits(RESPONSIVE_PROCESS_TEST_TIMEOUT, 128, 128),
    )
    .expect("fake netstat environment");

    assert_eq!(output, b"C/C/unset/1/-ibn");
}

#[test]
fn fake_netstat_timeout_is_bounded_and_does_not_leak_stderr() {
    let directory = tempfile::tempdir().expect("tempdir");
    let sentinel = "netstat-timeout-stderr-sentinel";
    let program = executable_script(
        directory.path(),
        "timeout",
        &format!("printf '{sentinel}' >&2; exec /bin/sleep 60"),
    );
    let started = Instant::now();

    let error = run_netstat(
        &program,
        &CaptureControl::default(),
        limits(Duration::from_millis(40), 128, 128),
    )
    .expect_err("slow fake netstat must time out");

    let message = error.to_string();
    assert!(message.contains("execution deadline"), "{message}");
    assert!(!message.contains(sentinel), "{message}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn fake_netstat_output_limit_is_explicit_and_does_not_leak_bytes() {
    let directory = tempfile::tempdir().expect("tempdir");
    let sentinel = "123456789";
    let program = executable_script(
        directory.path(),
        "oversized",
        &format!("printf '{sentinel}'; exec /bin/sleep 60"),
    );

    let error = run_netstat(
        &program,
        &CaptureControl::default(),
        limits(RESPONSIVE_PROCESS_TEST_TIMEOUT, 8, 128),
    )
    .expect_err("oversized fake netstat output must fail");

    let message = error.to_string();
    assert!(
        message.contains("stdout output limit of 8 bytes"),
        "{message}"
    );
    assert!(!message.contains(sentinel), "{message}");
}

#[test]
fn fake_netstat_honors_capture_cancellation() {
    let directory = tempfile::tempdir().expect("tempdir");
    let program = executable_script(directory.path(), "cancelled", "exec /bin/sleep 60");
    let control = CaptureControl::default();
    control.cancel();

    let error = run_netstat(&program, &control, limits(Duration::from_secs(1), 128, 128))
        .expect_err("cancelled fake netstat must fail");

    assert!(matches!(error, NetdiagError::CaptureCancelled { .. }));
}
