use super::{BoundedCommand, ProcessFailureReason, ProcessLimits};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const RESPONSIVE_PROCESS_TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn executable_script(directory: &Path, name: &str, body: &str) -> PathBuf {
    let path = directory.join(name);
    fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).expect("write fake program");
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
fn bounded_command_clears_environment_and_captures_both_streams() {
    let directory = tempfile::tempdir().expect("tempdir");
    let program = executable_script(
        directory.path(),
        "environment",
        "printf 'locale=%s/%s inherited=%s' \"${LC_ALL-unset}\" \"${LANG-unset}\" \"${HOME-unset}\"; printf 'stderr' >&2",
    );
    let mut command = BoundedCommand::new(&program);
    command.envs([("LC_ALL", "C"), ("LANG", "C")]);

    let output = command
        .run(limits(RESPONSIVE_PROCESS_TEST_TIMEOUT, 128, 128), &|| false)
        .expect("fake process");

    assert!(output.status.success());
    assert_eq!(output.stdout, b"locale=C/C inherited=unset");
    assert_eq!(output.stderr, b"stderr");
}

#[test]
fn bounded_command_times_out_and_reaps_the_process_group() {
    let directory = tempfile::tempdir().expect("tempdir");
    let program = executable_script(directory.path(), "timeout", "exec /bin/sleep 60");
    let started = Instant::now();

    let failure = BoundedCommand::new(&program)
        .run(limits(Duration::from_millis(40), 128, 128), &|| false)
        .expect_err("fake process must time out");

    assert!(matches!(failure.reason, ProcessFailureReason::Timeout));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(failure.cleanup_details.is_empty(), "{failure:?}");
}

#[test]
fn bounded_command_rejects_output_beyond_each_stream_limit() {
    let directory = tempfile::tempdir().expect("tempdir");
    for (name, body) in [
        ("stdout", "printf '123456789'; exec /bin/sleep 60"),
        ("stderr", "printf '123456789' >&2; exec /bin/sleep 60"),
    ] {
        let program = executable_script(directory.path(), name, body);
        let failure = BoundedCommand::new(&program)
            .run(limits(RESPONSIVE_PROCESS_TEST_TIMEOUT, 8, 8), &|| false)
            .expect_err("oversized output must fail");

        assert!(matches!(
            failure.reason,
            ProcessFailureReason::OutputLimit {
                stream_name,
                limit: 8,
            } if stream_name == name
        ));
        assert!(failure.cleanup_details.is_empty(), "{failure:?}");
    }
}

#[test]
fn bounded_command_honors_cancellation_and_reaps_the_process_group() {
    let directory = tempfile::tempdir().expect("tempdir");
    let program = executable_script(directory.path(), "cancel", "exec /bin/sleep 60");

    let failure = BoundedCommand::new(&program)
        .run(limits(Duration::from_secs(5), 128, 128), &|| true)
        .expect_err("cancelled process must fail");

    assert!(matches!(failure.reason, ProcessFailureReason::Cancelled));
    assert!(failure.cleanup_details.is_empty(), "{failure:?}");
}

#[test]
fn bounded_command_rejects_relative_executables_before_spawn() {
    let failure = BoundedCommand::new(Path::new("fake-program"))
        .run(limits(Duration::from_secs(1), 128, 128), &|| false)
        .expect_err("PATH lookup must be impossible");

    assert!(matches!(
        failure.reason,
        ProcessFailureReason::Output(ref cause) if cause.contains("must be absolute")
    ));
}
