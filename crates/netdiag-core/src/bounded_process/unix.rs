use super::capture::{DrainOutcome, ProcessCapture};
use super::termination::terminate;
use super::{BoundedCommand, ProcessFailure, ProcessFailureReason, ProcessLimits};
use command_group::{CommandGroup, GroupChild};
use std::process::{ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const OUTPUT_DRAIN_DEADLINE: Duration = Duration::from_millis(500);

pub(super) fn run(
    mut bounded: BoundedCommand,
    limits: ProcessLimits,
    cancelled: &dyn Fn() -> bool,
) -> std::result::Result<Output, ProcessFailure> {
    if !bounded.executable.is_absolute() {
        return Err(failure(
            limits,
            ProcessFailureReason::Output("process executable must be absolute".to_string()),
        ));
    }
    bounded
        .command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = bounded
        .command
        .group_spawn()
        .map_err(|error| ProcessFailure {
            timeout: limits.timeout,
            reason: ProcessFailureReason::Spawn(error),
            stderr: Vec::new(),
            cleanup_details: Vec::new(),
        })?;
    let capture = prepare_capture(limits, &mut child)?;
    wait_for_exit(limits, &mut child, capture, cancelled)
}

fn prepare_capture(
    limits: ProcessLimits,
    child: &mut GroupChild,
) -> std::result::Result<ProcessCapture, ProcessFailure> {
    let stdout = child.inner().stdout.take().ok_or_else(|| {
        setup_failure(
            limits,
            child,
            "process stdout pipe was not available".to_string(),
        )
    })?;
    let stderr = child.inner().stderr.take().ok_or_else(|| {
        setup_failure(
            limits,
            child,
            "process stderr pipe was not available".to_string(),
        )
    })?;
    ProcessCapture::new(stdout, stderr, limits.stdout_bytes, limits.stderr_bytes)
        .map_err(|error| setup_failure(limits, child, error.to_string()))
}

fn wait_for_exit(
    limits: ProcessLimits,
    child: &mut GroupChild,
    mut capture: ProcessCapture,
    cancelled: &dyn Fn() -> bool,
) -> std::result::Result<Output, ProcessFailure> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return finish_after_exit(limits, child, status, capture),
            Ok(None) => {}
            Err(error) => {
                return Err(runtime_failure(
                    limits,
                    child,
                    capture,
                    ProcessFailureReason::Wait(error),
                ));
            }
        }
        let reason = if cancelled() {
            Some(ProcessFailureReason::Cancelled)
        } else if started.elapsed() >= limits.timeout {
            Some(ProcessFailureReason::Timeout)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(runtime_failure(limits, child, capture, reason));
        }
        let poll_timeout =
            PROCESS_POLL_INTERVAL.min(limits.timeout.saturating_sub(started.elapsed()));
        match capture.poll_once(poll_timeout) {
            Ok(Some(limit)) => {
                return Err(runtime_failure(
                    limits,
                    child,
                    capture,
                    ProcessFailureReason::OutputLimit {
                        stream_name: limit.stream_name,
                        limit: limit.limit,
                    },
                ));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(runtime_failure(
                    limits,
                    child,
                    capture,
                    ProcessFailureReason::Output(error.to_string()),
                ));
            }
        }
    }
}

fn finish_after_exit(
    limits: ProcessLimits,
    child: &mut GroupChild,
    status: ExitStatus,
    mut capture: ProcessCapture,
) -> std::result::Result<Output, ProcessFailure> {
    match capture.drain_until(Instant::now() + OUTPUT_DRAIN_DEADLINE) {
        DrainOutcome::Complete => Ok(capture.into_output(status)),
        DrainOutcome::DeadlineExceeded => Err(runtime_failure(
            limits,
            child,
            capture,
            ProcessFailureReason::Output(
                "process output pipes remained open past the post-exit drain deadline".to_string(),
            ),
        )),
        DrainOutcome::OutputLimit(limit) => Err(runtime_failure(
            limits,
            child,
            capture,
            ProcessFailureReason::OutputLimit {
                stream_name: limit.stream_name,
                limit: limit.limit,
            },
        )),
        DrainOutcome::ReadFailure(error) => Err(runtime_failure(
            limits,
            child,
            capture,
            ProcessFailureReason::Output(error.to_string()),
        )),
    }
}

fn setup_failure(limits: ProcessLimits, child: &mut GroupChild, cause: String) -> ProcessFailure {
    let (stderr, cleanup_details) = terminate(child, None);
    ProcessFailure {
        timeout: limits.timeout,
        reason: ProcessFailureReason::Output(cause),
        stderr,
        cleanup_details,
    }
}

fn runtime_failure(
    limits: ProcessLimits,
    child: &mut GroupChild,
    capture: ProcessCapture,
    reason: ProcessFailureReason,
) -> ProcessFailure {
    let (stderr, cleanup_details) = terminate(child, Some(capture));
    ProcessFailure {
        timeout: limits.timeout,
        reason,
        stderr,
        cleanup_details,
    }
}

fn failure(limits: ProcessLimits, reason: ProcessFailureReason) -> ProcessFailure {
    ProcessFailure {
        timeout: limits.timeout,
        reason,
        stderr: Vec::new(),
        cleanup_details: Vec::new(),
    }
}
