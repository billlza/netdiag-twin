use command_group::GroupChild;
use std::io;
use std::thread;
use std::time::{Duration, Instant};

use super::capture::{DrainOutcome, ProcessCapture};

pub(super) const TERMINATION_DEADLINE: Duration = Duration::from_secs(2);

pub(super) fn terminate(
    child: &mut GroupChild,
    mut capture: Option<ProcessCapture>,
) -> (Vec<u8>, Vec<String>) {
    let deadline = Instant::now() + TERMINATION_DEADLINE;
    let mut details = terminate_process_group(child, deadline);
    let stderr = capture
        .as_mut()
        .map(|capture| {
            append_drain_outcome(&mut details, capture.drain_until(deadline));
            capture.stderr().to_vec()
        })
        .unwrap_or_default();
    (stderr, details)
}

fn terminate_process_group(child: &mut GroupChild, deadline: Instant) -> Vec<String> {
    let mut failures = Vec::new();
    if let Err(error) = child.kill() {
        append_kill_error(&mut failures, error);
    }
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                failures.push("process_tree_wait_error=deadline_exceeded".to_string());
                break;
            }
            Err(error) => {
                failures.push(format!("process_tree_wait_error={error:?}"));
                break;
            }
        }
    }
    failures
}

fn append_drain_outcome(details: &mut Vec<String>, outcome: DrainOutcome) {
    match outcome {
        DrainOutcome::Complete => {}
        DrainOutcome::DeadlineExceeded => {
            details.push("process_output_drain_error=deadline_exceeded".to_string());
        }
        DrainOutcome::OutputLimit(limit) => details.push(format!(
            "process_output_drain_error=limit_exceeded, stream={}, limit_bytes={}",
            limit.stream_name, limit.limit
        )),
        DrainOutcome::ReadFailure(error) => {
            details.push(format!("process_output_drain_error={error}"));
        }
    }
}

fn append_kill_error(failures: &mut Vec<String>, error: io::Error) {
    if error.kind() != io::ErrorKind::InvalidInput && error.kind() != io::ErrorKind::NotFound {
        failures.push(format!("process_tree_kill_error={error:?}"));
    }
}

#[cfg(test)]
mod tests;
