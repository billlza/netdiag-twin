use super::CaptureControl;
use crate::bounded_process::{BoundedCommand, ProcessFailure, ProcessFailureReason, ProcessLimits};
use crate::error::{NetdiagError, Result};
use std::path::Path;
use std::time::Duration;

pub(super) const NETSTAT_PROGRAM: &str = "/usr/sbin/netstat";

const NETSTAT_LIMITS: ProcessLimits = ProcessLimits {
    timeout: Duration::from_secs(2),
    stdout_bytes: 1024 * 1024,
    stderr_bytes: 64 * 1024,
};

pub(super) fn read_netstat_output(control: &CaptureControl) -> Result<Vec<u8>> {
    run_netstat(Path::new(NETSTAT_PROGRAM), control, NETSTAT_LIMITS)
}

fn run_netstat(program: &Path, control: &CaptureControl, limits: ProcessLimits) -> Result<Vec<u8>> {
    let mut command = BoundedCommand::new(program);
    command
        .args(["-ibn"])
        .envs([("LC_ALL", "C"), ("LANG", "C")]);
    let output = command
        .run(limits, &|| control.is_cancelled())
        .map_err(netstat_process_error)?;
    if !output.status.success() {
        return Err(NetdiagError::Connector(format!(
            "netstat -ibn failed with status {}",
            output.status
        )));
    }
    Ok(output.stdout)
}

fn netstat_process_error(failure: ProcessFailure) -> NetdiagError {
    let cause = match failure.reason {
        ProcessFailureReason::Cancelled => {
            return NetdiagError::CaptureCancelled {
                context: "system counters capture",
            };
        }
        ProcessFailureReason::Spawn(error) => {
            format!("failed to start bounded netstat -ibn: {error}")
        }
        ProcessFailureReason::Timeout => format!(
            "netstat -ibn exceeded its {:.3} second execution deadline",
            failure.timeout.as_secs_f64()
        ),
        ProcessFailureReason::Wait(error) => {
            format!("failed while waiting for bounded netstat -ibn: {error}")
        }
        ProcessFailureReason::OutputLimit { stream_name, limit } => {
            format!("netstat -ibn exceeded its {stream_name} output limit of {limit} bytes")
        }
        ProcessFailureReason::Output(error) => {
            format!("netstat -ibn output capture failed: {error}")
        }
    };
    NetdiagError::Connector(if failure.cleanup_details.is_empty() {
        cause
    } else {
        format!(
            "{cause}, cleanup_details=[{}]",
            failure.cleanup_details.join(", ")
        )
    })
}

#[cfg(all(test, unix))]
mod tests;
