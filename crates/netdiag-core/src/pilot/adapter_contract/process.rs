use crate::error::{NetdiagError, Result};
use std::path::Path;
use std::process::Output;
use std::time::Duration;

mod error;
pub(in crate::pilot) use crate::python_runtime::{ResolvedInterpreter, resolve_python_interpreter};
pub(in crate::pilot) use error::adapter_stderr_excerpt;

#[cfg(unix)]
pub(in crate::pilot) const ADAPTER_STDOUT_LIMIT_BYTES: usize = 4 * 1024 * 1024;
#[cfg(unix)]
pub(in crate::pilot) const ADAPTER_STDERR_LIMIT_BYTES: usize = 256 * 1024;

#[cfg(unix)]
pub(in crate::pilot) fn run_python_adapter(
    interpreter: &Path,
    adapter: &Path,
    cwd: &Path,
    args: &[String],
    timeout: Duration,
    environment: &[(String, String)],
    redaction_values: &[String],
) -> Result<Output> {
    use crate::bounded_process::{BoundedCommand, ProcessLimits};

    if !interpreter.is_absolute() {
        return Err(NetdiagError::Connector(format!(
            "adapter Python interpreter must be absolute: {}",
            interpreter.display()
        )));
    }
    let mut command = BoundedCommand::new(interpreter);
    command
        .arg("-I")
        .arg("-B")
        .arg(adapter)
        .args(args)
        .current_dir(cwd)
        .envs(environment.iter().map(|(name, value)| (name, value)));
    command
        .run(
            ProcessLimits {
                timeout,
                stdout_bytes: ADAPTER_STDOUT_LIMIT_BYTES,
                stderr_bytes: ADAPTER_STDERR_LIMIT_BYTES,
            },
            &|| false,
        )
        .map_err(|failure| adapter_process_error(adapter, failure, redaction_values))
}

#[cfg(unix)]
fn adapter_process_error(
    adapter: &Path,
    failure: crate::bounded_process::ProcessFailure,
    redaction_values: &[String],
) -> NetdiagError {
    use crate::bounded_process::ProcessFailureReason;

    let cause = match failure.reason {
        ProcessFailureReason::Spawn(error) => format!(
            "adapter process failed (phase=spawn, adapter={:?}, cause={error})",
            adapter.display().to_string()
        ),
        ProcessFailureReason::Timeout => format!(
            "adapter process failed (phase=runtime, adapter={:?}, reason=timeout, timeout_seconds={:.3})",
            adapter.display().to_string(),
            failure.timeout.as_secs_f64()
        ),
        ProcessFailureReason::Cancelled => format!(
            "adapter process failed (phase=runtime, adapter={:?}, reason=cancelled)",
            adapter.display().to_string()
        ),
        ProcessFailureReason::Wait(error) => format!(
            "adapter process failed (phase=wait, adapter={:?}, cause={error})",
            adapter.display().to_string()
        ),
        ProcessFailureReason::OutputLimit { stream_name, limit } => format!(
            "adapter process failed (phase=output, adapter={:?}, stream={stream_name}, reason=limit_exceeded, limit_bytes={limit})",
            adapter.display().to_string()
        ),
        ProcessFailureReason::Output(error) => format!(
            "adapter process failed (phase=output, adapter={:?}, cause={error})",
            adapter.display().to_string()
        ),
    };
    let mut details = failure.cleanup_details;
    let excerpt = adapter_stderr_excerpt(&failure.stderr, redaction_values);
    if !excerpt.is_empty() {
        details.insert(0, format!("stderr_excerpt={excerpt:?}"));
    }
    NetdiagError::Connector(if details.is_empty() {
        cause
    } else {
        format!("{cause}, details=[{}]", details.join(", "))
    })
}

#[cfg(not(unix))]
pub(in crate::pilot) fn run_python_adapter(
    _interpreter: &Path,
    _adapter: &Path,
    _cwd: &Path,
    _args: &[String],
    _timeout: Duration,
    _environment: &[(String, String)],
    _redaction_values: &[String],
) -> Result<Output> {
    Err(NetdiagError::Connector(
        "Python adapter execution is disabled on this platform because process-group termination and nonblocking output capture cannot yet be proven"
            .to_string(),
    ))
}
