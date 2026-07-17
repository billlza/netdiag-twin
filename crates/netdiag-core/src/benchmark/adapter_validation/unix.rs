use super::super::{BenchmarkCheck, BenchmarkSection, repo_root, timed_section};
use super::schema_validation::schema_python_runtime;
use crate::bounded_process::{BoundedCommand, ProcessFailure, ProcessFailureReason, ProcessLimits};
use crate::error::{IoContext, NetdiagError, Result};
use crate::models::ConnectorHealthStatus;
use serde_json::json;
use std::path::Path;
use std::process::Output;
use std::time::Duration;

const VALIDATOR_LIMITS: ProcessLimits = ProcessLimits {
    timeout: Duration::from_secs(60),
    stdout_bytes: 1024 * 1024,
    stderr_bytes: 1024 * 1024,
};
const RUST_VALIDATOR_RELATIVE_PATH: &str = "target/adapter-validator/debug/netdiag-cli";

pub(in crate::benchmark) fn run_adapter_validation_section() -> Result<BenchmarkSection> {
    timed_section("adapter schema and ingest", || {
        let python = schema_python_runtime()?;
        let repository_path = repo_root();
        let repository = repository_path.canonicalize().with_path(&repository_path)?;
        let rust_validator = repository.join(RUST_VALIDATOR_RELATIVE_PATH);
        [
            "validate_adapter_samples.py",
            "validate_adapter_contract.py",
        ]
        .into_iter()
        .map(|script_name| {
            let script = repository.join("scripts").join(script_name);
            let output = execute_validator(
                python.executable(),
                python.runtime_path(),
                &script,
                &rust_validator,
                &repository,
                script_name,
                VALIDATOR_LIMITS,
            )?;
            Ok(validator_check(script_name, output))
        })
        .collect()
    })
}

pub(super) fn execute_validator(
    executable: &Path,
    runtime_path: &str,
    script: &Path,
    rust_validator: &Path,
    repository: &Path,
    script_name: &str,
    limits: ProcessLimits,
) -> Result<Output> {
    let mut command = BoundedCommand::new(executable);
    command
        .args(["-E", "-B", "-s"])
        .arg(script)
        .arg("--rust-validator")
        .arg(rust_validator)
        .current_dir(repository)
        .envs([
            ("PATH", runtime_path),
            ("PYTHONNOUSERSITE", "1"),
            ("PYTHONDONTWRITEBYTECODE", "1"),
        ]);
    command
        .run(limits, &|| false)
        .map_err(|failure| validator_process_error(script_name, failure))
}

pub(super) fn validator_check(script_name: &str, output: Output) -> BenchmarkCheck {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    BenchmarkCheck {
        name: script_name.to_string(),
        status: if output.status.success() {
            ConnectorHealthStatus::Ok
        } else {
            ConnectorHealthStatus::Error
        },
        message: if output.status.success() {
            "adapter contract passed schema and Rust ingest validation".to_string()
        } else {
            "adapter contract validation failed".to_string()
        },
        details: Some(json!({
            "stdout": stdout.lines().collect::<Vec<_>>(),
            "stderr": stderr.lines().collect::<Vec<_>>(),
        })),
    }
}

fn validator_process_error(script_name: &str, failure: ProcessFailure) -> NetdiagError {
    let cause = match failure.reason {
        ProcessFailureReason::Spawn(error) => {
            format!("phase=spawn, cause={error}")
        }
        ProcessFailureReason::Timeout => format!(
            "phase=runtime, reason=timeout, timeout_seconds={:.3}",
            failure.timeout.as_secs_f64()
        ),
        ProcessFailureReason::Cancelled => "phase=runtime, reason=cancelled".to_string(),
        ProcessFailureReason::Wait(error) => format!("phase=wait, cause={error}"),
        ProcessFailureReason::OutputLimit { stream_name, limit } => format!(
            "phase=output, stream={stream_name}, reason=limit_exceeded, limit_bytes={limit}"
        ),
        ProcessFailureReason::Output(error) => format!("phase=output, cause={error}"),
    };
    let details = if failure.cleanup_details.is_empty() {
        String::new()
    } else {
        format!(", cleanup_details=[{}]", failure.cleanup_details.join(", "))
    };
    NetdiagError::Connector(format!(
        "adapter validator {script_name:?} failed ({cause}{details})"
    ))
}
