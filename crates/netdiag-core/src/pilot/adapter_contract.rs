use super::PilotSource;
use crate::error::{NetdiagError, Result};
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub(super) fn adapter_contract_enabled(source: &PilotSource) -> bool {
    source
        .metadata
        .get("adapter_contract")
        .or_else(|| source.metadata.get("contract"))
        .is_some_and(|value| {
            matches!(
                value.trim(),
                "v1" | "adapter-v1" | "netdiag-adapter/v1" | "netdiag-adapter-preflight/v1"
            )
        })
}

pub(super) fn validate_adapter_preflight(preflight: &Value) -> Result<()> {
    let schema = preflight.get("schema").and_then(Value::as_str);
    if schema != Some("netdiag-adapter-preflight/v1") {
        return Err(NetdiagError::Connector(
            "adapter preflight emitted an unsupported schema".to_string(),
        ));
    }
    if preflight.get("passed").and_then(Value::as_bool) != Some(true) {
        return Err(NetdiagError::Connector(
            "adapter preflight did not pass".to_string(),
        ));
    }
    if preflight
        .get("checks")
        .and_then(Value::as_array)
        .is_none_or(|checks| checks.is_empty())
    {
        return Err(NetdiagError::Connector(
            "adapter preflight must include non-empty checks".to_string(),
        ));
    }
    if preflight.get("health").is_none() {
        return Err(NetdiagError::Connector(
            "adapter preflight must include health metadata".to_string(),
        ));
    }
    if preflight.get("redaction").is_none() {
        return Err(NetdiagError::Connector(
            "adapter preflight must include redaction metadata".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn run_python_adapter(
    adapter: &Path,
    cwd: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<Output> {
    let mut child = Command::new("python3")
        .arg(adapter)
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| NetdiagError::Connector(format!("failed to run adapter sample: {err}")))?;
    let started = Instant::now();
    loop {
        if let Some(_status) = child
            .try_wait()
            .map_err(|err| NetdiagError::Connector(format!("adapter wait failed: {err}")))?
        {
            return child
                .wait_with_output()
                .map_err(|err| NetdiagError::Connector(format!("adapter output failed: {err}")));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let output = child.wait_with_output().ok();
            let stderr = output
                .as_ref()
                .map(|output| String::from_utf8_lossy(&output.stderr).to_string())
                .unwrap_or_default();
            return Err(NetdiagError::Connector(format!(
                "adapter sample {} timed out after {}s{}",
                adapter.display(),
                timeout.as_secs(),
                if stderr.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", stderr.trim())
                }
            )));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(test)]
mod tests;
