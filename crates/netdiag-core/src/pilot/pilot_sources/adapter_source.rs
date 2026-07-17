use super::adapter_args::{adapter_preflight_invocation, adapter_runtime_invocation};
use super::adapter_boundary::AdapterExecutionBoundary;
use super::adapter_environment::AdapterEnvironment;
use super::payload_contract::validate_adapter_payload_contract;
use super::{LoadedPilotSource, timeout};
use crate::error::{NetdiagError, Result};
use crate::ingest::ingest_json_value;
use crate::metric_quality::{
    MetricQualityDeclarations, apply_metric_quality_declarations, metric_quality_policy_for_schema,
};
use crate::pilot::PilotSource;
use crate::pilot::adapter_contract::{run_python_adapter, validate_adapter_preflight};
use crate::reliability::redact_json_value;
use crate::strict_json::parse_unique_value;
use serde_json::Value;
use std::path::Path;
use std::process::Output;

mod redaction;
use redaction::redact_adapter_value;
mod reporting;
use reporting::{adapter_exit_error, adapter_health};

pub(super) fn load_adapter_sample_source(
    source: &PilotSource,
    adapter_boundary: Option<&AdapterExecutionBoundary>,
    allow_adapter_execution: bool,
) -> Result<LoadedPilotSource> {
    if !allow_adapter_execution {
        return Err(NetdiagError::Connector(format!(
            "adapter source {} requires explicit allow_adapter_execution authorization",
            source.name
        )));
    }
    let boundary = adapter_boundary.ok_or_else(|| {
        NetdiagError::InvalidTrace("adapter execution boundary is not configured".to_string())
    })?;
    let adapter = boundary.staged_adapter(&source.name)?;
    let original_adapter = boundary.original_adapter(&source.name)?;
    execute_contract_preflight(source, boundary, adapter)?;

    let invocation = adapter_runtime_invocation(source)?;
    let (output, environment) =
        execute_adapter_invocation(source, boundary, adapter, &invocation.args)?;
    if !output.status.success() {
        return Err(adapter_exit_error(
            "collect",
            original_adapter,
            &output,
            environment.redaction_values(),
        ));
    }
    let mut payload = parse_unique_value(&output.stdout)?;
    redact_adapter_value(&mut payload, environment.redaction_values())?;
    validate_adapter_payload_contract(&payload, invocation.mode)?;
    let measurement_quality = MetricQualityDeclarations::from_payload(&payload)?;
    let undeclared_policy = metric_quality_policy_for_schema(
        payload.get("schema").and_then(Value::as_str),
        &measurement_quality,
    )?;
    let mut ingest = ingest_json_value(payload.clone(), source.name.clone())?;
    apply_metric_quality_declarations(
        &mut ingest,
        &measurement_quality,
        &source.name,
        undeclared_policy,
    );
    let mut redacted_payload = payload;
    redact_json_value(&mut redacted_payload);
    let health = adapter_health(source, &ingest);
    Ok(LoadedPilotSource {
        source: source.clone(),
        ingest,
        health,
        redacted_payload: Some(redacted_payload),
    })
}

fn execute_contract_preflight(
    source: &PilotSource,
    boundary: &AdapterExecutionBoundary,
    adapter: &Path,
) -> Result<()> {
    let invocation = adapter_preflight_invocation(source)?;
    let (output, environment) =
        execute_adapter_invocation(source, boundary, adapter, &invocation.args)?;
    if !output.status.success() {
        return Err(adapter_exit_error(
            "preflight",
            boundary.original_adapter(&source.name)?,
            &output,
            environment.redaction_values(),
        ));
    }
    let mut preflight = parse_unique_value(&output.stdout)?;
    redact_adapter_value(&mut preflight, environment.redaction_values())?;
    validate_adapter_preflight(
        &preflight,
        invocation.mode,
        boundary.adapter_identity(&source.name)?,
    )
}

fn execute_adapter_invocation(
    source: &PilotSource,
    boundary: &AdapterExecutionBoundary,
    adapter: &Path,
    args: &[String],
) -> Result<(Output, AdapterEnvironment)> {
    boundary.with_runtime_directory(|cwd| {
        let environment = AdapterEnvironment::from_source(source, boundary.runtime_path(), cwd)?;
        let output = run_python_adapter(
            boundary.interpreter(),
            adapter,
            cwd,
            args,
            timeout(source),
            environment.entries(),
            environment.redaction_values(),
        )?;
        Ok((output, environment))
    })
}
