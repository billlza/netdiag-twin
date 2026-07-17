use super::{
    passed_or_failed, persistence::save_workflow_report, phase, workflow_passed,
    workflow_verification,
};
use crate::connectors::authentication::BearerEnvironmentBindings;
use crate::error::Result;
use crate::pilot::prepared::PreparedPilot;
use crate::pilot::{
    PilotOptions, PilotWorkflowOptions, PilotWorkflowPhaseStatus, PilotWorkflowReport,
    PreparedPilotPreflight, prepare_pilot_run_preflight, require_model_snapshot,
    run_prepared_pilot,
};
use crate::pipeline::ensure_run_directory_publication_supported;
use crate::storage::{ArtifactRootCapability, prepare_artifact_root};
use chrono::Utc;
use std::path::Path;

const PILOT_WORKFLOW_SCHEMA: &str = "netdiag-pilot-workflow/v1";

pub fn run_pilot_workflow(
    path: impl AsRef<Path>,
    options: PilotWorkflowOptions,
) -> Result<PilotWorkflowReport> {
    run_pilot_workflow_with_bearer_bindings(path, options, &BearerEnvironmentBindings::default())
}

pub fn run_pilot_workflow_with_bearer_bindings(
    path: impl AsRef<Path>,
    options: PilotWorkflowOptions,
    bindings: &BearerEnvironmentBindings,
) -> Result<PilotWorkflowReport> {
    ensure_run_directory_publication_supported(&options.artifacts)?;
    let prepared = PreparedPilot::load(path.as_ref())?;
    let capability = prepare_artifact_root(&options.artifacts)?;
    let operation = run_prepared_pilot_workflow(&prepared, options, bindings, &capability);
    prepared.finish(operation)
}

fn run_prepared_pilot_workflow(
    prepared: &PreparedPilot,
    options: PilotWorkflowOptions,
    bindings: &BearerEnvironmentBindings,
    capability: &ArtifactRootCapability,
) -> Result<PilotWorkflowReport> {
    let pilot_options = PilotOptions {
        artifacts: options.artifacts.clone(),
        allow_active: options.allow_active,
        allow_adapter_execution: options.allow_adapter_execution,
    };
    let PreparedPilotPreflight {
        report: preflight,
        model_snapshot,
    } = prepare_pilot_run_preflight(prepared, &pilot_options, bindings, capability)?;
    let mut phases = vec![phase(
        "preflight",
        passed_or_failed(preflight.passed),
        if preflight.passed {
            "preflight passed"
        } else {
            "preflight failed"
        },
    )];

    if !preflight.passed {
        return Ok(PilotWorkflowReport {
            schema: PILOT_WORKFLOW_SCHEMA.to_string(),
            generated_at: Utc::now(),
            pilot_id: preflight.pilot_id.clone(),
            passed: false,
            phases,
            preflight: Some(preflight),
            pilot_run: None,
            verification: None,
        });
    }

    phases.push(phase(
        "collect",
        PilotWorkflowPhaseStatus::Passed,
        "sources collected through pilot connector contract",
    ));
    let model_snapshot = require_model_snapshot(model_snapshot, "pilot workflow")?;
    let pilot_run = run_prepared_pilot(
        prepared,
        pilot_options,
        &model_snapshot,
        bindings,
        capability,
    )?;
    phases.push(phase(
        "diagnose",
        passed_or_failed(pilot_run.passed),
        "primary source diagnosed and gated",
    ));
    phases.push(phase(
        "evidence_bundle",
        passed_or_failed(pilot_run.evidence_bundle.is_some()),
        "portable evidence bundle exported",
    ));
    phases.push(phase(
        "review",
        PilotWorkflowPhaseStatus::Pending,
        "human review is required before active remediation",
    ));

    let verification = workflow_verification(
        &mut phases,
        &pilot_run,
        &options.artifacts,
        options.verification,
    )?;

    let passed = workflow_passed(&pilot_run, &phases);
    let report = PilotWorkflowReport {
        schema: PILOT_WORKFLOW_SCHEMA.to_string(),
        generated_at: Utc::now(),
        pilot_id: pilot_run.pilot_id.clone(),
        passed,
        phases,
        preflight: Some(preflight),
        pilot_run: Some(pilot_run.clone()),
        verification,
    };
    save_workflow_report(&pilot_run, &report).map(|()| report)
}
