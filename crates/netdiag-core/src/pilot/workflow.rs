use super::{
    PilotOptions, PilotReport, PilotWorkflowOptions, PilotWorkflowPhase, PilotWorkflowPhaseStatus,
    PilotWorkflowReport, PilotWorkflowVerificationOptions, preflight_pilot, run_pilot,
};
use crate::error::Result;
use crate::lab::{ActionVerificationOptions, verify_action_with_options};
use crate::models::{ActionVerification, ActionVerificationVerdict};
use chrono::Utc;
use persistence::save_workflow_report;
use std::path::Path;

const PILOT_WORKFLOW_SCHEMA: &str = "netdiag-pilot-workflow/v1";

mod persistence;

pub fn run_pilot_workflow(
    path: impl AsRef<Path>,
    options: PilotWorkflowOptions,
) -> Result<PilotWorkflowReport> {
    run_pilot_workflow_path(path.as_ref(), options)
}

fn run_pilot_workflow_path(
    path: &Path,
    options: PilotWorkflowOptions,
) -> Result<PilotWorkflowReport> {
    let pilot_options = PilotOptions {
        artifacts: options.artifacts.clone(),
        allow_active: options.allow_active,
    };
    let preflight = preflight_pilot(path, pilot_options.clone())?;
    let mut phases = Vec::new();
    phases.push(phase(
        "preflight",
        passed_or_failed(preflight.passed),
        if preflight.passed {
            "preflight passed"
        } else {
            "preflight failed"
        },
    ));

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
    let pilot_run = run_pilot(path, pilot_options)?;
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

fn workflow_verification(
    phases: &mut Vec<PilotWorkflowPhase>,
    pilot_run: &PilotReport,
    artifact_root: &Path,
    options: Option<PilotWorkflowVerificationOptions>,
) -> Result<Option<ActionVerification>> {
    let Some(options) = options else {
        phases.push(phase(
            "verify",
            PilotWorkflowPhaseStatus::Pending,
            "no after-run configured yet",
        ));
        return Ok(None);
    };

    let verification = verify_action_with_options(
        artifact_root,
        &pilot_run.run_id,
        &options.after_run_id,
        ActionVerificationOptions {
            recommendation_id: options.recommendation_id,
            policy_path: options.policy_path,
            objective_path: options.objective_path,
        },
    )?;
    phases.push(phase(
        "verify",
        verification_phase_status(verification.verdict),
        verification_phase_message(&verification),
    ));
    Ok(Some(verification))
}

fn passed_or_failed(passed: bool) -> PilotWorkflowPhaseStatus {
    if passed {
        PilotWorkflowPhaseStatus::Passed
    } else {
        PilotWorkflowPhaseStatus::Failed
    }
}

fn workflow_passed(pilot_run: &PilotReport, phases: &[PilotWorkflowPhase]) -> bool {
    pilot_run.passed
        && phases
            .iter()
            .all(|phase| !matches!(phase.status, PilotWorkflowPhaseStatus::Failed))
}

fn verification_phase_status(verdict: ActionVerificationVerdict) -> PilotWorkflowPhaseStatus {
    match verdict {
        ActionVerificationVerdict::Verified => PilotWorkflowPhaseStatus::Passed,
        ActionVerificationVerdict::NotVerified | ActionVerificationVerdict::Inconclusive => {
            PilotWorkflowPhaseStatus::Failed
        }
    }
}

fn verification_phase_message(verification: &ActionVerification) -> String {
    let verdict = match verification.verdict {
        ActionVerificationVerdict::Verified => "verified",
        ActionVerificationVerdict::NotVerified => "not verified",
        ActionVerificationVerdict::Inconclusive => "inconclusive",
    };
    let reason = verification
        .reasons
        .first()
        .map(|reason| format!(": {reason}"))
        .unwrap_or_default();
    format!("after-run verification {verdict}{reason}")
}

fn phase(
    name: &'static str,
    status: PilotWorkflowPhaseStatus,
    message: impl Into<String>,
) -> PilotWorkflowPhase {
    PilotWorkflowPhase {
        name: name.to_string(),
        status,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests;
