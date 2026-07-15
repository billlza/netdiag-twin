use super::{
    PilotReport, PilotWorkflowPhase, PilotWorkflowPhaseStatus, PilotWorkflowVerificationOptions,
};
use crate::error::Result;
use crate::lab::{ActionVerificationOptions, verify_action_with_options};
use crate::models::{ActionVerification, ActionVerificationVerdict};
use std::path::Path;

mod entry;
mod persistence;
pub use entry::{run_pilot_workflow, run_pilot_workflow_with_bearer_bindings};

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
    pilot_run.passed && phases.iter().all(phase_allows_workflow_success)
}

fn phase_allows_workflow_success(phase: &PilotWorkflowPhase) -> bool {
    match phase.status {
        PilotWorkflowPhaseStatus::Passed => true,
        PilotWorkflowPhaseStatus::Failed => false,
        PilotWorkflowPhaseStatus::Pending => phase.name != "verify",
        PilotWorkflowPhaseStatus::Skipped => true,
    }
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
