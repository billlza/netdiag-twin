use super::super::{GREEN, INK, MUTED, ORANGE, RED};
use super::PilotRunCenterState;
use eframe::egui::{self, RichText};
use netdiag_core::models::ActionVerificationVerdict;
use netdiag_core::pilot::{PilotWorkflowPhaseStatus, PilotWorkflowReport};

pub(super) fn render_inventory(state: &PilotRunCenterState, ui: &mut egui::Ui) {
    let Some(preflight) = &state.preflight else {
        return;
    };
    ui.add_space(12.0);
    ui.label(RichText::new("Source inventory").strong().color(INK));
    for source in &preflight.source_inventory {
        let color = if source.active { ORANGE } else { GREEN };
        ui.label(
            RichText::new(format!(
                "{} · {:?} · {:?} · {}",
                source.name, source.kind, source.role, source.endpoint
            ))
            .size(12.0)
            .color(color),
        );
    }
}

pub(super) fn render_workflow(state: &PilotRunCenterState, ui: &mut egui::Ui) {
    let Some(workflow) = &state.workflow else {
        return;
    };
    ui.add_space(12.0);
    ui.label(RichText::new("Workflow phases").strong().color(INK));
    for phase in &workflow.phases {
        let color = match phase.status {
            PilotWorkflowPhaseStatus::Passed => GREEN,
            PilotWorkflowPhaseStatus::Failed => RED,
            PilotWorkflowPhaseStatus::Pending => ORANGE,
            PilotWorkflowPhaseStatus::Skipped => MUTED,
        };
        ui.label(
            RichText::new(format!(
                "{:?}: {} - {}",
                phase.status, phase.name, phase.message
            ))
            .size(12.0)
            .color(color),
        );
    }
    render_verification(workflow, ui);
}

fn render_verification(workflow: &PilotWorkflowReport, ui: &mut egui::Ui) {
    let Some(verification) = &workflow.verification else {
        return;
    };
    ui.add_space(8.0);
    let color = match verification.verdict {
        ActionVerificationVerdict::Verified => GREEN,
        ActionVerificationVerdict::NotVerified | ActionVerificationVerdict::Inconclusive => RED,
    };
    ui.label(
        RichText::new(format!("Verification verdict: {:?}", verification.verdict))
            .size(12.0)
            .color(color),
    );
    for reason in &verification.reasons {
        ui.label(RichText::new(format!("- {reason}")).size(12.0).color(color));
    }
}
