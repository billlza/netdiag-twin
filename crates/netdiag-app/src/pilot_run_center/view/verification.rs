use super::super::super::{GREEN, RED};
use eframe::egui::{self, RichText};
use netdiag_core::models::ActionVerificationVerdict;
use netdiag_core::pilot::PilotWorkflowReport;

pub(super) fn render_verification(workflow: &PilotWorkflowReport, ui: &mut egui::Ui) {
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
