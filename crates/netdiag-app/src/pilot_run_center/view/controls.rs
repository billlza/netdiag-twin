use super::super::super::{MUTED, section_title, soft_button};
use super::super::PilotRunCenterState;
use eframe::egui::{self, RichText};

pub(in crate::pilot_run_center) fn render_manifest_controls(
    state: &mut PilotRunCenterState,
    ui: &mut egui::Ui,
) {
    section_title(ui, "Pilot Run Center");
    ui.label(
        RichText::new("Run a manifest through preflight, collection, diagnosis, evidence, review, and verification gates.")
            .color(MUTED)
            .size(13.0),
    );
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("Manifest").size(12.0).color(MUTED));
        ui.add(
            egui::TextEdit::singleline(&mut state.manifest_path)
                .desired_width((ui.available_width() - 250.0).max(260.0)),
        );
        if soft_button(ui, "Choose").clicked() {
            state.choose_manifest();
        }
    });
    ui.checkbox(
        &mut state.allow_active,
        "Allow active probes when manifest also opts in",
    );
    ui.checkbox(
        &mut state.allow_adapter_execution,
        "Execute trusted adapter code selected from the manifest's adapter root (not sandboxed)",
    );
}
