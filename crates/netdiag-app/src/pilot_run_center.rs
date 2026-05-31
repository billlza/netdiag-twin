use super::{INK, MUTED, section_title, soft_button, soft_button_enabled};
use eframe::egui::{self, RichText};
use netdiag_core::pilot::{
    PilotOptions, PilotPreflightReport, PilotWorkflowOptions, PilotWorkflowReport,
    PilotWorkflowVerificationOptions, preflight_pilot, run_pilot_workflow,
};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

mod view;

pub struct PilotRunCenterState {
    pub manifest_path: String,
    pub allow_active: bool,
    pub verification_after_run_id: String,
    pub verification_recommendation_id: String,
    pub verification_policy_path: String,
    pub verification_objective_path: String,
    status: Option<String>,
    preflight: Option<PilotPreflightReport>,
    workflow: Option<PilotWorkflowReport>,
    job: Option<mpsc::Receiver<anyhow::Result<PilotRunCenterOutcome>>>,
}

impl Default for PilotRunCenterState {
    fn default() -> Self {
        Self {
            manifest_path: "examples/pilots/connector-family-readonly.yaml".to_string(),
            allow_active: false,
            verification_after_run_id: String::new(),
            verification_recommendation_id: String::new(),
            verification_policy_path: String::new(),
            verification_objective_path: String::new(),
            status: None,
            preflight: None,
            workflow: None,
            job: None,
        }
    }
}

pub enum PilotRunCenterAction {
    OpenPath(PathBuf),
}

enum PilotRunCenterOutcome {
    Preflight(PilotPreflightReport),
    Workflow(Box<PilotWorkflowReport>),
}

impl PilotRunCenterState {
    pub fn poll(&mut self, ctx: &egui::Context) {
        let message = match self.job.as_ref().map(|receiver| receiver.try_recv()) {
            Some(Ok(message)) => Some(message),
            Some(Err(mpsc::TryRecvError::Disconnected)) => Some(Err(anyhow::anyhow!(
                "pilot worker stopped before returning a result"
            ))),
            Some(Err(mpsc::TryRecvError::Empty)) => {
                ctx.request_repaint_after(Duration::from_millis(100));
                None
            }
            None => None,
        };

        if let Some(message) = message {
            self.job = None;
            match message {
                Ok(PilotRunCenterOutcome::Preflight(report)) => {
                    self.status = Some(if report.passed {
                        format!("Pilot preflight passed for {}", report.pilot_id)
                    } else {
                        format!("Pilot preflight failed for {}", report.pilot_id)
                    });
                    self.preflight = Some(report);
                }
                Ok(PilotRunCenterOutcome::Workflow(report)) => {
                    self.status = Some(if report.passed {
                        format!("Pilot workflow passed for {}", report.pilot_id)
                    } else {
                        format!("Pilot workflow needs attention for {}", report.pilot_id)
                    });
                    self.preflight = report.preflight.clone();
                    self.workflow = Some(*report);
                }
                Err(err) => {
                    self.status = Some(err.to_string());
                }
            }
            ctx.request_repaint();
        }
    }

    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        artifacts_root: &Path,
    ) -> Option<PilotRunCenterAction> {
        let mut action = None;
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
                egui::TextEdit::singleline(&mut self.manifest_path)
                    .desired_width((ui.available_width() - 250.0).max(260.0)),
            );
            if soft_button(ui, "Choose").clicked() {
                self.choose_manifest();
            }
        });
        ui.checkbox(
            &mut self.allow_active,
            "Allow active probes when manifest also opts in",
        );
        ui.add_space(8.0);
        ui.label(
            RichText::new("After-run verification")
                .size(12.0)
                .color(MUTED),
        );
        ui.horizontal(|ui| {
            ui.label(RichText::new("After run ID").size(12.0).color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.verification_after_run_id)
                    .hint_text("empty = partial workflow / pending verify")
                    .desired_width((ui.available_width() - 120.0).max(260.0)),
            );
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Recommendation").size(12.0).color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.verification_recommendation_id)
                    .hint_text("optional recommendation id")
                    .desired_width((ui.available_width() - 120.0).max(220.0)),
            );
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Policy").size(12.0).color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.verification_policy_path)
                    .hint_text("optional policy YAML")
                    .desired_width((ui.available_width() - 120.0).max(220.0)),
            );
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Objective").size(12.0).color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.verification_objective_path)
                    .hint_text("optional verification objective YAML")
                    .desired_width((ui.available_width() - 120.0).max(220.0)),
            );
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let ready = self.job.is_none();
            if soft_button_enabled(ui, "Preflight", ready).clicked() {
                self.start_preflight(artifacts_root.to_path_buf());
            }
            if soft_button_enabled(ui, "Run workflow", ready).clicked() {
                self.start_workflow(artifacts_root.to_path_buf());
            }
            if let Some(path) = self.latest_pilot_run_dir()
                && soft_button(ui, "Open run").clicked()
            {
                action = Some(PilotRunCenterAction::OpenPath(path));
            }
            if let Some(path) = self.latest_evidence_bundle()
                && soft_button(ui, "Open evidence").clicked()
            {
                action = Some(PilotRunCenterAction::OpenPath(path));
            }
        });
        if let Some(status) = &self.status {
            ui.add_space(8.0);
            ui.label(RichText::new(status).size(13.0).color(INK));
        }
        view::render_inventory(self, ui);
        view::render_workflow(self, ui);
        action
    }

    fn choose_manifest(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("Pilot manifest", &["yaml", "yml"])
            .set_directory("examples/pilots")
            .pick_file()
        else {
            return;
        };
        self.manifest_path = path.display().to_string();
    }

    fn start_preflight(&mut self, artifacts: PathBuf) {
        if self.job.is_some() {
            return;
        }
        let manifest = PathBuf::from(self.manifest_path.trim());
        let allow_active = self.allow_active;
        let (sender, receiver) = mpsc::channel();
        self.status = Some("Pilot preflight running".to_string());
        self.job = Some(receiver);
        thread::spawn(move || {
            let result = preflight_pilot(
                &manifest,
                PilotOptions {
                    artifacts,
                    allow_active,
                },
            )
            .map(PilotRunCenterOutcome::Preflight)
            .map_err(anyhow::Error::from);
            let _ = sender.send(result);
        });
    }

    fn start_workflow(&mut self, artifacts: PathBuf) {
        if self.job.is_some() {
            return;
        }
        let manifest = PathBuf::from(self.manifest_path.trim());
        let allow_active = self.allow_active;
        let verification = self.verification_options();
        let (sender, receiver) = mpsc::channel();
        self.status = Some("Pilot workflow running".to_string());
        self.job = Some(receiver);
        thread::spawn(move || {
            let result = run_pilot_workflow(
                &manifest,
                PilotWorkflowOptions {
                    artifacts,
                    allow_active,
                    verification,
                },
            )
            .map(|report| PilotRunCenterOutcome::Workflow(Box::new(report)))
            .map_err(anyhow::Error::from);
            let _ = sender.send(result);
        });
    }

    pub(crate) fn verification_options(&self) -> Option<PilotWorkflowVerificationOptions> {
        let after_run_id = optional_string(&self.verification_after_run_id)?;
        Some(PilotWorkflowVerificationOptions {
            after_run_id,
            recommendation_id: optional_string(&self.verification_recommendation_id),
            policy_path: optional_path(&self.verification_policy_path),
            objective_path: optional_path(&self.verification_objective_path),
        })
    }

    fn latest_pilot_run_dir(&self) -> Option<PathBuf> {
        self.workflow
            .as_ref()
            .and_then(|workflow| workflow.pilot_run.as_ref())
            .map(|run| PathBuf::from(&run.pilot_run_dir))
    }

    fn latest_evidence_bundle(&self) -> Option<PathBuf> {
        self.workflow
            .as_ref()
            .and_then(|workflow| workflow.pilot_run.as_ref())
            .and_then(|run| run.evidence_bundle.as_ref())
            .map(|bundle| PathBuf::from(&bundle.output))
    }
}

fn optional_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn optional_path(value: &str) -> Option<PathBuf> {
    optional_string(value).map(PathBuf::from)
}
