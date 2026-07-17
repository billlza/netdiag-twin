use super::{LabJobOutcome, NetDiagApp, pilot_run_center};
use netdiag_core::lab::{
    LabPreflightMode, LabPreflightOptions, LabRunOptions, preflight_lab_scenario, run_lab_scenario,
    summarize_lab_runs,
};
use netdiag_core::ml::export_feedback_training_dataset;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;

impl NetDiagApp {
    pub(super) fn handle_pilot_run_center_action(
        &mut self,
        action: pilot_run_center::PilotRunCenterAction,
    ) {
        match action {
            pilot_run_center::PilotRunCenterAction::StartPreflight => {
                if self.ensure_current_settings_for_operation() {
                    self.pilot_center
                        .start_preflight(self.artifacts_root.clone());
                }
            }
            pilot_run_center::PilotRunCenterAction::StartWorkflow => {
                if self.ensure_current_settings_for_operation() {
                    self.pilot_center
                        .start_workflow(self.artifacts_root.clone());
                }
            }
            pilot_run_center::PilotRunCenterAction::OpenPath(path) => {
                self.open_path_with_notice(&path);
            }
        }
    }

    pub(super) fn start_lab_preflight(&mut self) {
        if !self.prepare_lab_job() {
            return;
        }
        let scenario = PathBuf::from(self.lab_scenario_path.trim());
        let artifacts = self.artifacts_root.clone();
        let (sender, receiver) = mpsc::channel();
        self.lab_status = Some("Preflight running".to_string());
        self.lab_job = Some(receiver);
        thread::spawn(move || {
            let result = preflight_lab_scenario(
                &scenario,
                LabPreflightOptions {
                    artifacts,
                    mode: LabPreflightMode::Static,
                },
            )
            .map(LabJobOutcome::Preflight)
            .map_err(anyhow::Error::from);
            let _ = sender.send(result);
        });
    }

    pub(super) fn start_lab_run(&mut self) {
        if !self.prepare_lab_job() {
            return;
        }
        let scenario = PathBuf::from(self.lab_scenario_path.trim());
        let artifacts = self.artifacts_root.clone();
        let (sender, receiver) = mpsc::channel();
        self.lab_status = Some("Lab run started".to_string());
        self.lab_job = Some(receiver);
        thread::spawn(move || {
            let result = run_lab_scenario(&scenario, LabRunOptions { artifacts })
                .map(|result| LabJobOutcome::Run(Box::new(result)))
                .map_err(anyhow::Error::from);
            let _ = sender.send(result);
        });
    }

    pub(super) fn start_lab_summary(&mut self) {
        if !self.prepare_lab_job() {
            return;
        }
        let artifacts = self.artifacts_root.clone();
        let (sender, receiver) = mpsc::channel();
        self.lab_status = Some("Lab summary running".to_string());
        self.lab_job = Some(receiver);
        thread::spawn(move || {
            let result = summarize_lab_runs(&artifacts)
                .map(LabJobOutcome::Summary)
                .map_err(anyhow::Error::from);
            let _ = sender.send(result);
        });
    }

    pub(super) fn start_lab_dataset_export(&mut self) {
        if !self.prepare_lab_job() {
            return;
        }
        let artifacts = self.artifacts_root.clone();
        let output = artifacts.join("datasets").join("lab-feedback.jsonl");
        let (sender, receiver) = mpsc::channel();
        self.lab_status = Some("Dataset export running".to_string());
        self.lab_job = Some(receiver);
        thread::spawn(move || {
            let result = export_feedback_training_dataset(&artifacts, &output)
                .map(LabJobOutcome::DatasetExport)
                .map_err(anyhow::Error::from);
            let _ = sender.send(result);
        });
    }

    fn prepare_lab_job(&mut self) -> bool {
        if self.lab_job.is_some() {
            self.lab_status = Some("Lab job is already running".to_string());
            return false;
        }
        self.ensure_current_settings_for_operation()
    }
}
