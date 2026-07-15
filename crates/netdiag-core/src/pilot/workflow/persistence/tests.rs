use super::super::super::{PilotDiagnosisSummary, PilotWorkflowPhase};
use super::*;
use chrono::Utc;
use tempfile::tempdir;

fn minimal_pilot_report(artifact_root: &std::path::Path, run_id: String) -> PilotReport {
    PilotReport {
        schema: "netdiag-pilot-report/v1".to_string(),
        generated_at: Utc::now(),
        pilot_id: "test-pilot".to_string(),
        pilot_name: "Test pilot".to_string(),
        read_only: true,
        passed: true,
        run_id,
        pilot_run_dir: artifact_root.display().to_string(),
        source_inventory: Vec::new(),
        connector_health: Vec::new(),
        diagnosis_summary: PilotDiagnosisSummary {
            diagnosis_status: "known".to_string(),
            primary_label: Some("normal".to_string()),
            root_causes: vec!["normal".to_string()],
            recommendation_count: 0,
        },
        evidence_bundle: None,
        checks: Vec::new(),
    }
}

#[test]
fn save_workflow_report_bubbles_io_errors() {
    let temp = tempdir().expect("tempdir");
    let blocked_dir = temp.path().join("blocked");
    std::fs::write(&blocked_dir, "not a directory").expect("blocked file");
    let pilot_run = minimal_pilot_report(&blocked_dir, "before".to_string());
    let report = PilotWorkflowReport {
        schema: "netdiag-pilot-workflow/v1".to_string(),
        generated_at: Utc::now(),
        pilot_id: pilot_run.pilot_id.clone(),
        passed: true,
        phases: Vec::<PilotWorkflowPhase>::new(),
        preflight: None,
        pilot_run: Some(pilot_run.clone()),
        verification: None,
    };

    let error = save_workflow_report(&pilot_run, &report)
        .expect_err("file-backed pilot_run_dir should reject child artifact writes");

    assert!(error.to_string().contains("blocked"));
}
