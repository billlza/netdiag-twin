use super::super::{PilotReport, PilotWorkflowReport};
use crate::error::Result;
use crate::storage::save_json_atomic;
use std::path::PathBuf;

pub(super) fn save_workflow_report(
    pilot_run: &PilotReport,
    report: &PilotWorkflowReport,
) -> Result<()> {
    let report_path = PathBuf::from(&pilot_run.pilot_run_dir).join("pilot_workflow.json");
    save_json_atomic(report_path, report)?;
    Ok(())
}

#[cfg(test)]
mod tests;
