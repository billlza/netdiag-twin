use super::pilot_sources::LoadedPilotSource;
use super::{PilotReport, render_pilot_markdown};
use crate::error::{NetdiagError, Result};
use crate::evidence_bundle::{
    EvidenceBundleExtraFile, EvidenceContext, export_evidence_bundle_from_staged_directory,
};
use crate::models::{ConnectorHealthSnapshot, ConnectorHealthStatus};
use crate::reliability::{
    ReliabilityCheck, ReliabilityCheckOptions, ReliabilityReasonCode, check_reliability,
    write_text_atomic,
};
use crate::storage::{run_dir, save_json_atomic};
use std::path::Path;

pub(super) fn persist_redacted_source_payloads(
    loaded: &[LoadedPilotSource],
    pilot_run_dir: &Path,
) -> Result<Vec<EvidenceBundleExtraFile>> {
    let mut evidence_files = Vec::new();
    for item in loaded {
        if let Some(payload) = &item.redacted_payload {
            let file_name = format!("source_{}_redacted.json", item.source.name);
            let path = pilot_run_dir.join(&file_name);
            save_json_atomic(&path, payload)?;
            evidence_files.push(EvidenceBundleExtraFile {
                key: format!("pilot_source_{}_redacted", item.source.name),
                path,
                zip_path: file_name,
            });
        }
    }
    Ok(evidence_files)
}

pub(super) fn checks_before_bundle(
    pilot_run_dir: &Path,
    run_id: &str,
) -> Result<Vec<ReliabilityCheck>> {
    let report = check_reliability(ReliabilityCheckOptions {
        artifact_root: pilot_run_dir.to_path_buf(),
        run_id: Some(run_id.to_string()),
    })?;
    remove_expected_pending_bundle_check(report.checks)
}

pub(super) fn export_final_result(
    report: &mut PilotReport,
    staged_pilot_run_dir: &Path,
    published_pilot_run_dir: &Path,
    extra_files: &[EvidenceBundleExtraFile],
) -> Result<()> {
    save_json_atomic(
        staged_pilot_run_dir.join("pilot_evidence_report.json"),
        report,
    )?;
    write_text_atomic(
        staged_pilot_run_dir.join("pilot_summary.md"),
        &render_pilot_markdown(report),
    )?;
    let archive_name = format!("netdiag-evidence-{}.zip", report.run_id);
    let evidence_bundle = export_evidence_bundle_from_staged_directory(
        staged_pilot_run_dir,
        published_pilot_run_dir,
        &report.run_id,
        &staged_pilot_run_dir.join(&archive_name),
        &published_pilot_run_dir.join(archive_name),
        EvidenceContext::Pilot,
        extra_files,
    )?;
    save_json_atomic(
        run_dir(staged_pilot_run_dir, &report.run_id)?.join("evidence_bundle.json"),
        &evidence_bundle,
    )?;
    report.evidence_bundle = Some(evidence_bundle);
    save_json_atomic(staged_pilot_run_dir.join("pilot_report.json"), report)?;
    Ok(())
}

fn remove_expected_pending_bundle_check(
    checks: Vec<ReliabilityCheck>,
) -> Result<Vec<ReliabilityCheck>> {
    let mut found_expected = false;
    let mut retained = Vec::with_capacity(checks.len());
    for check in checks {
        if check.name != "evidence bundle freshness" {
            retained.push(check);
            continue;
        }
        let is_expected = !found_expected
            && check.status == ConnectorHealthStatus::Error
            && check.reason_codes == [ReliabilityReasonCode::ArtifactMissing]
            && check
                .artifact
                .as_deref()
                .is_some_and(|path| path.ends_with("evidence_bundle.json"));
        if !is_expected {
            return Err(NetdiagError::InvalidTrace(format!(
                "pilot pre-export reliability returned an unexpected evidence bundle check: {}",
                check.message
            )));
        }
        found_expected = true;
    }
    if !found_expected {
        return Err(NetdiagError::InvalidTrace(
            "pilot pre-export reliability did not report the required pending evidence bundle"
                .to_string(),
        ));
    }
    Ok(retained)
}

pub(super) fn aggregate_connector_status(
    health: &[ConnectorHealthSnapshot],
) -> ConnectorHealthStatus {
    health
        .iter()
        .map(|item| item.status)
        .max()
        .unwrap_or(ConnectorHealthStatus::Error)
}

#[cfg(test)]
mod tests;
