use self::pilot_sources::{AdapterExecutionBoundary, load_pilot_source_with_boundary};
use self::prepared::{PreparedPilot, read_manifest};
use self::run_directory::create_staged_pilot_run;
use crate::connectors::authentication::BearerEnvironmentBindings;
use crate::error::{NetdiagError, Result};
use crate::ml::ModelBundleSnapshot;
use crate::models::ConnectorHealthStatus;
use crate::pipeline::{
    diagnose_ingest_with_nested_artifact_root_and_model_snapshot_and_connector_health,
    ensure_run_directory_publication_supported,
};
use crate::reliability::ReliabilityCheck;
use crate::storage::{
    ArtifactRootCapability, finish_root_bound_staged_directory, prepare_artifact_root,
    save_json_atomic, with_artifact_root_capability,
};
use chrono::Utc;
use std::path::Path;

mod adapter_contract;
mod bearer;
mod evidence;
mod pilot_sources;
mod preflight;
mod prepared;
mod promotion;
mod redaction;
mod run_directory;
mod types;
mod validation;
mod workflow;

use preflight::{
    PreparedPilotPreflight, prepare_pilot_preflight, prepare_pilot_run_preflight,
    require_model_snapshot,
};
pub use promotion::*;
use redaction::{persist_redacted_pilot_manifest, redacted_endpoint, source_inventory};
pub use types::*;
pub use validation::validate_pilot_manifest;
pub use workflow::*;

const PILOT_SCHEMA: &str = "netdiag-pilot/v1";
const PILOT_REPORT_SCHEMA: &str = "netdiag-pilot-report/v1";

pub fn load_pilot_manifest(path: impl AsRef<Path>) -> Result<PilotManifest> {
    read_manifest(path.as_ref())
}

pub fn preflight_pilot(
    path: impl AsRef<Path>,
    options: PilotOptions,
) -> Result<PilotPreflightReport> {
    preflight_pilot_with_bearer_bindings(path, options, &BearerEnvironmentBindings::default())
}

pub fn preflight_pilot_with_bearer_bindings(
    path: impl AsRef<Path>,
    options: PilotOptions,
    bindings: &BearerEnvironmentBindings,
) -> Result<PilotPreflightReport> {
    let prepared = PreparedPilot::load(path.as_ref())?;
    let operation =
        prepare_pilot_preflight(&prepared, &options, bindings).map(|preflight| preflight.report);
    prepared.finish(operation)
}

pub fn run_pilot(path: impl AsRef<Path>, options: PilotOptions) -> Result<PilotReport> {
    run_pilot_with_bearer_bindings(path, options, &BearerEnvironmentBindings::default())
}

pub fn run_pilot_with_bearer_bindings(
    path: impl AsRef<Path>,
    options: PilotOptions,
    bindings: &BearerEnvironmentBindings,
) -> Result<PilotReport> {
    ensure_run_directory_publication_supported(&options.artifacts)?;
    let prepared = PreparedPilot::load(path.as_ref())?;
    let capability = prepare_artifact_root(&options.artifacts)?;
    let operation = (|| {
        let preflight = prepare_pilot_run_preflight(&prepared, &options, bindings, &capability)?;
        if !preflight.report.passed {
            return Err(NetdiagError::InvalidTrace(format!(
                "pilot preflight failed for {}",
                prepared.manifest.id
            )));
        }
        let model_snapshot = require_model_snapshot(preflight.model_snapshot, "pilot")?;
        run_prepared_pilot(&prepared, options, &model_snapshot, bindings, &capability)
    })();
    prepared.finish(operation)
}

fn run_prepared_pilot(
    prepared: &PreparedPilot,
    options: PilotOptions,
    model_snapshot: &ModelBundleSnapshot,
    bindings: &BearerEnvironmentBindings,
    capability: &ArtifactRootCapability,
) -> Result<PilotReport> {
    let manifest = &prepared.manifest;
    let declarations = bearer::declarations(manifest)?;
    let resolved_tokens = bindings.resolve_all(&declarations)?;
    let base_dir = &prepared.manifest_dir;
    let adapter_boundary = prepared.adapter_boundary.as_ref();
    AdapterExecutionBoundary::ensure_authorized(manifest, options.allow_adapter_execution)?;
    let created_at = Utc::now();
    let staged = with_artifact_root_capability(capability, |owned| {
        create_staged_pilot_run(owned, &manifest.id, created_at)
    })?;
    let staged_run_dir = staged.staging_path().to_path_buf();
    let published_run_dir = staged.target_path().to_path_buf();
    let operation = (|| {
        persist_redacted_pilot_manifest(manifest, &staged_run_dir.join("pilot.yaml"))?;

        let loaded = manifest
            .sources
            .iter()
            .map(|source| {
                load_pilot_source_with_boundary(
                    source,
                    base_dir,
                    adapter_boundary,
                    options.allow_adapter_execution,
                    &resolved_tokens,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let primary = loaded
            .iter()
            .find(|item| item.source.role == PilotSourceRole::Primary)
            .ok_or_else(|| {
                NetdiagError::InvalidTrace("pilot primary source missing".to_string())
            })?;
        let pipeline =
            diagnose_ingest_with_nested_artifact_root_and_model_snapshot_and_connector_health(
                primary.ingest.clone(),
                &staged,
                model_snapshot,
                None,
                primary.health.clone(),
            )?;
        let connector_health = loaded
            .iter()
            .map(|item| item.health.clone())
            .collect::<Vec<_>>();
        save_json_atomic(
            staged_run_dir.join("connector_health.json"),
            &connector_health,
        )?;

        let gate_status = evidence::aggregate_connector_status(&connector_health);
        let mut report = PilotReport {
            schema: PILOT_REPORT_SCHEMA.to_string(),
            generated_at: Utc::now(),
            pilot_id: manifest.id.clone(),
            pilot_name: manifest.name.clone(),
            read_only: !manifest.sources.iter().any(|source| source.active),
            passed: false,
            run_id: pipeline.run_id.clone(),
            pilot_run_dir: published_run_dir.display().to_string(),
            source_inventory: source_inventory(manifest)?,
            connector_health,
            diagnosis_summary: PilotDiagnosisSummary {
                diagnosis_status: pipeline.report.diagnosis_status.as_str().to_string(),
                primary_label: pipeline
                    .report
                    .diagnosis_decision
                    .primary_label
                    .map(|label| label.as_str().to_string()),
                root_causes: pipeline
                    .report
                    .root_causes
                    .iter()
                    .map(|root| root.symptom.clone())
                    .collect(),
                recommendation_count: pipeline.report.recommendations.len(),
            },
            evidence_bundle: None,
            checks: Vec::new(),
        };
        let redacted_source_files =
            evidence::persist_redacted_source_payloads(&loaded, &staged_run_dir)?;
        report.checks = evidence::checks_before_bundle(&staged_run_dir, &pipeline.run_id)?;
        rewrite_staged_check_paths(&mut report.checks, &staged_run_dir, &published_run_dir);
        report.passed = manifest
            .gates
            .allowed_connector_status
            .contains(&gate_status)
            && !report
                .checks
                .iter()
                .any(|check| check.status == ConnectorHealthStatus::Error);
        evidence::export_final_result(
            &mut report,
            &staged_run_dir,
            &published_run_dir,
            &redacted_source_files,
        )?;
        Ok(report)
    })();
    finish_root_bound_staged_directory(capability, staged, operation, |_, _, _| Ok(()))
        .map(|(report, _)| report)
}

fn rewrite_staged_check_paths(checks: &mut [ReliabilityCheck], staged: &Path, published: &Path) {
    for check in checks {
        let Some(artifact) = check.artifact.as_deref() else {
            continue;
        };
        let Ok(relative) = Path::new(artifact).strip_prefix(staged) else {
            continue;
        };
        check.artifact = Some(published.join(relative).display().to_string());
    }
}

fn render_pilot_markdown(report: &PilotReport) -> String {
    let mut body = String::new();
    body.push_str("# NetDiag Twin Pilot Report\n\n");
    body.push_str(&format!(
        "- Pilot: `{}`\n- Status: `{}`\n- Run ID: `{}`\n- Read-only: `{}`\n\n",
        report.pilot_id,
        if report.passed { "passed" } else { "failed" },
        report.run_id,
        report.read_only
    ));
    body.push_str("## Diagnosis\n\n");
    body.push_str(&format!(
        "- Status: `{}`\n- Primary label: `{}`\n- Recommendations: `{}`\n\n",
        report.diagnosis_summary.diagnosis_status,
        report
            .diagnosis_summary
            .primary_label
            .as_deref()
            .unwrap_or("n/a"),
        report.diagnosis_summary.recommendation_count,
    ));
    body.push_str("## Sources\n\n| Name | Kind | Role | Active | Endpoint |\n| --- | --- | --- | --- | --- |\n");
    for source in &report.source_inventory {
        body.push_str(&format!(
            "| {} | {:?} | {:?} | {} | {} |\n",
            source.name, source.kind, source.role, source.active, source.endpoint
        ));
    }
    body
}

#[cfg(test)]
mod tests;
