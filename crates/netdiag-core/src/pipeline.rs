#[cfg(test)]
use crate::error::NetdiagError;
use crate::error::Result;
use crate::ingest::ingest_trace;
use crate::ml::{
    ModelBundleSnapshot, ModelLoadPolicy, infer_with_quality_from_model_bundle_snapshot,
    load_model_bundle_snapshot_with_policy,
};
use crate::models::{
    ConnectorHealthSnapshot, DiagnosisEvent, IngestResult, MlResult, Recommendation,
    TelemetrySummary, TopologyModel, TwinPolicyAction, WhatIfResult,
};
use crate::recommendation::recommend_actions;
use crate::report::{Report, RuleMlComparison, compare_rule_ml, decide_diagnosis, render_report};
use crate::rules::diagnose_rules;
use crate::storage::{
    ArtifactRootCapability, StagedAtomicDirectory, prepare_artifact_root,
    with_artifact_root_capability,
};
use crate::telemetry::summarize_ingest;
use crate::twin::{policy_action, run_simulated_whatif_with_policy, topology_model};
use std::path::{Path, PathBuf};

mod artifact;
mod connector_health;
use connector_health::validated_connector_health;
mod execution;
use execution::ComputedPipelineRun;
mod publication;
use publication::{PendingRunPublication, RunPublicationRoot};
mod persist;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct PipelineResult {
    pub run_id: String,
    pub ingest: IngestResult,
    pub telemetry: TelemetrySummary,
    pub diagnosis_events: Vec<DiagnosisEvent>,
    pub ml_result: MlResult,
    pub comparison: RuleMlComparison,
    pub what_if: Option<WhatIfResult>,
    pub recommendations: Vec<Recommendation>,
    pub report: Report,
    pub connector_health: ConnectorHealthSnapshot,
    pub run_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WhatIfRequest {
    pub topology: TopologyModel,
    pub action: TwinPolicyAction,
}

impl WhatIfRequest {
    pub fn built_in(topology_key: &str, action_id: &str) -> Result<Self> {
        Ok(Self {
            topology: topology_model(topology_key)?,
            action: policy_action(action_id)?,
        })
    }
}

pub fn diagnose_file(
    path: impl AsRef<Path>,
    artifact_root: impl AsRef<Path>,
    default_what_if: Option<(&str, &str)>,
) -> Result<PipelineResult> {
    ensure_run_directory_publication_supported(artifact_root.as_ref())?;
    let ingest = ingest_trace(path)?;
    diagnose_ingest(ingest, artifact_root, default_what_if)
}

pub(crate) fn ensure_run_directory_publication_supported(
    artifact_root: impl AsRef<Path>,
) -> Result<()> {
    publication::preflight(artifact_root.as_ref())
}

pub fn diagnose_ingest(
    ingest: IngestResult,
    artifact_root: impl AsRef<Path>,
    default_what_if: Option<(&str, &str)>,
) -> Result<PipelineResult> {
    let what_if_request = default_what_if
        .map(|(topology, action)| WhatIfRequest::built_in(topology, action))
        .transpose()?;
    diagnose_ingest_with_whatif(ingest, artifact_root, what_if_request)
}

pub fn diagnose_ingest_with_whatif(
    ingest: IngestResult,
    artifact_root: impl AsRef<Path>,
    default_what_if: Option<WhatIfRequest>,
) -> Result<PipelineResult> {
    let artifact_root = artifact_root.as_ref();
    diagnose_ingest_with_whatif_and_model_dir(
        ingest,
        artifact_root,
        artifact_root.join("model"),
        default_what_if,
    )
}

pub fn diagnose_ingest_with_whatif_and_connector_health(
    ingest: IngestResult,
    artifact_root: impl AsRef<Path>,
    default_what_if: Option<WhatIfRequest>,
    connector_health: ConnectorHealthSnapshot,
) -> Result<PipelineResult> {
    let artifact_root = artifact_root.as_ref();
    diagnose_ingest_with_whatif_and_model_dir_with_policy(
        ingest,
        artifact_root,
        artifact_root.join("model"),
        default_what_if,
        ModelLoadPolicy::AllowSyntheticFallback,
        Some(connector_health),
    )
}

pub fn diagnose_ingest_with_whatif_and_model_dir(
    ingest: IngestResult,
    artifact_root: impl AsRef<Path>,
    model_dir: impl AsRef<Path>,
    default_what_if: Option<WhatIfRequest>,
) -> Result<PipelineResult> {
    diagnose_ingest_with_whatif_and_model_dir_with_policy(
        ingest,
        artifact_root,
        model_dir,
        default_what_if,
        ModelLoadPolicy::AllowSyntheticFallback,
        None,
    )
}

pub fn diagnose_ingest_with_whatif_and_existing_model_dir(
    ingest: IngestResult,
    artifact_root: impl AsRef<Path>,
    model_dir: impl AsRef<Path>,
    default_what_if: Option<WhatIfRequest>,
) -> Result<PipelineResult> {
    diagnose_ingest_with_whatif_and_model_dir_with_policy(
        ingest,
        artifact_root,
        model_dir,
        default_what_if,
        ModelLoadPolicy::ExistingOnly,
        None,
    )
}

fn diagnose_ingest_with_whatif_and_model_dir_with_policy(
    ingest: IngestResult,
    artifact_root: impl AsRef<Path>,
    model_dir: impl AsRef<Path>,
    default_what_if: Option<WhatIfRequest>,
    model_load_policy: ModelLoadPolicy,
    connector_health: Option<ConnectorHealthSnapshot>,
) -> Result<PipelineResult> {
    publication::preflight(artifact_root.as_ref())?;
    let connector_health = validated_connector_health(&ingest, connector_health)?;
    let artifact_root = artifact_root.as_ref();
    let capability = prepare_artifact_root(artifact_root)?;
    let load_snapshot =
        || load_model_bundle_snapshot_with_policy(model_dir.as_ref(), model_load_policy);
    let snapshot = with_artifact_root_capability(&capability, |_| load_snapshot())?;
    diagnose_ingest_with_authorized_model_snapshot(
        ingest,
        &snapshot,
        default_what_if,
        connector_health,
        &capability,
    )
}

pub(crate) fn diagnose_ingest_with_whatif_and_model_snapshot_and_capability(
    ingest: IngestResult,
    model_snapshot: &ModelBundleSnapshot,
    default_what_if: Option<WhatIfRequest>,
    capability: &ArtifactRootCapability,
) -> Result<PipelineResult> {
    publication::preflight(capability.path())?;
    let connector_health = validated_connector_health(&ingest, None)?;
    diagnose_ingest_with_authorized_model_snapshot(
        ingest,
        model_snapshot,
        default_what_if,
        connector_health,
        capability,
    )
}

pub(crate) fn diagnose_ingest_with_nested_artifact_root_and_model_snapshot_and_connector_health(
    ingest: IngestResult,
    nested_root: &StagedAtomicDirectory,
    model_snapshot: &ModelBundleSnapshot,
    default_what_if: Option<WhatIfRequest>,
    connector_health: ConnectorHealthSnapshot,
) -> Result<PipelineResult> {
    let connector_health = validated_connector_health(&ingest, Some(connector_health))?;
    let pending = PendingRunPublication::prepare();
    let computed = compute_pipeline_run(
        ingest,
        &pending,
        model_snapshot,
        default_what_if,
        connector_health,
    )?;
    computed.publish(pending, RunPublicationRoot::Nested(nested_root))
}

pub(crate) fn diagnose_ingest_with_nested_artifact_root_and_model_snapshot(
    ingest: IngestResult,
    nested_root: &StagedAtomicDirectory,
    model_snapshot: &ModelBundleSnapshot,
    default_what_if: Option<WhatIfRequest>,
) -> Result<PipelineResult> {
    let connector_health = validated_connector_health(&ingest, None)?;
    diagnose_ingest_with_nested_artifact_root_and_model_snapshot_and_connector_health(
        ingest,
        nested_root,
        model_snapshot,
        default_what_if,
        connector_health,
    )
}

fn diagnose_ingest_with_authorized_model_snapshot(
    ingest: IngestResult,
    model_snapshot: &ModelBundleSnapshot,
    default_what_if: Option<WhatIfRequest>,
    connector_health: ConnectorHealthSnapshot,
    capability: &ArtifactRootCapability,
) -> Result<PipelineResult> {
    let pending = PendingRunPublication::prepare();
    let computed = compute_pipeline_run(
        ingest,
        &pending,
        model_snapshot,
        default_what_if,
        connector_health,
    )?;
    with_artifact_root_capability(capability, |owned| {
        computed.publish(pending, RunPublicationRoot::Owned(owned))
    })
}

fn compute_pipeline_run(
    ingest: IngestResult,
    pending: &PendingRunPublication,
    model_snapshot: &ModelBundleSnapshot,
    default_what_if: Option<WhatIfRequest>,
    connector_health: ConnectorHealthSnapshot,
) -> Result<ComputedPipelineRun> {
    let run_id = pending.run_id().to_string();
    let telemetry = summarize_ingest(&ingest, 5)?;
    let diagnosis_events = diagnose_rules(&telemetry, &run_id);
    let ml_result = infer_with_quality_from_model_bundle_snapshot(
        &telemetry.windows,
        &run_id,
        model_snapshot,
        &telemetry.metric_provenance,
    )?;
    let comparison = compare_rule_ml(&diagnosis_events, &ml_result);
    let what_if = default_what_if
        .map(|request| {
            run_simulated_whatif_with_policy(&telemetry.overall, &request.topology, &request.action)
        })
        .transpose()?;
    let diagnosis_decision = decide_diagnosis(&diagnosis_events, &ml_result);
    let recommendations =
        recommend_actions(&diagnosis_events, what_if.as_ref(), &diagnosis_decision);
    let report = render_report(
        &run_id,
        &telemetry,
        &diagnosis_events,
        &ml_result,
        &diagnosis_decision,
        what_if.clone(),
        &recommendations,
    );
    Ok(ComputedPipelineRun {
        run_id,
        ingest,
        telemetry,
        diagnosis_events,
        ml_result,
        comparison,
        what_if,
        recommendations,
        report,
        connector_health,
    })
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_RUN_INDEX_UPDATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_AFTER_RUN_PUBLICATION_JOURNAL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn fail_next_run_index_update() {
    FAIL_NEXT_RUN_INDEX_UPDATE.with(|fail| fail.set(true));
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn fail_after_run_publication_journal() {
    FAIL_AFTER_RUN_PUBLICATION_JOURNAL.with(|fail| fail.set(true));
}

fn maybe_fail_run_index_update() -> Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_RUN_INDEX_UPDATE.with(|fail| fail.replace(false)) {
        return Err(NetdiagError::InvalidTrace(
            "injected run index update failure".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn maybe_fail_after_run_publication_journal() -> Result<()> {
    if FAIL_AFTER_RUN_PUBLICATION_JOURNAL.with(std::cell::Cell::take) {
        return Err(NetdiagError::InvalidTrace(
            "injected crash after run publication journal".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(test))]
fn maybe_fail_after_run_publication_journal() -> Result<()> {
    Ok(())
}
