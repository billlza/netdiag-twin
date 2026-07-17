use super::persist::PersistRun;
use super::publication::{PendingRunPublication, RunPublicationRoot};
use super::{
    PipelineResult, maybe_fail_after_run_publication_journal, maybe_fail_run_index_update,
};
use crate::error::{AtomicPublishPhase, NetdiagError, Result};
use crate::models::{
    ConnectorHealthSnapshot, DiagnosisEvent, HilReviewSummary, IngestResult, MlResult,
    Recommendation, RunManifest, TelemetrySummary, WhatIfResult,
};
use crate::report::{Report, RuleMlComparison};
use crate::storage::typed_json::MAX_RUN_MANIFEST_BYTES;
use crate::storage::{
    abandon_run_publication_not_published, begin_run_publication, complete_run_publication,
    preserve_published_directory, reconcile_nested_run_publication_index,
    reconcile_run_publication_index,
};
use chrono::Utc;

mod result;

pub(super) struct ComputedPipelineRun {
    pub(super) run_id: String,
    pub(super) ingest: IngestResult,
    pub(super) telemetry: TelemetrySummary,
    pub(super) diagnosis_events: Vec<DiagnosisEvent>,
    pub(super) ml_result: MlResult,
    pub(super) comparison: RuleMlComparison,
    pub(super) what_if: Option<WhatIfResult>,
    pub(super) recommendations: Vec<Recommendation>,
    pub(super) report: Report,
    pub(super) connector_health: ConnectorHealthSnapshot,
}

impl ComputedPipelineRun {
    pub(super) fn publish(
        self,
        pending: PendingRunPublication,
        root: RunPublicationRoot<'_>,
    ) -> Result<PipelineResult> {
        let mut staged = pending.stage(root)?;
        let artifact_paths = match (PersistRun {
            run_id: &self.run_id,
            ingest: &self.ingest,
            telemetry: &self.telemetry,
            diagnosis_events: &self.diagnosis_events,
            ml_result: &self.ml_result,
            what_if: self.what_if.as_ref(),
            recommendations: &self.recommendations,
            report: &self.report,
            connector_health: &self.connector_health,
        })
        .persist(&mut staged)
        {
            Ok(paths) => paths,
            Err(source) => return Err(staged.abort(source)),
        };
        let manifest = RunManifest {
            run_id: self.run_id.clone(),
            sample: self.ingest.schema.sample.clone(),
            created_at: Utc::now(),
            trace_rows: self.ingest.schema.rows,
            artifact_paths,
        };
        if let Err(source) = staged.save_json_bounded(
            "manifest.json",
            &manifest,
            MAX_RUN_MANIFEST_BYTES,
            "run manifest",
        ) {
            return Err(staged.abort(source));
        }
        let status = HilReviewSummary::from_recommendations(&self.recommendations)
            .run_status()
            .to_string();
        let publication_journal = match root {
            RunPublicationRoot::Owned(owned) => {
                match begin_run_publication(owned, &staged, &manifest, status.clone()) {
                    Ok(journal) => Some(journal),
                    Err(source) => return Err(staged.abort(source)),
                }
            }
            RunPublicationRoot::Nested(_) => None,
        };
        if publication_journal.is_some() {
            maybe_fail_after_run_publication_journal()?;
        }
        let run_dir_path = match staged.publish() {
            Ok(path) => path,
            Err(error) => {
                if error.atomic_publish_phase() == Some(AtomicPublishPhase::NotPublished)
                    && let (RunPublicationRoot::Owned(owned), Some(journal)) =
                        (root, publication_journal.as_ref())
                {
                    return Err(abandon_run_publication_not_published(owned, journal, error));
                }
                return Err(error);
            }
        };
        let index_update = maybe_fail_run_index_update().and_then(|()| match root {
            RunPublicationRoot::Owned(owned) => {
                let journal = publication_journal.as_ref().ok_or_else(|| {
                    NetdiagError::InvalidTrace(
                        "owned run publication is missing its journal".to_string(),
                    )
                })?;
                reconcile_run_publication_index(owned, journal)
            }
            RunPublicationRoot::Nested(staged_root) => reconcile_nested_run_publication_index(
                staged_root.trusted_directory(),
                &manifest,
                status,
            ),
        });
        preserve_published_directory(&run_dir_path, index_update)?;
        if let (RunPublicationRoot::Owned(owned), Some(journal)) =
            (root, publication_journal.as_ref())
        {
            preserve_published_directory(&run_dir_path, complete_run_publication(owned, journal))?;
        }
        Ok(self.into_result(run_dir_path))
    }
}
