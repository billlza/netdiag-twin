use super::artifact::{BoundedArtifact, validate_artifact_file_name};
use super::publication::StagedRunDirectory;
use crate::error::Result;
use crate::models::{
    ConnectorHealthSnapshot, DiagnosisEvent, IngestResult, MlResult, Recommendation,
    TelemetrySummary, WhatIfResult,
};
use crate::report::Report;
use crate::storage::typed_json::{
    MAX_CONNECTOR_HEALTH_BYTES, MAX_ML_RESULT_BYTES, MAX_RUN_REPORT_BYTES,
};
use serde::Serialize;
use std::collections::BTreeMap;

pub(super) struct PersistRun<'a> {
    pub(super) run_id: &'a str,
    pub(super) ingest: &'a IngestResult,
    pub(super) telemetry: &'a TelemetrySummary,
    pub(super) diagnosis_events: &'a [DiagnosisEvent],
    pub(super) ml_result: &'a MlResult,
    pub(super) what_if: Option<&'a WhatIfResult>,
    pub(super) recommendations: &'a [Recommendation],
    pub(super) report: &'a Report,
    pub(super) connector_health: &'a ConnectorHealthSnapshot,
}

impl PersistRun<'_> {
    pub(super) fn persist(
        &self,
        staged: &mut StagedRunDirectory,
    ) -> Result<BTreeMap<String, String>> {
        let mut paths = BTreeMap::new();
        self.persist_artifact(
            staged,
            &mut paths,
            "trace_schema",
            "trace_schema.json",
            &self.ingest.schema,
        )?;
        self.persist_artifact(
            staged,
            &mut paths,
            "telemetry_summary",
            "telemetry_summary.json",
            self.telemetry,
        )?;
        self.persist_artifact(
            staged,
            &mut paths,
            "telemetry_windows",
            "telemetry_windows.json",
            &self.telemetry.windows,
        )?;
        self.persist_artifact(
            staged,
            &mut paths,
            "diagnosis_events",
            "diagnosis_events.json",
            self.diagnosis_events,
        )?;
        self.persist_bounded_artifact(
            staged,
            &mut paths,
            BoundedArtifact {
                key: "ml_result",
                file_name: "ml_result.json",
                max_bytes: MAX_ML_RESULT_BYTES,
                kind: "ML result",
            },
            self.ml_result,
        )?;
        if let Some(what_if) = self.what_if {
            self.persist_artifact(
                staged,
                &mut paths,
                "whatif_default",
                &format!("whatif_{}.json", what_if.action_id),
                what_if,
            )?;
        }
        self.persist_artifact(
            staged,
            &mut paths,
            "recommendations",
            "recommendations.json",
            self.recommendations,
        )?;
        self.persist_bounded_artifact(
            staged,
            &mut paths,
            BoundedArtifact {
                key: "connector_health",
                file_name: "connector_health.json",
                max_bytes: MAX_CONNECTOR_HEALTH_BYTES,
                kind: "connector health",
            },
            self.connector_health,
        )?;
        self.persist_bounded_artifact(
            staged,
            &mut paths,
            BoundedArtifact {
                key: "report",
                file_name: "report.json",
                max_bytes: MAX_RUN_REPORT_BYTES,
                kind: "run report",
            },
            self.report,
        )?;
        paths.insert("run_id".to_string(), self.run_id.to_string());
        Ok(paths)
    }

    fn persist_artifact<T: Serialize + ?Sized>(
        &self,
        staged: &mut StagedRunDirectory,
        paths: &mut BTreeMap<String, String>,
        key: &str,
        file_name: &str,
        value: &T,
    ) -> Result<()> {
        validate_artifact_file_name(file_name)?;
        staged.save_json(file_name, value)?;
        paths.insert(key.to_string(), file_name.to_string());
        Ok(())
    }

    fn persist_bounded_artifact<T: Serialize + ?Sized>(
        &self,
        staged: &mut StagedRunDirectory,
        paths: &mut BTreeMap<String, String>,
        artifact: BoundedArtifact<'_>,
        value: &T,
    ) -> Result<()> {
        validate_artifact_file_name(artifact.file_name)?;
        staged.save_json_bounded(artifact.file_name, value, artifact.max_bytes, artifact.kind)?;
        paths.insert(artifact.key.to_string(), artifact.file_name.to_string());
        Ok(())
    }
}
