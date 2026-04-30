use crate::error::{IoContext, Result};
use crate::ingest::ingest_trace;
use crate::ml::infer;
use crate::models::{
    DiagnosisEvent, HilReviewSummary, IngestResult, MlResult, Recommendation, RunIndexEntry,
    RunManifest, TelemetrySummary, TopologyModel, WhatIfResult,
};
use crate::recommendation::recommend_actions;
use crate::report::{Report, RuleMlComparison, compare_rule_ml, render_report};
use crate::rules::diagnose_rules;
use crate::storage::{read_json, run_dir, save_json_atomic};
use crate::telemetry::summarize_telemetry;
use crate::twin::{run_simulated_whatif_with_model, topology_model};
use chrono::Utc;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use uuid::Uuid;

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
    pub run_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct WhatIfRequest {
    pub topology: TopologyModel,
    pub action_id: String,
}

impl WhatIfRequest {
    pub fn built_in(topology_key: &str, action_id: &str) -> Result<Self> {
        Ok(Self {
            topology: topology_model(topology_key)?,
            action_id: action_id.to_string(),
        })
    }
}

pub fn diagnose_file(
    path: impl AsRef<Path>,
    artifact_root: impl AsRef<Path>,
    default_what_if: Option<(&str, &str)>,
) -> Result<PipelineResult> {
    let ingest = ingest_trace(path)?;
    diagnose_ingest(ingest, artifact_root, default_what_if)
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
    std::fs::create_dir_all(artifact_root).with_path(artifact_root)?;
    let runs_root = artifact_root.join("runs");
    std::fs::create_dir_all(&runs_root).with_path(&runs_root)?;
    let run_id = Uuid::new_v4().to_string();
    let telemetry = summarize_telemetry(&ingest.records, 5)?;
    let diagnosis_events = diagnose_rules(&telemetry, &run_id);
    let ml_result = infer(&telemetry.windows, &run_id, artifact_root)?;
    let comparison = compare_rule_ml(&diagnosis_events, &ml_result);
    let what_if = default_what_if
        .map(|request| {
            run_simulated_whatif_with_model(
                &telemetry.overall,
                &request.topology,
                &request.action_id,
            )
        })
        .transpose()?;
    let recommendations = recommend_actions(&diagnosis_events, what_if.as_ref());
    let report = render_report(
        &run_id,
        &telemetry,
        &diagnosis_events,
        &ml_result,
        what_if.clone(),
        &recommendations,
    );
    let run_dir_path = run_dir(artifact_root, &run_id);
    let temp_run_dir = runs_root.join(format!(".{run_id}.tmp"));
    if temp_run_dir.exists() {
        std::fs::remove_dir_all(&temp_run_dir).with_path(&temp_run_dir)?;
    }
    std::fs::create_dir_all(&temp_run_dir).with_path(&temp_run_dir)?;
    let artifact_paths = PersistRun {
        write_dir_path: &temp_run_dir,
        final_run_dir_path: &run_dir_path,
        run_id: &run_id,
        ingest: &ingest,
        telemetry: &telemetry,
        diagnosis_events: &diagnosis_events,
        ml_result: &ml_result,
        what_if: what_if.as_ref(),
        recommendations: &recommendations,
        report: &report,
    }
    .persist()?;
    let manifest = RunManifest {
        run_id: run_id.clone(),
        sample: ingest.schema.sample.clone(),
        created_at: Utc::now(),
        trace_rows: ingest.schema.rows,
        artifact_paths,
    };
    save_json_atomic(temp_run_dir.join("manifest.json"), &manifest)?;
    if run_dir_path.exists() {
        std::fs::remove_dir_all(&run_dir_path).with_path(&run_dir_path)?;
    }
    std::fs::rename(&temp_run_dir, &run_dir_path).with_path(&run_dir_path)?;
    update_run_index(
        artifact_root,
        &manifest,
        &run_dir_path,
        HilReviewSummary::from_recommendations(&recommendations)
            .run_status()
            .to_string(),
    )?;

    Ok(PipelineResult {
        run_id,
        ingest,
        telemetry,
        diagnosis_events,
        ml_result,
        comparison,
        what_if,
        recommendations,
        report,
        run_dir: run_dir_path,
    })
}

fn update_run_index(
    artifact_root: &Path,
    manifest: &RunManifest,
    run_dir_path: &Path,
    status: String,
) -> Result<()> {
    let index_path = artifact_root.join("run_index.json");
    let mut entries = if index_path.exists() {
        serde_json::from_value::<Vec<RunIndexEntry>>(read_json(&index_path)?)?
    } else {
        Vec::new()
    };
    entries.retain(|entry| entry.run_id != manifest.run_id);
    entries.insert(
        0,
        RunIndexEntry {
            run_id: manifest.run_id.clone(),
            sample: manifest.sample.clone(),
            created_at: manifest.created_at,
            status,
            run_dir: run_dir_path.display().to_string(),
        },
    );
    entries.truncate(50);
    save_json_atomic(index_path, &entries)?;
    Ok(())
}

struct PersistRun<'a> {
    write_dir_path: &'a Path,
    final_run_dir_path: &'a Path,
    run_id: &'a str,
    ingest: &'a IngestResult,
    telemetry: &'a TelemetrySummary,
    diagnosis_events: &'a [DiagnosisEvent],
    ml_result: &'a MlResult,
    what_if: Option<&'a WhatIfResult>,
    recommendations: &'a [Recommendation],
    report: &'a Report,
}

impl PersistRun<'_> {
    fn persist(&self) -> Result<BTreeMap<String, String>> {
        let mut paths = BTreeMap::new();
        self.persist_artifact(
            &mut paths,
            "trace_schema",
            "trace_schema.json",
            &self.ingest.schema,
        )?;
        self.persist_artifact(
            &mut paths,
            "telemetry_summary",
            "telemetry_summary.json",
            self.telemetry,
        )?;
        self.persist_artifact(
            &mut paths,
            "telemetry_windows",
            "telemetry_windows.json",
            &self.telemetry.windows,
        )?;
        self.persist_artifact(
            &mut paths,
            "diagnosis_events",
            "diagnosis_events.json",
            self.diagnosis_events,
        )?;
        self.persist_artifact(&mut paths, "ml_result", "ml_result.json", self.ml_result)?;
        if let Some(what_if) = self.what_if {
            self.persist_artifact(
                &mut paths,
                "whatif_default",
                &format!("whatif_{}.json", what_if.action_id),
                what_if,
            )?;
        }
        self.persist_artifact(
            &mut paths,
            "recommendations",
            "recommendations.json",
            self.recommendations,
        )?;
        self.persist_artifact(&mut paths, "report", "report.json", self.report)?;
        paths.insert("run_id".to_string(), self.run_id.to_string());
        Ok(paths)
    }

    fn persist_artifact<T: Serialize + ?Sized>(
        &self,
        paths: &mut BTreeMap<String, String>,
        key: &str,
        file_name: &str,
        value: &T,
    ) -> Result<()> {
        save_json_atomic(self.write_dir_path.join(file_name), value)?;
        paths.insert(
            key.to_string(),
            self.final_run_dir_path
                .join(file_name)
                .display()
                .to_string(),
        );
        Ok(())
    }
}
