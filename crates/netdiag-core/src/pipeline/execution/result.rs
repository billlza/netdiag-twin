use super::ComputedPipelineRun;
use crate::pipeline::PipelineResult;
use std::path::PathBuf;

impl ComputedPipelineRun {
    pub(super) fn into_result(self, run_dir: PathBuf) -> PipelineResult {
        PipelineResult {
            run_id: self.run_id,
            ingest: self.ingest,
            telemetry: self.telemetry,
            diagnosis_events: self.diagnosis_events,
            ml_result: self.ml_result,
            comparison: self.comparison,
            what_if: self.what_if,
            recommendations: self.recommendations,
            report: self.report,
            connector_health: self.connector_health,
            run_dir,
        }
    }
}
