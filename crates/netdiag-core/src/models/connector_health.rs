use super::{
    ConnectorHealthSnapshot, ConnectorHealthStatus, IngestResult, MeasurementQualitySummary,
    MetricProvenance, MetricQuality,
};

impl ConnectorHealthSnapshot {
    pub fn from_ingest(
        source_kind: &str,
        profile_name: &str,
        sample: &str,
        ingest: &IngestResult,
    ) -> Self {
        let quality = MeasurementQualitySummary::from_provenance(&ingest.metric_provenance);
        let status = if ingest.records.is_empty() {
            ConnectorHealthStatus::Error
        } else if !ingest.warnings.is_empty() || quality.degraded() {
            ConnectorHealthStatus::Degraded
        } else {
            ConnectorHealthStatus::Ok
        };
        Self {
            status,
            source_kind: source_kind.to_string(),
            profile_name: profile_name.to_string(),
            sample: sample.to_string(),
            rows: ingest.schema.rows,
            warning_count: ingest.warnings.len(),
            missing_metrics: missing_metric_names(&ingest.metric_provenance),
            quality,
            captured_at: ingest.schema.ingested_at,
        }
    }
}

pub(crate) fn missing_metric_names(provenance: &[MetricProvenance]) -> Vec<String> {
    provenance
        .iter()
        .filter(|item| {
            matches!(
                item.quality,
                MetricQuality::Fallback | MetricQuality::Missing
            )
        })
        .map(|item| item.field.clone())
        .collect()
}
