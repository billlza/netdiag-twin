use super::{MetricQualityDeclarations, UndeclaredMetricPolicy};
use crate::ingest::{CANONICAL_COLUMNS, set_metric_provenance};
use crate::models::{IngestResult, MetricQuality};

pub(crate) fn apply_metric_quality_declarations(
    ingest: &mut IngestResult,
    declarations: &MetricQualityDeclarations,
    source: &str,
    undeclared_policy: UndeclaredMetricPolicy,
) {
    if undeclared_policy == UndeclaredMetricPolicy::Missing {
        for field in CANONICAL_COLUMNS
            .iter()
            .copied()
            .filter(|field| *field != "timestamp")
        {
            set_metric_provenance(
                ingest,
                field,
                MetricQuality::Missing,
                source,
                "source payload did not declare measurement quality for this metric",
            );
        }
    }
    for (field, quality) in declarations.entries() {
        set_metric_provenance(ingest, field, quality, source, quality_reason(quality));
    }
}

fn quality_reason(quality: MetricQuality) -> &'static str {
    match quality {
        MetricQuality::Measured => "source payload declares this metric as directly measured",
        MetricQuality::Estimated => "source payload declares this metric as estimated",
        MetricQuality::Fallback => "source payload declares this metric as a fallback proxy",
        MetricQuality::Missing => "source payload declares this metric as unavailable",
    }
}
