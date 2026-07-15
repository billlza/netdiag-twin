#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UndeclaredMetricPolicy {
    Preserve,
    Missing,
}

mod application;
pub(crate) use application::apply_metric_quality_declarations;
mod declarations;
pub(crate) use declarations::{
    ADAPTER_PAYLOAD_SCHEMA_V1, ADAPTER_PAYLOAD_SCHEMA_V2, MetricQualityDeclarations,
    metric_quality_policy_for_schema,
};
