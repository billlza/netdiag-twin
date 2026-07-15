use super::{HilState, MetricQuality};
use serde::{Deserialize, Serialize};

mod percent_delta;
pub(crate) use percent_delta::percent_delta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendationStateChange {
    pub recommendation_id: String,
    pub left_state: HilState,
    pub right_state: HilState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricQualityChange {
    pub field: String,
    pub left_quality: MetricQuality,
    pub right_quality: MetricQuality,
}
