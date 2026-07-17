use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PrometheusQueryWindowError {
    #[error("Prometheus lookback_seconds must be between 1 and 86400")]
    InvalidLookback,
    #[error(
        "Prometheus step_seconds must be between 1 and 3600 and no greater than lookback_seconds"
    )]
    InvalidStep,
}

pub fn validate_prometheus_query_window(
    lookback_seconds: i64,
    step_seconds: u64,
) -> Result<(), PrometheusQueryWindowError> {
    if !(1..=86_400).contains(&lookback_seconds) {
        return Err(PrometheusQueryWindowError::InvalidLookback);
    }
    let step_exceeds_lookback = match i64::try_from(step_seconds) {
        Ok(step) => step > lookback_seconds,
        Err(_) => true,
    };
    if !(1..=3_600).contains(&step_seconds) || step_exceeds_lookback {
        return Err(PrometheusQueryWindowError::InvalidStep);
    }
    Ok(())
}
