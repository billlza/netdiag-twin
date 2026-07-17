use super::{ApiConfig, ApiSettings, PrometheusExpositionSettings, PrometheusQuerySettings};
use std::fmt;

fn redacted_endpoint(endpoint: &str) -> String {
    netdiag_core::reliability::redact_url(endpoint)
}

impl fmt::Debug for ApiSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiSettings")
            .field("endpoint", &redacted_endpoint(&self.endpoint))
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

impl fmt::Debug for PrometheusQuerySettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrometheusQuerySettings")
            .field("base_url", &redacted_endpoint(&self.base_url))
            .field("lookback_seconds", &self.lookback_seconds)
            .field("step_seconds", &self.step_seconds)
            .field("mapping_entries", &self.mapping.len())
            .finish()
    }
}

impl fmt::Debug for PrometheusExpositionSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrometheusExpositionSettings")
            .field("endpoint", &redacted_endpoint(&self.endpoint))
            .field("mapping_entries", &self.mapping.len())
            .finish()
    }
}

impl fmt::Debug for ApiConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiConfig")
            .field("endpoint", &redacted_endpoint(&self.endpoint))
            .field("timeout", &self.timeout)
            .finish()
    }
}
