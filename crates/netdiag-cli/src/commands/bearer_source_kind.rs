use netdiag_core::authentication::BearerSourceKind;

pub(super) fn parse(value: &str) -> anyhow::Result<BearerSourceKind> {
    match value {
        "http-json" => Ok(BearerSourceKind::HttpJson),
        "prometheus-query" => Ok(BearerSourceKind::PrometheusQuery),
        "prometheus-metrics" => Ok(BearerSourceKind::PrometheusMetrics),
        _ => anyhow::bail!(
            "bearer source kind must be http-json, prometheus-query, or prometheus-metrics"
        ),
    }
}
