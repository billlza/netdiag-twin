use super::http_client::{ConnectorHttpClient, request_error, require_success};
use super::resource_budget::{NetworkSourceBudget, SourceDeadline};
use super::{
    ConnectorLoadResult, EVENT_METRICS, PrometheusExpositionConfig, PrometheusQueryRangeConfig,
    fallback_warning, merge_prometheus_query_mapping, merge_wire_metric_mapping,
    record_from_values, replace_metric_provenance, required_payload_metrics,
    validate_prometheus_query_window,
};
use crate::connectors::authentication::ValidatedBearerToken;
use crate::error::{NetdiagError, Result};
use crate::ingest::{CANONICAL_COLUMNS, build_ingest_result};
use crate::reliability::redact_url;
use chrono::Utc;
use std::collections::BTreeMap;

mod exposition;
mod query;
pub(super) use exposition::parse_prometheus_exposition;
pub(super) use query::{PrometheusMatrixRequest, query_prometheus_matrix};
use query::{complete_query_records, prometheus_query_endpoint};

pub fn load_prometheus_query_range(
    config: &PrometheusQueryRangeConfig,
    bearer_token: Option<&ValidatedBearerToken>,
) -> Result<ConnectorLoadResult> {
    const CONTEXT: &str = "Prometheus query_range source";
    validate_prometheus_query_window(config.lookback_seconds, config.step_seconds)
        .map_err(|error| NetdiagError::Connector(error.to_string()))?;
    let mapping = merge_prometheus_query_mapping(&config.queries)
        .map_err(|error| NetdiagError::Connector(format!("{CONTEXT} {error}")))?;
    let deadline = SourceDeadline::new(config.timeout, CONTEXT)?;
    let mut budget = NetworkSourceBudget::default();
    let endpoint = prometheus_query_endpoint(&config.base_url)?;
    let client = ConnectorHttpClient::from_endpoint(endpoint)?;
    let end = Utc::now();
    let start = end - chrono::Duration::seconds(config.lookback_seconds);
    let mut row_values: BTreeMap<i64, BTreeMap<String, f64>> = BTreeMap::new();
    let mut warnings = Vec::new();

    for metric in CANONICAL_COLUMNS {
        if metric == "timestamp" {
            continue;
        }
        let Some(query) = mapping.get(metric).filter(|query| !query.trim().is_empty()) else {
            if EVENT_METRICS.contains(&metric) {
                warnings.push(fallback_warning(
                    metric,
                    "Prometheus query is not configured",
                ));
                continue;
            }
            return Err(NetdiagError::Connector(format!(
                "Prometheus query is missing required metric {metric}"
            )));
        };
        let matrix = query_prometheus_matrix(
            PrometheusMatrixRequest {
                client: &client,
                bearer_token,
                query,
                start: start.timestamp(),
                end: end.timestamp(),
                step: config.step_seconds,
                metric,
            },
            &deadline,
            &mut budget,
        )?;
        if matrix.is_empty() {
            if EVENT_METRICS.contains(&metric) {
                warnings.push(fallback_warning(
                    metric,
                    "Prometheus query returned no data",
                ));
                continue;
            }
            return Err(NetdiagError::Connector(format!(
                "Prometheus query returned no data for required metric {metric}"
            )));
        }
        for (timestamp_ms, value) in matrix {
            if !row_values.contains_key(&timestamp_ms) {
                budget.validate_records(row_values.len() + 1, CONTEXT)?;
            }
            row_values
                .entry(timestamp_ms)
                .or_default()
                .insert(metric.to_string(), value);
        }
    }

    let records = complete_query_records(row_values, &mut warnings)?;
    budget.validate_records(records.len(), CONTEXT)?;
    deadline.ensure_remaining(CONTEXT)?;
    let mut ingest = build_ingest_result(records, config.sample.clone())?;
    ingest.warnings.extend(warnings);
    replace_metric_provenance(&mut ingest, "prometheus_query_range");
    let resource_usage = budget.usage(ingest.records.len());
    Ok(ConnectorLoadResult {
        ingest,
        sample: config.sample.clone(),
        provenance: BTreeMap::from([
            ("base_url".to_string(), redact_url(&config.base_url)),
            (
                "endpoint".to_string(),
                redact_url(client.endpoint().as_str()),
            ),
        ]),
        payload: None,
        resource_usage,
    })
}

pub fn load_prometheus_exposition(
    config: &PrometheusExpositionConfig,
    bearer_token: Option<&ValidatedBearerToken>,
) -> Result<ConnectorLoadResult> {
    const CONTEXT: &str = "Prometheus exposition source";
    let mapping = merge_wire_metric_mapping(&config.metrics)
        .map_err(|error| NetdiagError::Connector(format!("{CONTEXT} {error}")))?;
    let deadline = SourceDeadline::new(config.timeout, CONTEXT)?;
    let mut budget = NetworkSourceBudget::default();
    let client = ConnectorHttpClient::new(&config.endpoint, CONTEXT)?;
    let request = client
        .get(bearer_token, CONTEXT)?
        .timeout(deadline.remaining(CONTEXT)?);
    let response = request
        .send()
        .map_err(|error| request_error("Prometheus scrape", &error))?;
    let response = require_success(response, "Prometheus scrape")?;
    let response_bytes = budget.read_response(response, "Prometheus exposition response")?;
    deadline.ensure_remaining(CONTEXT)?;
    let body = std::str::from_utf8(&response_bytes).map_err(|err| {
        NetdiagError::Connector(format!("Prometheus scrape body is not valid UTF-8: {err}"))
    })?;
    let values = parse_prometheus_exposition(body, &mapping)?;
    let mut warnings = Vec::new();
    for metric in EVENT_METRICS {
        if !values.contains_key(metric) {
            warnings.push(fallback_warning(
                metric,
                "Prometheus exposition metric is missing",
            ));
        }
    }
    for metric in required_payload_metrics() {
        if !values.contains_key(metric) {
            return Err(NetdiagError::Connector(format!(
                "Prometheus exposition missing required metric {metric}"
            )));
        }
    }
    let record = record_from_values(Utc::now().timestamp_millis(), &values)?;
    let mut ingest = build_ingest_result(vec![record], config.sample.clone())?;
    ingest.warnings.extend(warnings);
    replace_metric_provenance(&mut ingest, "prometheus_exposition");
    budget.validate_records(ingest.records.len(), CONTEXT)?;
    deadline.ensure_remaining(CONTEXT)?;
    let resource_usage = budget.usage(ingest.records.len());
    Ok(ConnectorLoadResult {
        ingest,
        sample: config.sample.clone(),
        provenance: BTreeMap::from([(
            "endpoint".to_string(),
            redact_url(client.endpoint().as_str()),
        )]),
        payload: None,
        resource_usage,
    })
}
