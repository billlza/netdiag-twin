use super::super::http_client::{ConnectorHttpClient, request_error, require_success};
use super::super::http_endpoint::connector_endpoint;
use super::super::prometheus_matrix::parse_prometheus_matrix_sample;
use super::super::resource_budget::{NetworkSourceBudget, SourceDeadline};
use crate::connectors::authentication::ValidatedBearerToken;
use crate::error::{NetdiagError, Result};
use serde::Deserialize;
use serde_json::Value;

const SOURCE_CONTEXT: &str = "Prometheus query_range source";

mod rows;
pub(super) use rows::complete_query_records;

pub(in crate::connectors) struct PrometheusMatrixRequest<'a> {
    pub(in crate::connectors) client: &'a ConnectorHttpClient,
    pub(in crate::connectors) bearer_token: Option<&'a ValidatedBearerToken>,
    pub(in crate::connectors) query: &'a str,
    pub(in crate::connectors) start: i64,
    pub(in crate::connectors) end: i64,
    pub(in crate::connectors) step: u64,
    pub(in crate::connectors) metric: &'a str,
}

pub(in crate::connectors) fn query_prometheus_matrix(
    request: PrometheusMatrixRequest<'_>,
    deadline: &SourceDeadline,
    budget: &mut NetworkSourceBudget,
) -> Result<Vec<(i64, f64)>> {
    let response_context = format!(
        "Prometheus query_range response for metric {}",
        request.metric
    );
    let http_request = request
        .client
        .get(request.bearer_token, SOURCE_CONTEXT)?
        .query(&[
            ("query", request.query.to_string()),
            ("start", request.start.to_string()),
            ("end", request.end.to_string()),
            ("step", request.step.to_string()),
        ])
        .timeout(deadline.remaining(SOURCE_CONTEXT)?);
    let response = http_request
        .send()
        .map_err(|error| request_error("Prometheus query_range", &error))?;
    let response = require_success(response, "Prometheus query_range")?;
    let response_bytes = budget.read_response(response, &response_context)?;
    deadline.ensure_remaining(SOURCE_CONTEXT)?;
    let series = parse_matrix_response(&response_bytes)?;
    let sample_count = series.iter().try_fold(0_usize, |total, series| {
        total.checked_add(series.values.len()).ok_or_else(|| {
            NetdiagError::Connector(format!("{response_context} sample count overflowed"))
        })
    })?;
    budget.reserve_prometheus_shape(series.len(), sample_count, &response_context)?;
    if series.len() > 1 {
        return Err(NetdiagError::Connector(
            "Prometheus query_range response is ambiguous; each canonical metric must return at most one series"
                .to_string(),
        ));
    }
    let Some(result) = series.into_iter().next() else {
        return Ok(Vec::new());
    };
    let mut values = Vec::with_capacity(sample_count);
    let mut previous_timestamp = None;
    for (sample_index, pair) in result.values.iter().enumerate() {
        let sample = parse_prometheus_matrix_sample(pair, 0, sample_index)?;
        if previous_timestamp.is_some_and(|previous| sample.0 <= previous) {
            return Err(NetdiagError::Connector(
                "Prometheus query_range timestamps must be unique and strictly increasing"
                    .to_string(),
            ));
        }
        previous_timestamp = Some(sample.0);
        values.push(sample);
    }
    deadline.ensure_remaining(SOURCE_CONTEXT)?;
    Ok(values)
}

pub(super) fn prometheus_query_endpoint(base_url: &str) -> Result<reqwest::Url> {
    let mut endpoint = connector_endpoint(base_url, SOURCE_CONTEXT)?;
    let current_path = endpoint.path().trim_end_matches('/');
    if !current_path.ends_with("/api/v1/query_range") {
        endpoint.set_path(&format!("{current_path}/api/v1/query_range"));
    }
    Ok(endpoint)
}

fn parse_matrix_response(response: &[u8]) -> Result<Vec<PrometheusSeries>> {
    let envelope: PrometheusEnvelope = serde_json::from_slice(response).map_err(json_error)?;
    match envelope.status.as_str() {
        "success" => parse_success_data(envelope.data),
        "error" => Err(error_envelope(envelope.error_type, envelope.error)),
        _ => Err(NetdiagError::Connector(
            "Prometheus query response has an unsupported status".to_string(),
        )),
    }
}

fn parse_success_data(data: Option<PrometheusData>) -> Result<Vec<PrometheusSeries>> {
    let data = data.ok_or_else(|| {
        NetdiagError::Connector(
            "Prometheus query_range success response is missing data".to_string(),
        )
    })?;
    if data.result_type != "matrix" {
        return Err(NetdiagError::Connector(
            "Prometheus query_range success response must use matrix resultType".to_string(),
        ));
    }
    Ok(data.result)
}

fn json_error(error: serde_json::Error) -> NetdiagError {
    let reason = if error.is_syntax() || error.is_eof() {
        "is not valid JSON"
    } else {
        "does not match the expected JSON schema"
    };
    NetdiagError::Connector(format!(
        "Prometheus query_range response {reason} at line {}, column {}",
        error.line(),
        error.column()
    ))
}

fn error_envelope(error_type: Option<String>, detail: Option<String>) -> NetdiagError {
    let Some(error_type) = error_type else {
        return NetdiagError::Connector(
            "Prometheus query returned error status without errorType".to_string(),
        );
    };
    if detail.is_none() {
        return NetdiagError::Connector(
            "Prometheus query returned error status without error detail".to_string(),
        );
    }
    NetdiagError::Connector(format!(
        "Prometheus query failed: {}",
        safe_prometheus_error_type(&error_type)
    ))
}

fn safe_prometheus_error_type(value: &str) -> &'static str {
    match value {
        "bad_data" => "bad_data",
        "timeout" => "timeout",
        "canceled" => "canceled",
        "execution" => "execution",
        "internal" => "internal",
        "not_found" => "not_found",
        "not_acceptable" => "not_acceptable",
        "unavailable" => "unavailable",
        _ => "unknown",
    }
}

#[derive(Debug, Deserialize)]
struct PrometheusEnvelope {
    status: String,
    data: Option<PrometheusData>,
    #[serde(rename = "errorType")]
    error_type: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PrometheusData {
    #[serde(rename = "resultType")]
    result_type: String,
    result: Vec<PrometheusSeries>,
}

#[derive(Debug, Deserialize)]
struct PrometheusSeries {
    values: Vec<Vec<Value>>,
}

#[cfg(test)]
mod tests;
