use super::http_client::{ConnectorHttpClient, request_error, require_success};
use super::resource_budget::{NetworkSourceBudget, SourceDeadline};
use super::{ConnectorLoadResult, HttpJsonConfig, replace_metric_provenance};
use crate::connectors::authentication::ValidatedBearerToken;
use crate::error::Result;
use crate::ingest::build_ingest_result;
use crate::metric_quality::{apply_metric_quality_declarations, metric_quality_policy_for_schema};
use crate::reliability::redact_url;
use std::collections::BTreeMap;

mod decode;
use decode::decode_response;
mod metadata;
pub use metadata::validate_http_json_metadata;

pub fn load_http_json(
    config: &HttpJsonConfig,
    bearer_token: Option<&ValidatedBearerToken>,
) -> Result<ConnectorLoadResult> {
    const CONTEXT: &str = "HTTP/JSON source";
    let deadline = SourceDeadline::new(config.timeout, CONTEXT)?;
    let mut budget = NetworkSourceBudget::default();
    let client = ConnectorHttpClient::new(&config.endpoint, CONTEXT)?;
    let request = client
        .get(bearer_token, CONTEXT)?
        .timeout(deadline.remaining(CONTEXT)?);
    let response = request
        .send()
        .map_err(|error| request_error("HTTP/JSON request", &error))?;
    let response = require_success(response, "HTTP/JSON request")?;
    let response_bytes = budget.read_response(response, "HTTP/JSON response")?;
    deadline.ensure_remaining(CONTEXT)?;
    let decoded = decode_response(&response_bytes)?;
    drop(response_bytes);
    budget.validate_records(decoded.records.len(), CONTEXT)?;
    deadline.ensure_remaining(CONTEXT)?;
    let mut ingest = build_ingest_result(decoded.records, decoded.sample.clone())?;
    replace_metric_provenance(&mut ingest, "http_json");
    let schema = decoded
        .metadata
        .get("schema")
        .and_then(|value| value.as_str());
    let undeclared_policy = metric_quality_policy_for_schema(schema, &decoded.measurement_quality)?;
    apply_metric_quality_declarations(
        &mut ingest,
        &decoded.measurement_quality,
        "http_json",
        undeclared_policy,
    );
    let resource_usage = budget.usage(ingest.records.len());
    Ok(ConnectorLoadResult {
        ingest,
        sample: decoded.sample,
        provenance: BTreeMap::from([(
            "endpoint".to_string(),
            redact_url(client.endpoint().as_str()),
        )]),
        payload: Some(decoded.metadata),
        resource_usage,
    })
}
