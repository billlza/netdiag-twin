use super::metadata::validate_http_json_metadata;
use crate::MAX_CONNECTOR_FLOW_METADATA_ITEMS;
use crate::error::{NetdiagError, Result};
use crate::models::TraceRecord;
use crate::resource_limits::MAX_SOURCE_RECORDS;
use serde::de::IgnoredAny;
use serde_json::Value;

mod bounded_sequence;
use bounded_sequence::LIMIT_ERROR_MARKER;
mod envelope;
use crate::metric_quality::MetricQualityDeclarations;
use envelope::{BoundedRecords, ResponseEnvelope};

#[derive(Debug)]
pub(super) struct DecodedResponse {
    pub(super) records: Vec<TraceRecord>,
    pub(super) sample: String,
    pub(super) metadata: Value,
    pub(super) measurement_quality: MetricQualityDeclarations,
}

pub(super) fn decode_response(bytes: &[u8]) -> Result<DecodedResponse> {
    match bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
    {
        Some(b'[') => decode_bare_records(bytes),
        Some(b'{') => decode_envelope(bytes),
        _ => {
            serde_json::from_slice::<IgnoredAny>(bytes)
                .map_err(|error| decode_error(bytes, error))?;
            Err(response_shape_error())
        }
    }
}

fn decode_bare_records(bytes: &[u8]) -> Result<DecodedResponse> {
    let records = serde_json::from_slice::<BoundedRecords>(bytes)
        .map_err(|error| decode_error(bytes, error))?
        .0;
    Ok(DecodedResponse {
        records,
        sample: "http_json".to_string(),
        metadata: Value::Object(serde_json::Map::new()),
        measurement_quality: MetricQualityDeclarations::default(),
    })
}

fn decode_envelope(bytes: &[u8]) -> Result<DecodedResponse> {
    let envelope: ResponseEnvelope =
        serde_json::from_slice(bytes).map_err(|error| decode_error(bytes, error))?;
    let (records, metadata, measurement_quality) =
        envelope.into_parts().ok_or_else(response_shape_error)?;
    validate_http_json_metadata(&metadata)?;
    let sample = metadata
        .get("sample")
        .and_then(Value::as_str)
        .unwrap_or("http_json")
        .to_string();
    Ok(DecodedResponse {
        records,
        sample,
        metadata,
        measurement_quality,
    })
}

fn decode_error(bytes: &[u8], error: serde_json::Error) -> NetdiagError {
    let message = error.to_string();
    let record_limit_marker = format!("{LIMIT_ERROR_MARKER}:{MAX_SOURCE_RECORDS}");
    if message.starts_with(&record_limit_marker) {
        return NetdiagError::Connector(format!(
            "HTTP/JSON source resource limit failed: record count exceeds the {MAX_SOURCE_RECORDS}-record limit"
        ));
    }
    let flow_limit_marker = format!("{LIMIT_ERROR_MARKER}:{MAX_CONNECTOR_FLOW_METADATA_ITEMS}");
    if message.starts_with(&flow_limit_marker) {
        return NetdiagError::Connector(format!(
            "HTTP/JSON response metadata validation failed: flow metadata count exceeds the {MAX_CONNECTOR_FLOW_METADATA_ITEMS}-item limit"
        ));
    }
    if (error.is_syntax() || error.is_eof()) && serde_json::from_slice::<IgnoredAny>(bytes).is_err()
    {
        return NetdiagError::Connector(format!(
            "HTTP/JSON response is not valid JSON at line {}, column {}",
            error.line(),
            error.column()
        ));
    }
    NetdiagError::Connector(
        "HTTP/JSON response does not match the required response schema".to_string(),
    )
}

fn response_shape_error() -> NetdiagError {
    NetdiagError::Connector(
        "HTTP/JSON must return TraceRecord[] or { records: TraceRecord[] }".to_string(),
    )
}

#[cfg(test)]
mod tests;
