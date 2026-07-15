use crate::error::{NetdiagError, Result};
use crate::feature_schema::FEATURES;
use crate::ingest::build_ingest_result;
use crate::models::{FaultLabel, TraceRecord};
use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

mod input;

pub(in crate::dataset) struct ValidatedDatasetRow {
    pub(in crate::dataset) label: FaultLabel,
    pub(in crate::dataset) payload: ValidatedDatasetPayload,
}

pub(in crate::dataset) enum ValidatedDatasetPayload {
    Records(Vec<TraceRecord>),
    Features(BTreeMap<String, f64>),
}

pub(super) fn parse_and_validate(
    path: &Path,
    line_number: usize,
    line: &str,
) -> Result<FaultLabel> {
    parse_and_validate_row(path, line_number, line).map(|row| row.label)
}

pub(in crate::dataset) fn parse_and_validate_row(
    path: &Path,
    line_number: usize,
    line: &str,
) -> Result<ValidatedDatasetRow> {
    let mut value = input::parse_unique_row(path, line_number, line)?;
    let label = row_label(path, line_number, &value)?;
    let payload = validate_payload(path, line_number, &mut value)?;
    Ok(ValidatedDatasetRow { label, payload })
}

fn row_label(path: &Path, line_number: usize, value: &serde_json::Value) -> Result<FaultLabel> {
    let label = value
        .get("label")
        .or_else(|| value.get("final_label"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            NetdiagError::Ml(format!(
                "{} line {line_number} is missing label or final_label",
                path.display()
            ))
        })?;
    FaultLabel::from_str(label).map_err(|_| {
        NetdiagError::Ml(format!(
            "{} line {line_number} has an unsupported label",
            path.display()
        ))
    })
}

fn validate_payload(
    path: &Path,
    line_number: usize,
    value: &mut serde_json::Value,
) -> Result<ValidatedDatasetPayload> {
    if let Some(records) = value
        .as_object_mut()
        .and_then(|object| object.remove("records"))
    {
        let records = serde_json::from_value::<Vec<TraceRecord>>(records).map_err(|error| {
            NetdiagError::Ml(format!(
                "{} line {line_number} records are not valid TraceRecord[]: {}",
                path.display(),
                crate::strict_json::error_summary(&error)
            ))
        })?;
        let ingest = build_ingest_result(records, format!("{}:line-{line_number}", path.display()))
            .map_err(|error| {
                NetdiagError::Ml(format!(
                    "{} line {line_number} records failed canonical validation: {error}",
                    path.display()
                ))
            })?;
        return Ok(ValidatedDatasetPayload::Records(ingest.records));
    }
    let features = value
        .get("features")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            NetdiagError::Ml(format!(
                "{} line {line_number} must include non-empty records or features",
                path.display()
            ))
        })?;
    let mut validated = BTreeMap::new();
    for feature in FEATURES {
        let value = features
            .get(feature)
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| {
                NetdiagError::Ml(format!(
                    "{} line {line_number} feature map is missing numeric {feature}",
                    path.display()
                ))
            })?;
        if !value.is_finite() {
            return Err(NetdiagError::Ml(format!(
                "{} line {line_number} feature {feature} is not finite",
                path.display()
            )));
        }
        validated.insert(feature.to_string(), value);
    }
    Ok(ValidatedDatasetPayload::Features(validated))
}
