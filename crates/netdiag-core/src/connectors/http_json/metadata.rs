use crate::error::{NetdiagError, Result};
use crate::{
    MAX_CONNECTOR_FLOW_METADATA_ITEMS, MAX_CONNECTOR_METADATA_STRING_BYTES,
    MAX_CONNECTOR_METADATA_TOTAL_STRING_BYTES,
};
use serde_json::{Map, Value};

const METADATA_STRING_FIELDS: [&str; 4] = ["sample", "protocol", "schema", "collection_mode"];
const FLOW_ARRAY_FIELDS: [&str; 2] = ["flows", "top_talkers"];
const EXPERIMENT_STRING_FIELDS: [&str; 4] =
    ["scenario_id", "fault_start", "fault_end", "ground_truth"];

#[derive(Default)]
struct MetadataBudget {
    string_bytes: usize,
}

impl MetadataBudget {
    fn reserve(&mut self, bytes: usize) -> Result<()> {
        self.string_bytes = self
            .string_bytes
            .checked_add(bytes)
            .ok_or_else(|| metadata_error("aggregate metadata string byte count overflowed"))?;
        if self.string_bytes > MAX_CONNECTOR_METADATA_TOTAL_STRING_BYTES {
            return Err(metadata_error(format_args!(
                "aggregate string size exceeds the {MAX_CONNECTOR_METADATA_TOTAL_STRING_BYTES}-byte limit"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum TextContext<'a> {
    Metadata,
    Experiment,
    Flow { field: &'a str, index: usize },
}

impl std::fmt::Display for TextContext<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metadata => formatter.write_str("metadata"),
            Self::Experiment => formatter.write_str("metadata.experiment"),
            Self::Flow { field, index } => write!(formatter, "{field}[{index}]"),
        }
    }
}

/// Validates bounded HTTP/JSON metadata before it is cloned or interpreted.
pub fn validate_http_json_metadata(value: &Value) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    if object.contains_key("flows") && object.contains_key("top_talkers") {
        return Err(metadata_error(
            "flows and top_talkers cannot both be present",
        ));
    }
    let mut budget = MetadataBudget::default();
    for field in METADATA_STRING_FIELDS {
        validate_optional_text(object, field, TextContext::Metadata, &mut budget)?;
    }
    for field in FLOW_ARRAY_FIELDS {
        validate_flow_array(object, field, &mut budget)?;
    }
    validate_experiment(object, &mut budget)?;
    Ok(())
}

fn validate_flow_array(
    object: &Map<String, Value>,
    field: &str,
    budget: &mut MetadataBudget,
) -> Result<()> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    let items = value
        .as_array()
        .ok_or_else(|| metadata_error(format_args!("{field} must be an array")))?;
    if items.len() > MAX_CONNECTOR_FLOW_METADATA_ITEMS {
        return Err(metadata_error(format_args!(
            "{field} count {} exceeds the {MAX_CONNECTOR_FLOW_METADATA_ITEMS}-item limit",
            items.len()
        )));
    }
    for (index, item) in items.iter().enumerate() {
        let entry = item
            .as_object()
            .ok_or_else(|| metadata_error(format_args!("{field}[{index}] must be an object")))?;
        let context = TextContext::Flow { field, index };
        let src = validate_optional_text(entry, "src", context, budget)?;
        let dst = validate_optional_text(entry, "dst", context, budget)?;
        let label = validate_optional_text(entry, "label", context, budget)?;
        validate_optional_text(entry, "protocol", context, budget)?;
        if label.is_none() && (src.is_none() || dst.is_none()) {
            return Err(metadata_error(format_args!(
                "{context} requires a non-empty label or both src and dst"
            )));
        }
        entry.get("bytes").and_then(Value::as_u64).ok_or_else(|| {
            metadata_error(format_args!(
                "{context}.bytes must be an unsigned 64-bit integer"
            ))
        })?;
    }
    Ok(())
}

fn validate_experiment(object: &Map<String, Value>, budget: &mut MetadataBudget) -> Result<()> {
    let Some(value) = object.get("experiment") else {
        return Ok(());
    };
    let experiment = value
        .as_object()
        .ok_or_else(|| metadata_error("metadata.experiment must be an object"))?;
    for field in EXPERIMENT_STRING_FIELDS {
        if validate_optional_text(experiment, field, TextContext::Experiment, budget)?.is_none() {
            return Err(metadata_error(format_args!(
                "metadata.experiment.{field} is required"
            )));
        }
    }
    Ok(())
}

fn validate_optional_text<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    context: TextContext<'_>,
    budget: &mut MetadataBudget,
) -> Result<Option<&'a str>> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| metadata_error(format_args!("{context}.{field} must be text")))?;
    if text.len() > MAX_CONNECTOR_METADATA_STRING_BYTES {
        return Err(metadata_error(format_args!(
            "{context}.{field} exceeds the {MAX_CONNECTOR_METADATA_STRING_BYTES}-byte limit"
        )));
    }
    if text.trim().is_empty() {
        return Err(metadata_error(format_args!(
            "{context}.{field} must be non-empty text"
        )));
    }
    if text.chars().any(char::is_control) {
        return Err(metadata_error(format_args!(
            "{context}.{field} must not contain control characters"
        )));
    }
    budget.reserve(text.len())?;
    Ok(Some(text))
}

fn metadata_error(detail: impl std::fmt::Display) -> NetdiagError {
    NetdiagError::Connector(format!(
        "HTTP/JSON response metadata validation failed: {detail}"
    ))
}

#[cfg(test)]
mod tests;
