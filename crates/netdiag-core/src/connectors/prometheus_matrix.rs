use crate::error::{NetdiagError, Result};
use serde_json::Value;

pub(super) fn parse_prometheus_matrix_sample(
    pair: &[Value],
    series_index: usize,
    sample_index: usize,
) -> Result<(i64, f64)> {
    let context = || format!("Prometheus matrix series {series_index} sample {sample_index}");
    if pair.len() != 2 {
        return Err(NetdiagError::Connector(format!(
            "{} must contain exactly timestamp and value",
            context()
        )));
    }
    let timestamp = pair[0].as_f64().ok_or_else(|| {
        NetdiagError::Connector(format!("{} timestamp must be numeric", context()))
    })?;
    let timestamp_ms = timestamp * 1000.0;
    if !timestamp_ms.is_finite() || timestamp_ms < i64::MIN as f64 || timestamp_ms > i64::MAX as f64
    {
        return Err(NetdiagError::Connector(format!(
            "{} timestamp is outside the supported range",
            context()
        )));
    }
    let value_text = pair[1]
        .as_str()
        .ok_or_else(|| NetdiagError::Connector(format!("{} value must be a string", context())))?;
    let value = value_text.parse::<f64>().map_err(|error| {
        NetdiagError::Connector(format!("{} value is invalid: {error}", context()))
    })?;
    if !value.is_finite() || value < 0.0 {
        return Err(NetdiagError::Connector(format!(
            "{} value must be finite and non-negative",
            context()
        )));
    }
    Ok((timestamp_ms.round() as i64, value))
}
