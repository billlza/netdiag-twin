use crate::error::{NetdiagError, Result};
use std::collections::BTreeMap;

pub(in crate::connectors) fn parse_prometheus_exposition(
    body: &str,
    mapping: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, f64>> {
    let wanted: BTreeMap<&str, &str> = mapping
        .iter()
        .map(|(canonical, metric)| (metric.as_str(), canonical.as_str()))
        .collect();
    let mut values = BTreeMap::new();
    for raw_line in body.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name_end = line
            .find(|ch: char| ch == '{' || ch.is_whitespace())
            .unwrap_or(line.len());
        if name_end == 0 {
            continue;
        }
        let name = &line[..name_end];
        let Some(canonical) = wanted.get(name) else {
            continue;
        };
        let value_region = mapped_value_region(line, name_end)?;
        let value_text = value_region.split_whitespace().next().ok_or_else(|| {
            NetdiagError::Connector(
                "Prometheus exposition mapped metric is missing a value".to_string(),
            )
        })?;
        let value = value_text.parse::<f64>().map_err(|_| {
            NetdiagError::Connector(
                "Prometheus exposition mapped metric has an invalid value".to_string(),
            )
        })?;
        if !value.is_finite() || value < 0.0 {
            return Err(NetdiagError::Connector(
                "Prometheus exposition mapped metric must be finite and non-negative".to_string(),
            ));
        }
        if values.insert((*canonical).to_string(), value).is_some() {
            return Err(NetdiagError::Connector(
                "Prometheus exposition contains multiple series for one mapped metric".to_string(),
            ));
        }
    }
    Ok(values)
}

fn mapped_value_region(line: &str, name_end: usize) -> Result<&str> {
    if line.as_bytes().get(name_end) != Some(&b'{') {
        return Ok(line[name_end..].trim());
    }
    let label_block = &line[name_end..];
    let end = label_block_end(label_block).ok_or_else(|| {
        NetdiagError::Connector(
            "Prometheus exposition mapped metric has an unterminated label block".to_string(),
        )
    })?;
    Ok(label_block[end..].trim())
}

fn label_block_end(label_block: &str) -> Option<usize> {
    debug_assert!(label_block.starts_with('{'));
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in label_block.bytes().enumerate().skip(1) {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b'}' {
            return Some(index + 1);
        }
    }
    None
}

#[cfg(test)]
mod tests;
