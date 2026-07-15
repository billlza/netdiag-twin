use anyhow::{Result, bail};
use netdiag_core::connectors::validate_http_json_metadata;
use netdiag_core::models::TraceRecord;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct FlowSummary {
    pub protocol: Option<String>,
    pub flows: Option<u64>,
    pub total_bytes: Option<u64>,
    pub top_talkers: Vec<TopTalker>,
}

#[derive(Debug, Clone)]
pub struct TopTalker {
    pub label: String,
    pub bytes: u64,
}

impl FlowSummary {
    pub(crate) fn validated_total_bytes(&self) -> Result<Option<u64>> {
        match self.total_bytes {
            Some(total_bytes) => Ok(Some(total_bytes)),
            None if self.top_talkers.is_empty() => Ok(None),
            None => bail!("flow summary contains top talkers without a validated total byte count"),
        }
    }

    /// Aggregates top-talker byte counts without allowing integer wraparound.
    pub fn checked_top_talker_bytes(top_talkers: &[TopTalker]) -> Result<Option<u64>> {
        let total_bytes = top_talkers.iter().try_fold(0_u64, |total, talker| {
            total.checked_add(talker.bytes).ok_or_else(|| {
                anyhow::anyhow!(
                    "top-talker byte count exceeds u64::MAX while aggregating flow summary"
                )
            })
        })?;
        Ok((!top_talkers.is_empty()).then_some(total_bytes))
    }
}

pub(super) fn simulated_flow_summary(total_bytes: u64) -> Result<FlowSummary> {
    let shares = [
        ("10.0.0.2 ↔ 10.0.0.3", 50_u128),
        ("10.0.0.2 ↔ 10.0.0.4", 31_u128),
        ("10.0.0.5 ↔ 10.0.0.3", 12_u128),
        ("Others", 7_u128),
    ];
    let top_talkers = shares
        .into_iter()
        .map(|(label, percent)| {
            let rounded_bytes = (u128::from(total_bytes) * percent + 50) / 100;
            Ok(TopTalker {
                label: label.to_string(),
                bytes: u64::try_from(rounded_bytes).map_err(|_| {
                    anyhow::anyhow!("simulated top-talker byte count exceeds u64::MAX")
                })?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(FlowSummary {
        protocol: Some("TCP".to_string()),
        flows: Some(4),
        total_bytes: Some(total_bytes),
        top_talkers,
    })
}

pub(super) fn parse_api_flow_summary(
    value: &Value,
    protocol: Option<String>,
) -> Result<FlowSummary> {
    validate_http_json_metadata(value)?;
    let flows = match value.get("flows").or_else(|| value.get("top_talkers")) {
        Some(flows) => flows
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| anyhow::anyhow!("validated API flows are not an array"))?,
        None => &[],
    };
    let top_talkers = flows
        .iter()
        .map(top_talker_from_api_flow)
        .collect::<Result<Vec<_>>>()?;
    let protocol = protocol.or_else(|| {
        flows.iter().find_map(|flow| {
            flow.get("protocol")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
    });
    let total_bytes = FlowSummary::checked_top_talker_bytes(&top_talkers)?;
    let flows = if flows.is_empty() {
        match value.get("flow_count") {
            Some(flow_count) => Some(flow_count.as_u64().ok_or_else(|| {
                anyhow::anyhow!("API flow_count must be an unsigned 64-bit integer")
            })?),
            None => None,
        }
    } else {
        Some(
            u64::try_from(flows.len())
                .map_err(|_| anyhow::anyhow!("API flow count exceeds u64::MAX"))?,
        )
    };
    Ok(FlowSummary {
        protocol,
        flows,
        total_bytes,
        top_talkers,
    })
}

fn top_talker_from_api_flow(flow: &Value) -> Result<TopTalker> {
    let bytes = flow
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("validated API flow bytes are missing"))?;
    let label = match flow.get("label").and_then(Value::as_str) {
        Some(label) => label.to_string(),
        None => {
            let src = flow
                .get("src")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("validated API flow source is missing"))?;
            let dst = flow
                .get("dst")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("validated API flow destination is missing"))?;
            format!("{src} ↔ {dst}")
        }
    };
    Ok(TopTalker { label, bytes })
}

/// Estimates a byte total from interval throughput without saturating numeric conversions.
pub fn estimate_bytes_from_records(records: &[TraceRecord]) -> Result<Option<u64>> {
    if records.len() < 2 {
        return Ok(None);
    }
    let mut bytes = 0.0;
    for (index, pair) in records.windows(2).enumerate() {
        let elapsed_ms = (pair[1].timestamp - pair[0].timestamp).num_milliseconds();
        if elapsed_ms < 0 {
            bail!(
                "record {} timestamp precedes the previous record",
                index + 1
            );
        }
        let throughput_mbps = pair[0].throughput_mbps;
        if !throughput_mbps.is_finite() {
            bail!("record {index} throughput_mbps is not finite");
        }
        if throughput_mbps < 0.0 {
            bail!("record {index} throughput_mbps must be non-negative");
        }
        let interval_bytes = throughput_mbps * 125.0 * elapsed_ms as f64;
        bytes += interval_bytes;
        if !bytes.is_finite() {
            bail!("estimated byte total is not finite at record {}", index + 1);
        }
    }
    let rounded_bytes = bytes.round();
    const U64_EXCLUSIVE_UPPER_BOUND: f64 = 18_446_744_073_709_551_616.0;
    if rounded_bytes >= U64_EXCLUSIVE_UPPER_BOUND {
        bail!("estimated byte total exceeds u64::MAX");
    }
    // The finite, non-negative, exclusive-upper-bound checks make this cast non-saturating.
    Ok(Some(rounded_bytes as u64))
}

#[cfg(test)]
mod tests;
