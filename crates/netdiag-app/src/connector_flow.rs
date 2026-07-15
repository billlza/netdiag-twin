use netdiag_app::data_source::{
    FlowSummary, SourceDescriptor, SourceSnapshot, TopTalker, estimate_bytes_from_records,
};
use netdiag_app::settings::ConnectorKind;
use netdiag_core::NetdiagError;
use netdiag_core::connectors::ConnectorLoadResult;
use serde_json::Value;

pub(super) fn source_snapshot_from_connector_session(
    loaded: ConnectorLoadResult,
    kind: ConnectorKind,
    captured_verb: &str,
    data_source_label: String,
) -> anyhow::Result<SourceSnapshot> {
    let rows = loaded.ingest.records.len();
    let payload = loaded.payload.unwrap_or(Value::Null);
    let (kind_label, protocol) = match kind {
        ConnectorKind::OtlpGrpcReceiver => ("OTLP gRPC Session", "OTLP"),
        ConnectorKind::NativePcap => ("Native pcap Session", "PCAP"),
        ConnectorKind::SystemCounters => ("System counters Session", "Interface"),
        _ => ("Capture Session", "Capture"),
    };
    let mut flow_summary = connector_payload_flow_summary(&payload, protocol, rows)?;
    if flow_summary.total_bytes.is_none() {
        flow_summary.total_bytes = estimate_bytes_from_records(&loaded.ingest.records)?;
    }
    Ok(SourceSnapshot {
        descriptor: SourceDescriptor {
            name: loaded.sample,
            kind: kind_label.to_string(),
            captured_label: format!("{captured_verb}  •  {}", chrono::Utc::now().format("%H:%M")),
            data_source_label,
        },
        flow_summary,
        ingest: loaded.ingest,
    })
}

pub(super) enum CaptureSessionCompletion {
    Completed(Box<SourceSnapshot>),
    Cancelled,
    Failed(anyhow::Error),
}

pub(super) fn capture_session_completion(
    result: netdiag_core::Result<ConnectorLoadResult>,
    kind: ConnectorKind,
    captured_verb: &str,
    source_label: String,
) -> CaptureSessionCompletion {
    match result {
        Ok(loaded) => {
            source_snapshot_from_connector_session(loaded, kind, captured_verb, source_label)
                .map(Box::new)
                .map(CaptureSessionCompletion::Completed)
                .unwrap_or_else(CaptureSessionCompletion::Failed)
        }
        Err(NetdiagError::CaptureCancelled { .. }) => CaptureSessionCompletion::Cancelled,
        Err(error) => CaptureSessionCompletion::Failed(error.into()),
    }
}

pub(super) fn connector_payload_flow_summary(
    payload: &Value,
    protocol: &str,
    rows: usize,
) -> anyhow::Result<FlowSummary> {
    let top_talkers = parse_top_talkers(payload)?;
    let inferred_total_bytes = FlowSummary::checked_top_talker_bytes(&top_talkers)?;
    let total_bytes = validated_total_bytes(payload, inferred_total_bytes)?;
    let flows = validated_flow_count(payload, rows, top_talkers.len())?;
    Ok(FlowSummary {
        protocol: Some(protocol.to_string()),
        flows,
        total_bytes,
        top_talkers,
    })
}

fn parse_top_talkers(payload: &Value) -> anyhow::Result<Vec<TopTalker>> {
    let Some(value) = payload.get("top_talkers") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("connector top_talkers must be an array"))?;
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let label = item
                .get("label")
                .and_then(Value::as_str)
                .filter(|label| !label.trim().is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("connector top_talkers[{index}].label must be non-empty text")
                })?;
            let bytes = item.get("bytes").and_then(Value::as_u64).ok_or_else(|| {
                anyhow::anyhow!(
                    "connector top_talkers[{index}].bytes must be an unsigned 64-bit integer"
                )
            })?;
            Ok(TopTalker {
                label: label.to_string(),
                bytes,
            })
        })
        .collect()
}

fn optional_u64(payload: &Value, key: &str) -> anyhow::Result<Option<u64>> {
    payload
        .get(key)
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                anyhow::anyhow!("connector {key} must be an unsigned 64-bit integer")
            })
        })
        .transpose()
}

fn validated_total_bytes(payload: &Value, inferred: Option<u64>) -> anyhow::Result<Option<u64>> {
    let total = optional_u64(payload, "total_bytes")?;
    let legacy = optional_u64(payload, "bytes")?;
    if let (Some(total), Some(legacy)) = (total, legacy)
        && total != legacy
    {
        anyhow::bail!("connector total_bytes and bytes fields disagree");
    }
    let declared = total.or(legacy);
    if let (Some(declared), Some(inferred)) = (declared, inferred)
        && declared < inferred
    {
        anyhow::bail!(
            "connector total_bytes {declared} is smaller than top-talker bytes {inferred}"
        );
    }
    Ok(declared.or(inferred))
}

fn validated_flow_count(
    payload: &Value,
    rows: usize,
    top_talker_count: usize,
) -> anyhow::Result<Option<u64>> {
    let listed = u64::try_from(top_talker_count)
        .map_err(|_| anyhow::anyhow!("connector top-talker count exceeds u64::MAX"))?;
    let declared = optional_u64(payload, "flow_count")?;
    if let Some(declared) = declared {
        if declared < listed {
            anyhow::bail!(
                "connector flow_count {declared} is smaller than {listed} listed top talkers"
            );
        }
        return Ok(Some(declared));
    }
    if top_talker_count > 0 {
        Ok(Some(listed))
    } else {
        Ok(Some(u64::try_from(rows).map_err(|_| {
            anyhow::anyhow!("connector row count exceeds u64::MAX")
        })?))
    }
}
