use super::UndeclaredMetricPolicy;
use crate::error::{NetdiagError, Result};
use crate::models::MetricQuality;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

pub(crate) const ADAPTER_PAYLOAD_SCHEMA_V1: &str = "netdiag-adapter-payload/v1";
pub(crate) const ADAPTER_PAYLOAD_SCHEMA_V2: &str = "netdiag-adapter-payload/v2";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetricQualityDeclarations {
    #[serde(default)]
    latency_ms: Declared<MetricQuality>,
    #[serde(default)]
    jitter_ms: Declared<MetricQuality>,
    #[serde(default)]
    packet_loss_rate: Declared<MetricQuality>,
    #[serde(default)]
    retransmission_rate: Declared<MetricQuality>,
    #[serde(default)]
    timeout_events: Declared<MetricQuality>,
    #[serde(default)]
    retry_events: Declared<MetricQuality>,
    #[serde(default)]
    throughput_mbps: Declared<MetricQuality>,
    #[serde(default)]
    dns_failure_events: Declared<MetricQuality>,
    #[serde(default)]
    tls_failure_events: Declared<MetricQuality>,
    #[serde(default)]
    quic_blocked_ratio: Declared<MetricQuality>,
}

#[derive(Debug, Default)]
enum Declared<T> {
    #[default]
    Absent,
    Present(T),
}

impl<'de, T> Deserialize<'de> for Declared<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

impl<T: Copy> Declared<T> {
    fn value(&self) -> Option<T> {
        match self {
            Self::Absent => None,
            Self::Present(value) => Some(*value),
        }
    }
}

impl MetricQualityDeclarations {
    pub(crate) fn from_payload(payload: &Value) -> Result<Self> {
        let Some(value) = payload.get("measurement_quality") else {
            return Ok(Self::default());
        };
        Self::deserialize(value).map_err(|_| {
            NetdiagError::Connector(
                "source measurement_quality does not match the canonical metric-quality schema"
                    .to_string(),
            )
        })
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (&'static str, MetricQuality)> + '_ {
        [
            ("latency_ms", self.latency_ms.value()),
            ("jitter_ms", self.jitter_ms.value()),
            ("packet_loss_rate", self.packet_loss_rate.value()),
            ("retransmission_rate", self.retransmission_rate.value()),
            ("timeout_events", self.timeout_events.value()),
            ("retry_events", self.retry_events.value()),
            ("throughput_mbps", self.throughput_mbps.value()),
            ("dns_failure_events", self.dns_failure_events.value()),
            ("tls_failure_events", self.tls_failure_events.value()),
            ("quic_blocked_ratio", self.quic_blocked_ratio.value()),
        ]
        .into_iter()
        .filter_map(|(field, quality)| quality.map(|quality| (field, quality)))
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Object(Map::from_iter(self.entries().map(|(field, quality)| {
            (
                field.to_string(),
                Value::String(quality.as_str().to_string()),
            )
        })))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries().next().is_none()
    }

    fn is_complete(&self) -> bool {
        self.entries().count() == 10
    }
}

pub(crate) fn metric_quality_policy_for_schema(
    schema: Option<&str>,
    declarations: &MetricQualityDeclarations,
) -> Result<UndeclaredMetricPolicy> {
    match schema {
        Some(ADAPTER_PAYLOAD_SCHEMA_V2) if !declarations.is_complete() => {
            Err(NetdiagError::Connector(
                "adapter payload v2 requires measurement_quality for all canonical metrics"
                    .to_string(),
            ))
        }
        Some(ADAPTER_PAYLOAD_SCHEMA_V1 | ADAPTER_PAYLOAD_SCHEMA_V2) => {
            Ok(UndeclaredMetricPolicy::Missing)
        }
        _ => Ok(UndeclaredMetricPolicy::Preserve),
    }
}

#[cfg(test)]
mod tests;
