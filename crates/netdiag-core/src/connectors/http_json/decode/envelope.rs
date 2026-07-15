use super::bounded_sequence::BoundedSequence;
use crate::MAX_CONNECTOR_FLOW_METADATA_ITEMS;
use crate::metric_quality::MetricQualityDeclarations;
use crate::models::TraceRecord;
use crate::resource_limits::MAX_SOURCE_RECORDS;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

pub(super) type BoundedRecords = BoundedSequence<TraceRecord, MAX_SOURCE_RECORDS>;
type BoundedFlows = BoundedSequence<FlowMetadata, MAX_CONNECTOR_FLOW_METADATA_ITEMS>;

#[derive(Deserialize)]
pub(super) struct ResponseEnvelope {
    #[serde(default)]
    records: OptionalValue<BoundedRecords>,
    #[serde(default)]
    sample: OptionalValue<String>,
    #[serde(default)]
    protocol: OptionalValue<String>,
    #[serde(default)]
    schema: OptionalValue<String>,
    #[serde(default)]
    collection_mode: OptionalValue<String>,
    #[serde(default)]
    flow_count: OptionalValue<u64>,
    #[serde(default)]
    total_bytes: OptionalValue<u64>,
    #[serde(default)]
    bytes: OptionalValue<u64>,
    #[serde(default)]
    flows: OptionalValue<BoundedFlows>,
    #[serde(default)]
    top_talkers: OptionalValue<BoundedFlows>,
    #[serde(default)]
    experiment: OptionalValue<ExperimentMetadata>,
    #[serde(default)]
    measurement_quality: OptionalValue<MetricQualityDeclarations>,
}

#[derive(Deserialize)]
struct FlowMetadata {
    #[serde(default)]
    src: OptionalValue<String>,
    #[serde(default)]
    dst: OptionalValue<String>,
    #[serde(default)]
    label: OptionalValue<String>,
    #[serde(default)]
    bytes: OptionalValue<u64>,
    #[serde(default)]
    protocol: OptionalValue<String>,
}

#[derive(Deserialize)]
struct ExperimentMetadata {
    #[serde(default)]
    scenario_id: OptionalValue<String>,
    #[serde(default)]
    fault_start: OptionalValue<String>,
    #[serde(default)]
    fault_end: OptionalValue<String>,
    #[serde(default)]
    ground_truth: OptionalValue<String>,
}

#[derive(Default)]
enum OptionalValue<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T> Deserialize<'de> for OptionalValue<T>
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

impl<T> OptionalValue<T> {
    fn into_option(self) -> Option<T> {
        match self {
            Self::Missing => None,
            Self::Present(value) => Some(value),
        }
    }
}

impl ResponseEnvelope {
    pub(super) fn into_parts(self) -> Option<(Vec<TraceRecord>, Value, MetricQualityDeclarations)> {
        let records = self.records.into_option()?.0;
        let mut metadata = Map::new();
        insert_string(&mut metadata, "sample", self.sample.into_option());
        insert_string(&mut metadata, "protocol", self.protocol.into_option());
        insert_string(&mut metadata, "schema", self.schema.into_option());
        insert_string(
            &mut metadata,
            "collection_mode",
            self.collection_mode.into_option(),
        );
        insert_u64(&mut metadata, "flow_count", self.flow_count.into_option());
        insert_u64(&mut metadata, "total_bytes", self.total_bytes.into_option());
        insert_u64(&mut metadata, "bytes", self.bytes.into_option());
        insert_flows(&mut metadata, "flows", self.flows.into_option());
        insert_flows(&mut metadata, "top_talkers", self.top_talkers.into_option());
        if let Some(experiment) = self.experiment.into_option() {
            metadata.insert("experiment".to_string(), experiment.into_value());
        }
        let measurement_quality = self.measurement_quality.into_option().unwrap_or_default();
        if !measurement_quality.is_empty() {
            metadata.insert(
                "measurement_quality".to_string(),
                measurement_quality.to_value(),
            );
        }
        Some((records, Value::Object(metadata), measurement_quality))
    }
}

impl FlowMetadata {
    fn into_value(self) -> Value {
        let mut value = Map::new();
        insert_string(&mut value, "src", self.src.into_option());
        insert_string(&mut value, "dst", self.dst.into_option());
        insert_string(&mut value, "label", self.label.into_option());
        insert_u64(&mut value, "bytes", self.bytes.into_option());
        insert_string(&mut value, "protocol", self.protocol.into_option());
        Value::Object(value)
    }
}

impl ExperimentMetadata {
    fn into_value(self) -> Value {
        let mut value = Map::new();
        insert_string(&mut value, "scenario_id", self.scenario_id.into_option());
        insert_string(&mut value, "fault_start", self.fault_start.into_option());
        insert_string(&mut value, "fault_end", self.fault_end.into_option());
        insert_string(&mut value, "ground_truth", self.ground_truth.into_option());
        Value::Object(value)
    }
}

fn insert_flows(target: &mut Map<String, Value>, field: &str, flows: Option<BoundedFlows>) {
    if let Some(flows) = flows {
        target.insert(
            field.to_string(),
            Value::Array(flows.0.into_iter().map(FlowMetadata::into_value).collect()),
        );
    }
}

fn insert_string(target: &mut Map<String, Value>, field: &str, value: Option<String>) {
    if let Some(value) = value {
        target.insert(field.to_string(), Value::String(value));
    }
}

fn insert_u64(target: &mut Map<String, Value>, field: &str, value: Option<u64>) {
    if let Some(value) = value {
        target.insert(field.to_string(), Value::from(value));
    }
}
