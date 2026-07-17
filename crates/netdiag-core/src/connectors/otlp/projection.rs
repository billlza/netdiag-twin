use super::OtlpMetricFrame;
use crate::error::{NetdiagError, Result as CoreResult};
use budget::RequestShapeBudget;
use chrono::Utc;
use numeric::validate_mapped_metric_data;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::metrics::v1::Metric;
use prost::Message;
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use tonic::Status;

mod budget;
mod numeric;

pub(super) const MAX_DECODING_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_MAPPING_ENTRIES: usize = 256;
const MAX_MAPPING_STRING_BYTES: usize = 256;

#[derive(Debug)]
pub(super) struct OtlpProjectionSchema {
    wire_to_index: BTreeMap<String, usize>,
    canonical_names: Box<[String]>,
    required_indices: Box<[usize]>,
}

#[derive(Debug, PartialEq)]
struct MappedObservationContext {
    resource_index: usize,
    scope_index: usize,
    attributes: Box<[KeyValue]>,
}

struct ProjectionState {
    budget: RequestShapeBudget,
    values: Vec<f64>,
    seen_metrics: Vec<bool>,
    selected_time_nanos: Option<u64>,
    selected_context: Option<MappedObservationContext>,
}

impl ProjectionState {
    fn new(metric_count: usize) -> Self {
        Self {
            budget: RequestShapeBudget::default(),
            values: vec![f64::NAN; metric_count],
            seen_metrics: vec![false; metric_count],
            selected_time_nanos: None,
            selected_context: None,
        }
    }
}

impl OtlpProjectionSchema {
    pub(super) fn new(mapping: BTreeMap<String, String>) -> CoreResult<Self> {
        if mapping.is_empty() || mapping.len() > MAX_MAPPING_ENTRIES {
            return Err(NetdiagError::Connector(format!(
                "OTLP metric mapping must contain 1..={MAX_MAPPING_ENTRIES} entries"
            )));
        }
        let mut canonical_names = Vec::with_capacity(mapping.len());
        let mut wire_to_index = BTreeMap::new();
        for (canonical, wire_name) in mapping {
            validate_mapping_string("canonical name", &canonical)?;
            validate_mapping_string("wire name", &wire_name)?;
            let index = canonical_names.len();
            match wire_to_index.entry(wire_name) {
                Entry::Vacant(entry) => {
                    canonical_names.push(canonical);
                    entry.insert(index);
                }
                Entry::Occupied(_) => {
                    return Err(NetdiagError::Connector(
                        "OTLP metric mapping wire names must be unique".to_string(),
                    ));
                }
            }
        }
        let required_indices = super::super::required_payload_metrics()
            .into_iter()
            .map(|required| {
                canonical_names
                    .iter()
                    .position(|canonical| canonical == required)
                    .ok_or_else(|| {
                        NetdiagError::Connector(
                            "OTLP metric mapping is missing a required canonical field".to_string(),
                        )
                    })
            })
            .collect::<CoreResult<Box<[usize]>>>()?;
        Ok(Self {
            wire_to_index,
            canonical_names: canonical_names.into_boxed_slice(),
            required_indices,
        })
    }

    pub(super) fn project(
        &self,
        request: &ExportMetricsServiceRequest,
    ) -> Result<OtlpMetricFrame, Status> {
        let encoded_bytes = request.encoded_len();
        if encoded_bytes > MAX_DECODING_MESSAGE_BYTES {
            return Err(Status::resource_exhausted(
                "OTLP export exceeds the decoded message byte limit",
            ));
        }
        let received_at = Utc::now();
        let mut state = ProjectionState::new(self.canonical_names.len());
        self.project_resources(request, &mut state)?;
        let selected_time_nanos = state.selected_time_nanos.ok_or_else(|| {
            Status::invalid_argument("OTLP export does not contain a mapped metric timestamp")
        })?;
        let timestamp_ms = if selected_time_nanos == 0 {
            received_at.timestamp_millis()
        } else {
            i64::try_from(selected_time_nanos / 1_000_000)
                .map_err(|_| Status::invalid_argument("OTLP metric timestamp is out of range"))?
        };
        Ok(OtlpMetricFrame {
            received_at,
            timestamp_ms,
            input_bytes: u64::try_from(encoded_bytes).map_err(|_| {
                Status::resource_exhausted("OTLP export byte count does not fit in u64")
            })?,
            values: state.values.into_boxed_slice(),
        })
    }

    pub(super) fn validate_complete(&self, frame: &OtlpMetricFrame) -> Result<(), Status> {
        if self
            .required_indices
            .iter()
            .any(|index| frame.values[*index].is_nan())
        {
            return Err(Status::invalid_argument(
                "OTLP export is missing one or more required mapped metrics",
            ));
        }
        Ok(())
    }

    pub(super) fn values<'a>(
        &'a self,
        frame: &'a OtlpMetricFrame,
    ) -> impl Iterator<Item = (&'a str, f64)> + 'a {
        self.canonical_names
            .iter()
            .zip(frame.values.iter().copied())
            .filter(|(_, value)| !value.is_nan())
            .map(|(name, value)| (name.as_str(), value))
    }

    pub(super) fn len(&self) -> usize {
        self.canonical_names.len()
    }

    fn project_resources(
        &self,
        request: &ExportMetricsServiceRequest,
        state: &mut ProjectionState,
    ) -> Result<(), Status> {
        state
            .budget
            .reserve_resources(request.resource_metrics.len())?;
        for (resource_index, resource_metrics) in request.resource_metrics.iter().enumerate() {
            state.budget.validate_text(&resource_metrics.schema_url)?;
            if let Some(resource) = &resource_metrics.resource {
                state.budget.validate_attributes(&resource.attributes)?;
                state.budget.validate_entity_refs(&resource.entity_refs)?;
            }
            state
                .budget
                .reserve_scopes(resource_metrics.scope_metrics.len())?;
            for (scope_index, scope_metrics) in resource_metrics.scope_metrics.iter().enumerate() {
                state
                    .budget
                    .validate_scope(scope_metrics.scope.as_ref(), &scope_metrics.schema_url)?;
                state.budget.reserve_metrics(scope_metrics.metrics.len())?;
                for metric in &scope_metrics.metrics {
                    self.project_metric(metric, resource_index, scope_index, state)?;
                }
            }
        }
        Ok(())
    }

    fn project_metric(
        &self,
        metric: &Metric,
        resource_index: usize,
        scope_index: usize,
        state: &mut ProjectionState,
    ) -> Result<(), Status> {
        state.budget.validate_text(&metric.name)?;
        state.budget.validate_text(&metric.description)?;
        state.budget.validate_text(&metric.unit)?;
        state.budget.validate_attributes(&metric.metadata)?;
        let Some(index) = self.wire_to_index.get(metric.name.as_str()).copied() else {
            state.budget.validate_metric_data(metric.data.as_ref())?;
            return Ok(());
        };
        if state.seen_metrics[index] {
            return Err(Status::invalid_argument(
                "OTLP export contains multiple metrics for one mapped field",
            ));
        }
        let projected = validate_mapped_metric_data(&mut state.budget, metric.data.as_ref())?;
        if state
            .selected_time_nanos
            .is_some_and(|selected| selected != projected.timestamp)
        {
            return Err(Status::invalid_argument(
                "mapped OTLP metrics must resolve to one consistent observation timestamp",
            ));
        }
        let context = MappedObservationContext {
            resource_index,
            scope_index,
            attributes: projected.attributes,
        };
        if state
            .selected_context
            .as_ref()
            .is_some_and(|selected| selected != &context)
        {
            return Err(Status::invalid_argument(
                "mapped OTLP metrics must belong to one observation context",
            ));
        }
        state.seen_metrics[index] = true;
        state.values[index] = projected.value;
        state.selected_time_nanos = Some(projected.timestamp);
        state.selected_context = Some(context);
        Ok(())
    }
}

fn validate_mapping_string(kind: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() || value.len() > MAX_MAPPING_STRING_BYTES {
        return Err(NetdiagError::Connector(format!(
            "OTLP metric mapping {kind} must contain 1..={MAX_MAPPING_STRING_BYTES} bytes"
        )));
    }
    Ok(())
}
