use opentelemetry_proto::tonic as otlp;
use otlp::common::v1::{AnyValue, EntityRef, KeyValue, any_value};
use otlp::metrics::v1::{Exemplar, NumberDataPoint, metric};
use tonic::Status;

const MAX_RESOURCES: usize = 32;
const MAX_SCOPES: usize = 128;
const MAX_METRICS: usize = 1_024;
const MAX_DATA_POINTS: usize = 4_096;
const MAX_ATTRIBUTES: usize = 4_096;
const MAX_NESTED_VALUES: usize = 8_192;
const MAX_AUXILIARY_ITEMS: usize = 16_384;
const MAX_ATTRIBUTE_DEPTH: usize = 8;
const MAX_FIELD_BYTES: usize = 1_024;
const MAX_TOTAL_STRING_BYTES: usize = 128 * 1024;

#[derive(Debug, Default)]
pub(super) struct RequestShapeBudget {
    resources: usize,
    scopes: usize,
    metrics: usize,
    data_points: usize,
    attributes: usize,
    nested_values: usize,
    auxiliary_items: usize,
    string_bytes: usize,
}

impl RequestShapeBudget {
    pub(super) fn reserve_resources(&mut self, count: usize) -> Result<(), Status> {
        reserve_count(&mut self.resources, count, MAX_RESOURCES, "resource")
    }

    pub(super) fn reserve_scopes(&mut self, count: usize) -> Result<(), Status> {
        reserve_count(&mut self.scopes, count, MAX_SCOPES, "scope")
    }

    pub(super) fn reserve_metrics(&mut self, count: usize) -> Result<(), Status> {
        reserve_count(&mut self.metrics, count, MAX_METRICS, "metric")
    }

    pub(super) fn reserve_data_points(&mut self, count: usize) -> Result<(), Status> {
        reserve_count(&mut self.data_points, count, MAX_DATA_POINTS, "data point")
    }

    fn reserve_auxiliary(&mut self, count: usize) -> Result<(), Status> {
        reserve_count(
            &mut self.auxiliary_items,
            count,
            MAX_AUXILIARY_ITEMS,
            "auxiliary item",
        )
    }

    pub(super) fn validate_text(&mut self, value: &str) -> Result<(), Status> {
        if value.len() > MAX_FIELD_BYTES {
            return Err(Status::invalid_argument(
                "OTLP export contains a string field above the per-field byte limit",
            ));
        }
        reserve_count(
            &mut self.string_bytes,
            value.len(),
            MAX_TOTAL_STRING_BYTES,
            "string byte",
        )
    }

    pub(super) fn validate_scope(
        &mut self,
        scope: Option<&otlp::common::v1::InstrumentationScope>,
        schema_url: &str,
    ) -> Result<(), Status> {
        self.validate_text(schema_url)?;
        if let Some(scope) = scope {
            self.validate_text(&scope.name)?;
            self.validate_text(&scope.version)?;
            self.validate_attributes(&scope.attributes)?;
        }
        Ok(())
    }

    pub(super) fn validate_entity_refs(&mut self, refs: &[EntityRef]) -> Result<(), Status> {
        self.reserve_auxiliary(refs.len())?;
        for entity in refs {
            self.validate_text(&entity.schema_url)?;
            self.validate_text(&entity.r#type)?;
            self.reserve_auxiliary(entity.id_keys.len())?;
            self.reserve_auxiliary(entity.description_keys.len())?;
            for value in entity.id_keys.iter().chain(&entity.description_keys) {
                self.validate_text(value)?;
            }
        }
        Ok(())
    }

    pub(super) fn validate_attributes(&mut self, attributes: &[KeyValue]) -> Result<(), Status> {
        reserve_count(
            &mut self.attributes,
            attributes.len(),
            MAX_ATTRIBUTES,
            "attribute",
        )?;
        for attribute in attributes {
            self.validate_text(&attribute.key)?;
            if let Some(value) = &attribute.value {
                self.validate_any_value(value, 1)?;
            }
        }
        Ok(())
    }

    pub(super) fn validate_metric_data(
        &mut self,
        data: Option<&metric::Data>,
    ) -> Result<(), Status> {
        match data {
            Some(metric::Data::Gauge(gauge)) => self.validate_number_points(&gauge.data_points),
            Some(metric::Data::Sum(sum)) => self.validate_number_points(&sum.data_points),
            Some(metric::Data::Histogram(histogram)) => {
                self.validate_histogram_points(&histogram.data_points)
            }
            Some(metric::Data::ExponentialHistogram(histogram)) => {
                self.validate_exponential_points(&histogram.data_points)
            }
            Some(metric::Data::Summary(summary)) => {
                self.validate_summary_points(&summary.data_points)
            }
            None => Ok(()),
        }
    }

    pub(super) fn validate_exemplars(&mut self, exemplars: &[Exemplar]) -> Result<(), Status> {
        self.reserve_auxiliary(exemplars.len())?;
        for exemplar in exemplars {
            self.validate_attributes(&exemplar.filtered_attributes)?;
            if exemplar.span_id.len() > MAX_FIELD_BYTES || exemplar.trace_id.len() > MAX_FIELD_BYTES
            {
                return Err(Status::invalid_argument(
                    "OTLP exemplar identifier exceeds the per-field byte limit",
                ));
            }
        }
        Ok(())
    }

    fn validate_any_value(&mut self, value: &AnyValue, depth: usize) -> Result<(), Status> {
        if depth > MAX_ATTRIBUTE_DEPTH {
            return Err(Status::invalid_argument(
                "OTLP attribute nesting exceeds the supported depth",
            ));
        }
        reserve_count(
            &mut self.nested_values,
            1,
            MAX_NESTED_VALUES,
            "nested attribute value",
        )?;
        match value.value.as_ref() {
            Some(any_value::Value::StringValue(value)) => self.validate_text(value),
            Some(any_value::Value::BytesValue(value)) if value.len() > MAX_FIELD_BYTES => Err(
                Status::invalid_argument("OTLP attribute bytes exceed the per-field byte limit"),
            ),
            Some(any_value::Value::ArrayValue(array)) => {
                self.reserve_auxiliary(array.values.len())?;
                for value in &array.values {
                    self.validate_any_value(value, depth + 1)?;
                }
                Ok(())
            }
            Some(any_value::Value::KvlistValue(list)) => {
                self.validate_attributes_at_depth(&list.values, depth + 1)
            }
            _ => Ok(()),
        }
    }

    fn validate_attributes_at_depth(
        &mut self,
        attributes: &[KeyValue],
        depth: usize,
    ) -> Result<(), Status> {
        if depth > MAX_ATTRIBUTE_DEPTH {
            return Err(Status::invalid_argument(
                "OTLP attribute nesting exceeds the supported depth",
            ));
        }
        reserve_count(
            &mut self.attributes,
            attributes.len(),
            MAX_ATTRIBUTES,
            "attribute",
        )?;
        for attribute in attributes {
            self.validate_text(&attribute.key)?;
            if let Some(value) = &attribute.value {
                self.validate_any_value(value, depth)?;
            }
        }
        Ok(())
    }

    fn validate_number_points(&mut self, points: &[NumberDataPoint]) -> Result<(), Status> {
        self.reserve_data_points(points.len())?;
        for point in points {
            self.validate_attributes(&point.attributes)?;
            self.validate_exemplars(&point.exemplars)?;
        }
        Ok(())
    }

    fn validate_histogram_points(
        &mut self,
        points: &[otlp::metrics::v1::HistogramDataPoint],
    ) -> Result<(), Status> {
        self.reserve_data_points(points.len())?;
        for point in points {
            self.validate_attributes(&point.attributes)?;
            self.validate_exemplars(&point.exemplars)?;
            self.reserve_auxiliary(point.bucket_counts.len())?;
            self.reserve_auxiliary(point.explicit_bounds.len())?;
        }
        Ok(())
    }

    fn validate_exponential_points(
        &mut self,
        points: &[otlp::metrics::v1::ExponentialHistogramDataPoint],
    ) -> Result<(), Status> {
        self.reserve_data_points(points.len())?;
        for point in points {
            self.validate_attributes(&point.attributes)?;
            self.validate_exemplars(&point.exemplars)?;
            if let Some(buckets) = &point.positive {
                self.reserve_auxiliary(buckets.bucket_counts.len())?;
            }
            if let Some(buckets) = &point.negative {
                self.reserve_auxiliary(buckets.bucket_counts.len())?;
            }
        }
        Ok(())
    }

    fn validate_summary_points(
        &mut self,
        points: &[otlp::metrics::v1::SummaryDataPoint],
    ) -> Result<(), Status> {
        self.reserve_data_points(points.len())?;
        for point in points {
            self.validate_attributes(&point.attributes)?;
            self.reserve_auxiliary(point.quantile_values.len())?;
        }
        Ok(())
    }
}

fn reserve_count(
    current: &mut usize,
    additional: usize,
    limit: usize,
    kind: &str,
) -> Result<(), Status> {
    let projected = current
        .checked_add(additional)
        .ok_or_else(|| Status::resource_exhausted("OTLP request shape accounting overflowed"))?;
    if projected > limit {
        return Err(Status::resource_exhausted(format!(
            "OTLP export exceeds the {kind} limit"
        )));
    }
    *current = projected;
    Ok(())
}
