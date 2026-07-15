use crate::error::{NetdiagError, Result};
use crate::resource_limits::{
    MAX_COLLECTION_TIMEOUT_SECS, MAX_SOURCE_INPUT_BYTES, MAX_SOURCE_RECORDS,
};
use reqwest::blocking::Response;
use std::io::Read;
use std::time::{Duration, Instant};

use super::ConnectorResourceUsage;

pub(super) const MAX_PROMETHEUS_SERIES_PER_RESPONSE: usize = 1_024;
pub(super) const MAX_PROMETHEUS_SAMPLES_PER_SOURCE: usize = 100_000;

#[derive(Debug, Default)]
pub(super) struct NetworkSourceBudget {
    input_bytes: u64,
    prometheus_samples: usize,
}

impl NetworkSourceBudget {
    pub(super) fn read_response(&mut self, response: Response, context: &str) -> Result<Vec<u8>> {
        let remaining = MAX_SOURCE_INPUT_BYTES
            .checked_sub(self.input_bytes)
            .ok_or_else(|| resource_error(context, "network source byte budget underflowed"))?;
        let bytes = read_bounded_response(response, remaining, context)?;
        let read = u64::try_from(bytes.len())
            .map_err(|_| resource_error(context, "response size does not fit in u64"))?;
        self.reserve_input_bytes(read, context)?;
        Ok(bytes)
    }

    pub(super) fn reserve_input_bytes(&mut self, bytes: u64, context: &str) -> Result<()> {
        let projected = self
            .input_bytes
            .checked_add(bytes)
            .ok_or_else(|| resource_error(context, "network source byte count overflowed"))?;
        if projected > MAX_SOURCE_INPUT_BYTES {
            return Err(resource_error(
                context,
                format!(
                    "cumulative input size {projected} bytes exceeds the {MAX_SOURCE_INPUT_BYTES}-byte source limit"
                ),
            ));
        }
        self.input_bytes = projected;
        Ok(())
    }

    pub(super) fn validate_records(&self, records: usize, context: &str) -> Result<()> {
        if records > MAX_SOURCE_RECORDS {
            return Err(resource_error(
                context,
                format!("record count {records} exceeds the {MAX_SOURCE_RECORDS}-record limit"),
            ));
        }
        Ok(())
    }

    pub(super) fn reserve_prometheus_shape(
        &mut self,
        series: usize,
        samples: usize,
        context: &str,
    ) -> Result<()> {
        if series > MAX_PROMETHEUS_SERIES_PER_RESPONSE {
            return Err(resource_error(
                context,
                format!(
                    "series count {series} exceeds the {MAX_PROMETHEUS_SERIES_PER_RESPONSE}-series limit"
                ),
            ));
        }
        let projected = self
            .prometheus_samples
            .checked_add(samples)
            .ok_or_else(|| resource_error(context, "Prometheus sample count overflowed"))?;
        if projected > MAX_PROMETHEUS_SAMPLES_PER_SOURCE {
            return Err(resource_error(
                context,
                format!(
                    "cumulative sample count {projected} exceeds the {MAX_PROMETHEUS_SAMPLES_PER_SOURCE}-sample source limit"
                ),
            ));
        }
        self.prometheus_samples = projected;
        Ok(())
    }

    pub(super) fn usage(&self, records: usize) -> ConnectorResourceUsage {
        ConnectorResourceUsage {
            input_bytes: self.input_bytes,
            records,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SourceDeadline {
    deadline: Instant,
}

impl SourceDeadline {
    pub(super) fn new(timeout: Duration, context: &str) -> Result<Self> {
        if timeout < Duration::from_millis(1)
            || timeout > Duration::from_secs(MAX_COLLECTION_TIMEOUT_SECS)
        {
            return Err(resource_error(
                context,
                format!(
                    "timeout must be between 1 millisecond and {MAX_COLLECTION_TIMEOUT_SECS} seconds"
                ),
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| resource_error(context, "source deadline overflowed"))?;
        Ok(Self { deadline })
    }

    pub(super) fn remaining(&self, context: &str) -> Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| resource_error(context, "source deadline exceeded"))
    }

    pub(super) fn ensure_remaining(&self, context: &str) -> Result<()> {
        self.remaining(context).map(|_| ())
    }
}

fn read_bounded_response(mut response: Response, max_bytes: u64, context: &str) -> Result<Vec<u8>> {
    if let Some(declared) = response.content_length()
        && declared > max_bytes
    {
        return Err(resource_error(
            context,
            format!(
                "declared Content-Length {declared} exceeds the remaining {max_bytes}-byte source limit"
            ),
        ));
    }
    let capacity_u64 = response
        .content_length()
        .unwrap_or_default()
        .min(max_bytes)
        .min(64 * 1024);
    let capacity = usize::try_from(capacity_u64)
        .map_err(|_| resource_error(context, "response capacity does not fit in usize"))?;
    read_bounded(&mut response, max_bytes, capacity, context)
}

fn read_bounded(
    reader: &mut impl Read,
    max_bytes: u64,
    capacity: usize,
    context: &str,
) -> Result<Vec<u8>> {
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| resource_error(context, "response read limit overflowed"))?;
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|source| {
            NetdiagError::Connector(format!("{context} body read failed: {source}"))
        })?;
    let actual_bytes = u64::try_from(bytes.len())
        .map_err(|_| resource_error(context, "response size does not fit in u64"))?;
    if actual_bytes > max_bytes {
        return Err(resource_error(
            context,
            format!("body exceeds the remaining {max_bytes}-byte source limit"),
        ));
    }
    Ok(bytes)
}

fn resource_error(context: &str, detail: impl std::fmt::Display) -> NetdiagError {
    NetdiagError::Connector(format!("{context} resource limit failed: {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn record_and_prometheus_shape_limits_are_inclusive() {
        let mut budget = NetworkSourceBudget::default();
        budget
            .validate_records(MAX_SOURCE_RECORDS, "fixture")
            .expect("exact record limit");
        budget
            .reserve_prometheus_shape(
                MAX_PROMETHEUS_SERIES_PER_RESPONSE,
                MAX_PROMETHEUS_SAMPLES_PER_SOURCE,
                "fixture",
            )
            .expect("exact Prometheus limits");

        assert!(
            budget
                .validate_records(MAX_SOURCE_RECORDS + 1, "fixture")
                .expect_err("record overflow")
                .to_string()
                .contains("record count")
        );
        assert!(
            NetworkSourceBudget::default()
                .reserve_prometheus_shape(MAX_PROMETHEUS_SERIES_PER_RESPONSE + 1, 0, "fixture",)
                .expect_err("series overflow")
                .to_string()
                .contains("series count")
        );
        assert!(
            budget
                .reserve_prometheus_shape(0, 1, "fixture")
                .expect_err("sample overflow")
                .to_string()
                .contains("cumulative sample count")
        );
    }

    #[test]
    fn cumulative_input_byte_limit_is_inclusive_and_fail_closed() {
        let mut budget = NetworkSourceBudget::default();
        budget
            .reserve_input_bytes(MAX_SOURCE_INPUT_BYTES, "fixture")
            .expect("exact byte limit");

        let error = budget
            .reserve_input_bytes(1, "fixture")
            .expect_err("one byte above the source limit must fail");
        assert!(error.to_string().contains("cumulative input size"));
        assert_eq!(budget.usage(0).input_bytes, MAX_SOURCE_INPUT_BYTES);
    }

    #[test]
    fn source_deadline_rejects_zero_and_unbounded_timeouts() {
        assert!(SourceDeadline::new(Duration::ZERO, "fixture").is_err());
        assert!(SourceDeadline::new(Duration::from_nanos(1), "fixture").is_err());
        assert!(
            SourceDeadline::new(
                Duration::from_secs(MAX_COLLECTION_TIMEOUT_SECS + 1),
                "fixture"
            )
            .is_err()
        );
    }

    #[test]
    fn bounded_reader_accepts_exact_limit_and_detects_one_extra_byte() {
        let mut exact = Cursor::new(b"1234");
        assert_eq!(
            read_bounded(&mut exact, 4, 4, "fixture").expect("exact limit"),
            b"1234"
        );

        let mut oversized = Cursor::new(b"12345");
        let error = read_bounded(&mut oversized, 4, 4, "fixture")
            .expect_err("one byte above the limit must fail");
        assert!(error.to_string().contains("body exceeds"));
    }

    #[test]
    fn source_deadline_remaining_time_decreases_from_one_shared_deadline() {
        let deadline =
            SourceDeadline::new(Duration::from_secs(1), "fixture").expect("shared source deadline");
        let first = deadline.remaining("fixture").expect("first remaining time");
        std::thread::sleep(Duration::from_millis(2));
        let second = deadline
            .remaining("fixture")
            .expect("second remaining time");

        assert!(second < first);
    }
}
