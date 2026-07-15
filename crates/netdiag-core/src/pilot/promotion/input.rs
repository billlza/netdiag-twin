use crate::benchmark::{BENCHMARK_SCHEMA, BenchmarkReport};
use crate::error::{NetdiagError, Result};
use crate::lab::LabCalibrationReport;
use crate::storage::read_stable_regular_file_bounded;
use std::path::Path;

pub(super) const MAX_BENCHMARK_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CALIBRATION_REPORT_BYTES: u64 = 16 * 1024 * 1024;

pub(super) fn read_benchmark_report(path: &Path) -> Result<BenchmarkReport> {
    let bytes = read_required(path, MAX_BENCHMARK_REPORT_BYTES, "benchmark report")?;
    let report: BenchmarkReport = crate::strict_json::from_slice(&bytes).map_err(|error| {
        NetdiagError::InvalidTrace(format!(
            "benchmark report {} is invalid JSON: {}",
            path.display(),
            crate::strict_json::error_summary(&error)
        ))
    })?;
    if report.schema != BENCHMARK_SCHEMA {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported benchmark report schema: {}; expected {BENCHMARK_SCHEMA}",
            report.schema
        )));
    }
    Ok(report)
}

pub(super) fn read_calibration_report(
    path: &Path,
) -> std::result::Result<LabCalibrationReport, String> {
    let bytes = read_required(path, MAX_CALIBRATION_REPORT_BYTES, "lab calibration report")
        .map_err(|error| error.to_string())?;
    crate::strict_json::from_slice::<LabCalibrationReport>(&bytes).map_err(|error| {
        format!(
            "lab calibration report {} is invalid JSON: {}",
            path.display(),
            crate::strict_json::error_summary(&error)
        )
    })
}

fn read_required(path: &Path, max_bytes: u64, kind: &str) -> Result<Vec<u8>> {
    read_stable_regular_file_bounded(path, max_bytes)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!("required {kind} is missing: {}", path.display()))
    })
}
