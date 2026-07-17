use super::graph::shortest_path_link_indices;
use super::{redundancy_score, round2, round4, validate_topology_model};
use crate::error::{NetdiagError, Result};
use crate::models::{TopologyCalibrationReport, TopologyModel};
use crate::reliability::{StrictNamedScanLimits, scan_named_files_strict};
use crate::storage::typed_json::MAX_RUN_REPORT_BYTES;
use crate::storage::{PathStatus, path_status, read_stable_regular_file_bounded};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::path::Path;

const TELEMETRY_SUMMARY_FILE_NAME: &str = "telemetry_summary.json";
const MAX_CALIBRATION_SCAN_ENTRIES: usize = 8_192;
const MAX_CALIBRATION_SCAN_FILES: usize = 4_096;
const MAX_CALIBRATION_SUMMARIES: usize = 4_096;
const MAX_TOTAL_CALIBRATION_BYTES: u64 = 256 * 1024 * 1024;

pub fn calibrate_topology_from_runs(
    topology: &TopologyModel,
    runs_path: impl AsRef<Path>,
) -> Result<TopologyCalibrationReport> {
    validate_topology_model(topology)?;
    let runs_path = runs_path.as_ref();
    let observations = read_calibration_observations(runs_path)?;
    let source_runs = observations.count;
    let observed_path_latency_p95_ms = observations.latency.mean;
    let observed_loss_pct = observations.loss.mean;
    let observed_throughput_mbps = observations.throughput.mean;

    let mut calibrated_topology = topology.clone();
    let path_link_indices = shortest_path_link_indices(&calibrated_topology)?;
    let path_link_set = path_link_indices.iter().copied().collect::<BTreeSet<_>>();
    let path_link_count = path_link_indices.len() as f64;
    let per_link_latency = (observed_path_latency_p95_ms / path_link_count).max(0.1);
    let per_link_loss = (observed_loss_pct / path_link_count).max(0.0);
    let calibrated_capacity = checked_capacity(observed_throughput_mbps)?;
    let redundancy_score = redundancy_score(&calibrated_topology);

    for (index, link) in calibrated_topology.links.iter_mut().enumerate() {
        if !path_link_set.contains(&index) {
            link.metadata
                .insert("calibration_role".to_string(), json!("off_shortest_path"));
            continue;
        }
        link.latency_ms = round2(per_link_latency);
        link.loss_pct = round4(per_link_loss);
        link.capacity_mbps = round2(calibrated_capacity);
        link.metadata
            .insert("calibrated_from_runs".to_string(), json!(source_runs));
        link.metadata.insert(
            "observed_path_latency_p95_ms".to_string(),
            json!(round2(observed_path_latency_p95_ms)),
        );
        link.metadata.insert(
            "observed_loss_pct".to_string(),
            json!(round4(observed_loss_pct)),
        );
        link.metadata.insert(
            "observed_throughput_mbps".to_string(),
            json!(round2(observed_throughput_mbps)),
        );
    }
    calibrated_topology
        .metadata
        .insert("calibrated_at".to_string(), json!(Utc::now().to_rfc3339()));
    calibrated_topology
        .metadata
        .insert("calibrated_run_count".to_string(), json!(source_runs));
    calibrated_topology.metadata.insert(
        "redundancy_score".to_string(),
        json!(round4(redundancy_score)),
    );
    validate_topology_model(&calibrated_topology)?;

    let path_bottleneck_link_id = path_link_indices
        .iter()
        .map(|&index| &calibrated_topology.links[index])
        .min_by(|left, right| {
            left.capacity_mbps
                .total_cmp(&right.capacity_mbps)
                .then_with(|| left.id.cmp(&right.id))
        })
        .map(|link| link.id.clone())
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "topology {} has no link on its client-to-server path",
                topology.key
            ))
        })?;

    Ok(TopologyCalibrationReport {
        schema: "netdiag-topology-calibration/v1".to_string(),
        generated_at: Utc::now(),
        topology_key: calibrated_topology.key.clone(),
        source_runs,
        updated_metrics: vec![
            "link_latency_ms".to_string(),
            "loss_pct".to_string(),
            "capacity_mbps".to_string(),
            "path_bottleneck".to_string(),
            "redundancy_score".to_string(),
        ],
        observed_path_latency_p95_ms: round2(observed_path_latency_p95_ms),
        observed_loss_pct: round4(observed_loss_pct),
        observed_throughput_mbps: round2(observed_throughput_mbps),
        path_bottleneck_link_id,
        redundancy_score: round4(redundancy_score),
        warnings: vec![
            "source telemetry has no per-link attribution; observed path metrics were distributed only across the current shortest client-to-server path"
                .to_string(),
        ],
        calibrated_topology,
    })
}

fn read_calibration_observations(path: &Path) -> Result<CalibrationObservations> {
    match path_status(path)? {
        PathStatus::RegularFile => {
            if path.file_name() != Some(OsStr::new(TELEMETRY_SUMMARY_FILE_NAME)) {
                return Err(NetdiagError::InvalidTrace(format!(
                    "topology calibration file must be named {TELEMETRY_SUMMARY_FILE_NAME}: {}",
                    path.display()
                )));
            }
            let bytes =
                read_stable_regular_file_bounded(path, MAX_RUN_REPORT_BYTES)?.ok_or_else(|| {
                    NetdiagError::InvalidTrace(format!(
                        "telemetry summary disappeared while being read: {}",
                        path.display()
                    ))
                })?;
            let mut observations = CalibrationObservations::default();
            observations.observe(path, parse_observation(path, &bytes)?)?;
            Ok(observations)
        }
        PathStatus::Directory => {
            let files = scan_named_files_strict(
                path,
                OsStr::new(TELEMETRY_SUMMARY_FILE_NAME),
                StrictNamedScanLimits {
                    max_entries: MAX_CALIBRATION_SCAN_ENTRIES,
                    max_files: MAX_CALIBRATION_SCAN_FILES,
                    max_matches: MAX_CALIBRATION_SUMMARIES,
                    max_file_bytes: MAX_RUN_REPORT_BYTES,
                    max_total_file_bytes: MAX_TOTAL_CALIBRATION_BYTES,
                },
            )?;
            if files.is_empty() {
                return Err(no_summaries(path));
            }
            let mut observations = CalibrationObservations::default();
            for file in files {
                let summary_path = file.path().to_path_buf();
                let input = file.read_text()?;
                observations.observe(
                    &summary_path,
                    parse_observation(&summary_path, input.as_bytes())?,
                )?;
            }
            Ok(observations)
        }
        PathStatus::Missing => Err(NetdiagError::InvalidTrace(format!(
            "runs path does not exist: {}",
            path.display()
        ))),
        PathStatus::Other => Err(NetdiagError::InvalidTrace(format!(
            "runs path is not a regular file or directory: {}",
            path.display()
        ))),
    }
}

fn no_summaries(path: &Path) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "topology calibration found no {TELEMETRY_SUMMARY_FILE_NAME} files under {}",
        path.display()
    ))
}

#[derive(Debug, Deserialize)]
struct CalibrationSummary {
    overall: CalibrationOverall,
}

#[derive(Debug, Deserialize)]
struct CalibrationOverall {
    latency: CalibrationLatency,
    packet_loss_rate: f64,
    throughput_mbps: CalibrationThroughput,
}

#[derive(Debug, Deserialize)]
struct CalibrationLatency {
    p95: f64,
}

#[derive(Debug, Deserialize)]
struct CalibrationThroughput {
    mean: f64,
}

#[derive(Debug, Clone, Copy)]
struct CalibrationObservation {
    latency_p95_ms: f64,
    loss_pct: f64,
    throughput_mbps: f64,
}

fn parse_observation(path: &Path, input: &[u8]) -> Result<CalibrationObservation> {
    let summary: CalibrationSummary = crate::strict_json::from_slice(input).map_err(|error| {
        NetdiagError::InvalidTrace(format!(
            "invalid telemetry calibration summary at {}: {}",
            path.display(),
            crate::strict_json::error_summary(&error)
        ))
    })?;
    Ok(CalibrationObservation {
        latency_p95_ms: summary.overall.latency.p95,
        loss_pct: summary.overall.packet_loss_rate,
        throughput_mbps: summary.overall.throughput_mbps.mean,
    })
}

#[derive(Debug, Default)]
struct CalibrationObservations {
    count: usize,
    latency: OnlineMean,
    loss: OnlineMean,
    throughput: OnlineMean,
}

impl CalibrationObservations {
    fn observe(&mut self, path: &Path, observation: CalibrationObservation) -> Result<()> {
        validate_metric(path, "latency p95 ms", observation.latency_p95_ms, None)?;
        validate_metric(
            path,
            "packet loss percent",
            observation.loss_pct,
            Some(100.0),
        )?;
        validate_metric(path, "throughput Mbps", observation.throughput_mbps, None)?;
        self.count = self.count.checked_add(1).ok_or_else(|| {
            NetdiagError::InvalidTrace("telemetry summary count overflowed".to_string())
        })?;
        self.latency.add(observation.latency_p95_ms)?;
        self.loss.add(observation.loss_pct)?;
        self.throughput.add(observation.throughput_mbps)
    }
}

#[derive(Debug, Default)]
struct OnlineMean {
    count: usize,
    mean: f64,
}

impl OnlineMean {
    fn add(&mut self, value: f64) -> Result<()> {
        self.count = self.count.checked_add(1).ok_or_else(|| {
            NetdiagError::InvalidTrace("calibration metric count overflowed".to_string())
        })?;
        self.mean += (value - self.mean) / self.count as f64;
        if !self.mean.is_finite() {
            return Err(NetdiagError::InvalidTrace(
                "calibration metric aggregation overflowed".to_string(),
            ));
        }
        Ok(())
    }
}

fn validate_metric(path: &Path, name: &str, value: f64, maximum: Option<f64>) -> Result<()> {
    let valid = value.is_finite() && value >= 0.0 && maximum.is_none_or(|maximum| value <= maximum);
    if valid {
        return Ok(());
    }
    let range = maximum.map_or("non-negative".to_string(), |maximum| {
        format!("between 0 and {maximum}")
    });
    Err(NetdiagError::InvalidTrace(format!(
        "telemetry summary {name} must be finite and {range} at {}; got {value}",
        path.display()
    )))
}

fn checked_capacity(observed_throughput_mbps: f64) -> Result<f64> {
    let capacity = observed_throughput_mbps * 1.20;
    if !capacity.is_finite() {
        return Err(NetdiagError::InvalidTrace(format!(
            "calibrated capacity overflowed for observed throughput {observed_throughput_mbps} Mbps"
        )));
    }
    Ok(capacity.max(1.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_validation_rejects_all_non_finite_values() {
        let path = Path::new("telemetry_summary.json");
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let error = validate_metric(path, "latency p95 ms", value, None)
                .expect_err("non-finite metric must fail");
            assert!(error.to_string().contains("must be finite"), "{error}");
        }
    }

    #[test]
    fn capacity_calculation_rejects_finite_input_that_overflows() {
        let error = checked_capacity(1.6e308).expect_err("capacity overflow must fail");
        assert!(error.to_string().contains("capacity overflowed"), "{error}");
    }
}
