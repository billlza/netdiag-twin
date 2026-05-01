use crate::error::{IoContext, NetdiagError, Result};
use crate::ingest::ingest_trace;
use crate::ml::{infer, load_or_train_model};
use crate::models::{PerfBudget, PerfBudgetEntry, TraceRecord};
use crate::pipeline::diagnose_file;
use crate::rules::diagnose_rules;
use crate::storage::save_json_atomic;
use crate::telemetry::summarize_telemetry;
use crate::twin::run_simulated_whatif;
use chrono::{Duration, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, Instant};

const PERF_SCHEMA_VERSION: u32 = 1;
const SAMPLE_NAMES: [&str; 6] = [
    "normal",
    "congestion",
    "random_loss",
    "dns_failure",
    "tls_failure",
    "udp_quic_blocked",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfMeasurement {
    pub name: String,
    pub elapsed_millis: f64,
    pub rows: usize,
    pub iterations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfBudgetFailure {
    pub name: String,
    pub elapsed_millis: f64,
    pub allowed_millis: f64,
    pub budget_millis: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfBudgetReport {
    pub schema_version: u32,
    pub generated_at: chrono::DateTime<Utc>,
    pub threshold_percent: f64,
    pub passed: bool,
    pub measurements: Vec<PerfMeasurement>,
    pub failures: Vec<PerfBudgetFailure>,
}

pub fn run_perf_measurements(artifact_root: impl AsRef<Path>) -> Result<Vec<PerfMeasurement>> {
    let root = artifact_root.as_ref().join("current");
    if root.exists() {
        std::fs::remove_dir_all(&root).with_path(&root)?;
    }
    std::fs::create_dir_all(&root).with_path(&root)?;

    let sample_paths = sample_paths();
    let mut measurements = Vec::new();
    measurements.push(measure(
        "ingest_six_samples",
        480,
        SAMPLE_NAMES.len(),
        || {
            for path in &sample_paths {
                black_box(ingest_trace(path)?);
            }
            Ok(())
        },
    )?);

    let records_10k = synthetic_records(10_000);
    let records_100k = synthetic_records(100_000);
    measurements.push(measure("telemetry_synthetic_100k", 100_000, 1, || {
        black_box(summarize_telemetry(&records_100k, 5)?);
        Ok(())
    })?);

    let summary_100k = summarize_telemetry(&records_100k, 5)?;
    measurements.push(measure("rules_synthetic_100k", 100_000, 1, || {
        black_box(diagnose_rules(&summary_100k, "perf"));
        Ok(())
    })?);

    let model_dir = root.join("model");
    measurements.push(measure("ml_cold_model_train", 0, 1, || {
        if model_dir.exists() {
            std::fs::remove_dir_all(&model_dir).with_path(&model_dir)?;
        }
        black_box(load_or_train_model(&model_dir)?);
        Ok(())
    })?);

    let summary_10k = summarize_telemetry(&records_10k, 5)?;
    measurements.push(measure("ml_cached_infer_20", 10_000, 20, || {
        for idx in 0..20 {
            black_box(infer(
                &summary_10k.windows,
                &format!("perf-ml-{idx}"),
                &root,
            )?);
        }
        Ok(())
    })?);

    measurements.push(measure("whatif_synthetic_100", 10_000, 100, || {
        for _ in 0..100 {
            black_box(run_simulated_whatif(
                &summary_10k.overall,
                "line",
                "reroute_path_b",
            )?);
        }
        Ok(())
    })?);

    measurements.push(measure("artifact_write_large_10k", 10_000, 1, || {
        black_box(save_json_atomic(
            root.join("large_trace.json"),
            &records_10k,
        )?);
        Ok(())
    })?);

    measurements.push(measure(
        "pipeline_six_samples_cached_model",
        480,
        SAMPLE_NAMES.len(),
        || {
            for path in &sample_paths {
                black_box(diagnose_file(
                    path,
                    &root,
                    Some(("line", "reroute_path_b")),
                )?);
            }
            Ok(())
        },
    )?);

    Ok(measurements)
}

pub fn build_perf_budget(
    measurements: &[PerfMeasurement],
    threshold_percent: f64,
    scale: f64,
) -> PerfBudget {
    let scale = scale.max(1.0);
    PerfBudget {
        schema_version: PERF_SCHEMA_VERSION,
        generated_at: Utc::now(),
        threshold_percent,
        scenarios: measurements
            .iter()
            .map(|measurement| {
                (
                    measurement.name.clone(),
                    PerfBudgetEntry {
                        max_millis: round_millis(
                            (measurement.elapsed_millis * scale)
                                .max(min_budget_millis(&measurement.name)),
                        ),
                        rows: measurement.rows,
                        iterations: measurement.iterations,
                    },
                )
            })
            .collect(),
    }
}

pub fn compare_perf_budget(
    measurements: Vec<PerfMeasurement>,
    budget: &PerfBudget,
    threshold_percent: f64,
) -> PerfBudgetReport {
    let threshold_percent = if threshold_percent.is_finite() && threshold_percent >= 0.0 {
        threshold_percent
    } else {
        budget.threshold_percent
    };
    let mut failures = Vec::new();
    for measurement in &measurements {
        let Some(entry) = budget.scenarios.get(&measurement.name) else {
            failures.push(PerfBudgetFailure {
                name: measurement.name.clone(),
                elapsed_millis: measurement.elapsed_millis,
                allowed_millis: 0.0,
                budget_millis: 0.0,
            });
            continue;
        };
        let allowed = entry.max_millis * (1.0 + threshold_percent / 100.0);
        if measurement.elapsed_millis > allowed {
            failures.push(PerfBudgetFailure {
                name: measurement.name.clone(),
                elapsed_millis: measurement.elapsed_millis,
                allowed_millis: round_millis(allowed),
                budget_millis: entry.max_millis,
            });
        }
    }
    PerfBudgetReport {
        schema_version: PERF_SCHEMA_VERSION,
        generated_at: Utc::now(),
        threshold_percent,
        passed: failures.is_empty(),
        measurements,
        failures,
    }
}

pub fn load_perf_budget(path: impl AsRef<Path>) -> Result<PerfBudget> {
    let path = path.as_ref();
    let file = std::fs::File::open(path).with_path(path)?;
    Ok(serde_json::from_reader(std::io::BufReader::new(file))?)
}

pub fn save_perf_budget(path: impl AsRef<Path>, budget: &PerfBudget) -> Result<PathBuf> {
    save_json_atomic(path, budget)
}

fn measure<T>(
    name: &str,
    rows: usize,
    iterations: usize,
    action: impl FnOnce() -> Result<T>,
) -> Result<PerfMeasurement> {
    let started = Instant::now();
    black_box(action()?);
    Ok(PerfMeasurement {
        name: name.to_string(),
        elapsed_millis: round_duration(started.elapsed()),
        rows,
        iterations,
    })
}

fn sample_paths() -> Vec<PathBuf> {
    SAMPLE_NAMES
        .iter()
        .map(|name| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../data/samples")
                .join(format!("{name}.csv"))
        })
        .collect()
}

fn synthetic_records(count: usize) -> Vec<TraceRecord> {
    let start = Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
        .single()
        .expect("fixed synthetic timestamp");
    (0..count)
        .map(|idx| {
            let phase = (idx % 120) as f64 / 120.0;
            let congested = idx % 400 >= 220;
            let latency_ms = if congested {
                165.0 + phase * 70.0
            } else {
                35.0 + phase * 20.0
            };
            TraceRecord {
                timestamp: start + Duration::milliseconds(idx as i64 * 1_000),
                latency_ms,
                jitter_ms: if congested {
                    18.0 + phase * 9.0
                } else {
                    3.0 + phase
                },
                packet_loss_rate: if congested { 1.2 + phase } else { 0.05 },
                retransmission_rate: if congested { 2.0 + phase } else { 0.1 },
                timeout_events: if congested { 1.0 } else { 0.0 },
                retry_events: if congested { 2.0 } else { 0.0 },
                throughput_mbps: if congested { 22.0 } else { 95.0 },
                dns_failure_events: 0.0,
                tls_failure_events: 0.0,
                quic_blocked_ratio: 0.0,
            }
        })
        .collect()
}

fn round_duration(duration: StdDuration) -> f64 {
    round_millis(duration.as_secs_f64() * 1_000.0)
}

fn round_millis(value: f64) -> f64 {
    if !value.is_finite() {
        return 0.0;
    }
    (value * 100.0).round() / 100.0
}

fn min_budget_millis(name: &str) -> f64 {
    match name {
        "ingest_six_samples" => 25.0,
        "telemetry_synthetic_100k" => 500.0,
        "rules_synthetic_100k" => 25.0,
        "ml_cold_model_train" => 1_000.0,
        "ml_cached_infer_20" => 50.0,
        "whatif_synthetic_100" => 25.0,
        "artifact_write_large_10k" => 250.0,
        "pipeline_six_samples_cached_model" => 2_500.0,
        _ => 100.0,
    }
}

pub fn ensure_budget_has_measurements(report: &PerfBudgetReport) -> Result<()> {
    if report.measurements.is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "performance budget produced no measurements".to_string(),
        ));
    }
    Ok(())
}
