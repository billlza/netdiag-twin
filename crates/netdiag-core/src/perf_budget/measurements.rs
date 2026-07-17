use super::{PerfMeasurement, round_millis};
use crate::error::Result;
use crate::evidence_bundle::export_evidence_bundle;
use crate::ingest::ingest_trace;
use crate::ml::{
    infer_with_quality_from_model_bundle_snapshot, load_existing_model_bundle_snapshot,
    load_or_train_model,
};
use crate::models::{TelemetryWindow, TraceRecord};
use crate::pipeline::{
    WhatIfRequest, diagnose_ingest_with_nested_artifact_root_and_model_snapshot,
};
use crate::rules::diagnose_rules;
use crate::storage::StagedAtomicDirectory;
use crate::telemetry::summarize_telemetry;
use crate::twin::run_simulated_whatif;
use chrono::{Duration, TimeZone, Utc};
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::time::{Duration as StdDuration, Instant};

const SAMPLE_NAMES: [&str; 6] = [
    "normal",
    "congestion",
    "random_loss",
    "dns_failure",
    "tls_failure",
    "udp_quic_blocked",
];

pub(super) fn run(workspace: &mut StagedAtomicDirectory) -> Result<Vec<PerfMeasurement>> {
    let root = workspace.staging_path().to_path_buf();
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
        black_box(load_or_train_model(&model_dir)?);
        Ok(())
    })?);
    let summary_10k = summarize_telemetry(&records_10k, 5)?;
    measurements.extend(measure_model_inference(&model_dir, &summary_10k.windows)?);
    let model_snapshot = load_existing_model_bundle_snapshot(&model_dir)?;

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
        black_box(workspace.save_json("large_trace.json", &records_10k)?);
        Ok(())
    })?);

    measurements.push(measure(
        "pipeline_six_samples_cached_model",
        480,
        SAMPLE_NAMES.len(),
        || {
            for path in &sample_paths {
                black_box(
                    diagnose_ingest_with_nested_artifact_root_and_model_snapshot(
                        ingest_trace(path)?,
                        workspace,
                        &model_snapshot,
                        Some(WhatIfRequest::built_in("line", "reroute_path_b")?),
                    )?,
                );
            }
            Ok(())
        },
    )?);
    let evidence_pipeline = diagnose_ingest_with_nested_artifact_root_and_model_snapshot(
        ingest_trace(&sample_paths[0])?,
        workspace,
        &model_snapshot,
        None,
    )?;
    measurements.push(measure(
        "evidence_bundle_export_cached_run",
        480,
        1,
        || {
            black_box(export_evidence_bundle(
                &root,
                &evidence_pipeline.run_id,
                root.join("perf-evidence.zip"),
                &[],
            )?);
            Ok(())
        },
    )?);
    Ok(measurements)
}

fn measure_model_inference(
    model_dir: &Path,
    windows: &[TelemetryWindow],
) -> Result<[PerfMeasurement; 2]> {
    let secure_load = measure("ml_secure_bundle_load", 0, 1, || {
        black_box(load_existing_model_bundle_snapshot(model_dir)?);
        Ok(())
    })?;
    let model_snapshot = load_existing_model_bundle_snapshot(model_dir)?;
    let cached_inference = measure("ml_cached_infer_20", 10_000, 20, || {
        for idx in 0..20 {
            black_box(infer_with_quality_from_model_bundle_snapshot(
                windows,
                &format!("perf-ml-{idx}"),
                &model_snapshot,
                &[],
            )?);
        }
        Ok(())
    })?;
    Ok([secure_load, cached_inference])
}

fn measure<T>(
    name: &str,
    rows: usize,
    iterations: usize,
    action: impl FnOnce() -> Result<T>,
) -> Result<PerfMeasurement> {
    let started = Instant::now();
    black_box(action()?);
    let elapsed_millis = round_duration(started.elapsed());
    Ok(PerfMeasurement {
        name: name.to_string(),
        elapsed_millis,
        min_millis: elapsed_millis,
        max_millis: elapsed_millis,
        sample_millis: vec![elapsed_millis],
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
    (0..count).map(|idx| synthetic_record(start, idx)).collect()
}

fn synthetic_record(start: chrono::DateTime<Utc>, idx: usize) -> TraceRecord {
    let phase = (idx % 120) as f64 / 120.0;
    let congested = idx % 400 >= 220;
    TraceRecord {
        timestamp: start + Duration::milliseconds(idx as i64 * 1_000),
        latency_ms: if congested {
            165.0 + phase * 70.0
        } else {
            35.0 + phase * 20.0
        },
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
}

fn round_duration(duration: StdDuration) -> f64 {
    round_millis(duration.as_secs_f64() * 1_000.0)
}
