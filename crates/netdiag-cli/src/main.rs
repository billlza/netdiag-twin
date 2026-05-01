use anyhow::Context;
use clap::{Parser, Subcommand};
use netdiag_core::connectors::{
    HttpJsonConfig, NativePcapConfig, NativePcapSource, OtlpGrpcReceiverConfig,
    PrometheusExpositionConfig, PrometheusQueryRangeConfig, SystemCountersConfig,
    default_prometheus_mapping, load_http_json, load_native_pcap, load_otlp_grpc_receiver,
    load_prometheus_exposition, load_prometheus_query_range, load_system_counters,
};
use netdiag_core::ml::{export_feedback_training_dataset, train_model_from_jsonl_with_validation};
use netdiag_core::models::{FaultLabel, HilState, TelemetrySummary};
use netdiag_core::perf_budget::{
    build_perf_budget, compare_perf_budget, ensure_budget_has_measurements, load_perf_budget,
    run_perf_measurements_sampled, save_perf_budget,
};
use netdiag_core::storage::{read_json, review_recommendation, run_dir, save_json};
use netdiag_core::twin::run_simulated_whatif;
use netdiag_core::{Result as CoreResult, diagnose_file};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(name = "netdiag")]
#[command(about = "NetDiag Twin Rust-native diagnostics CLI")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Diagnose {
        file: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Whatif {
        run_id: String,
        topology: String,
        action: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Export {
        run_id: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Train {
        #[arg(long)]
        dataset: PathBuf,
        #[arg(long)]
        model_dir: PathBuf,
        #[arg(long, default_value_t = 0.0)]
        validation_split: f64,
    },
    Feedback {
        #[command(subcommand)]
        command: FeedbackCommand,
    },
    Review {
        run_id: String,
        recommendation_id: String,
        #[arg(long)]
        state: String,
        #[arg(long, default_value = "")]
        notes: String,
        #[arg(long, default_value = "cli")]
        reviewer: String,
        #[arg(long)]
        final_label: Option<String>,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Collect {
        #[arg(
            long,
            value_parser = [
                "http-json",
                "prometheus-query",
                "prometheus-metrics",
                "otlp-grpc",
                "native-pcap",
                "system-counters"
            ]
        )]
        kind: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value_t = 8)]
        timeout_secs: u64,
        #[arg(long, default_value_t = 300)]
        lookback_secs: i64,
        #[arg(long, default_value_t = 15)]
        step_secs: u64,
        #[arg(long, default_value_t = 256)]
        packet_limit: usize,
        #[arg(long, default_value_t = 1)]
        interval_secs: u64,
        #[arg(long)]
        mapping: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        diagnose: bool,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    PerfBudget {
        #[arg(long, default_value = "perf-baseline.json")]
        baseline: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "target/perf-artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = 15.0)]
        threshold_percent: f64,
        #[arg(long, default_value_t = false)]
        update_baseline: bool,
        #[arg(long, default_value_t = 3.0)]
        baseline_scale: f64,
        #[arg(long, default_value_t = 1)]
        samples: usize,
    },
}

#[derive(Debug, Subcommand)]
enum FeedbackCommand {
    Export {
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    run(Args::parse())
}

fn run(args: Args) -> anyhow::Result<()> {
    match args.command {
        Command::Diagnose { file, artifacts } => {
            let result = diagnose_file(file, artifacts, Some(("line", "reroute_path_b")))
                .context("diagnosis failed")?;
            println!("{}", serde_json::to_string_pretty(&result.report)?);
        }
        Command::Whatif {
            run_id,
            topology,
            action,
            artifacts,
        } => run_whatif(&run_id, &topology, &action, artifacts).context("what-if failed")?,
        Command::Export { run_id, artifacts } => {
            let path = run_dir(artifacts, &run_id).join("report.json");
            let report = read_json(path)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Train {
            dataset,
            model_dir,
            validation_split,
        } => {
            let manifest =
                train_model_from_jsonl_with_validation(&dataset, &model_dir, validation_split)
                    .with_context(|| format!("training failed for {}", dataset.display()))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "trained",
                    "dataset": dataset,
                    "model_dir": model_dir,
                    "model_file": manifest.model_file,
                    "manifest_file": "model_manifest.json",
                    "labels": manifest.labels,
                    "training_examples": manifest.training_examples,
                    "evaluation": manifest.evaluation,
                }))?
            );
        }
        Command::Feedback { command } => match command {
            FeedbackCommand::Export { artifacts, output } => {
                let summary = export_feedback_training_dataset(&artifacts, &output)
                    .context("feedback export failed")?;
                println!("{}", serde_json::to_string_pretty(&summary)?);
            }
        },
        Command::Review {
            run_id,
            recommendation_id,
            state,
            notes,
            reviewer,
            final_label,
            artifacts,
        } => {
            let state = HilState::from_str(&state)
                .map_err(|_| anyhow::anyhow!("invalid HIL state: {state}"))?;
            let final_label = final_label
                .as_deref()
                .map(FaultLabel::from_str)
                .transpose()
                .map_err(|_| anyhow::anyhow!("invalid final label"))?;
            let outcome = review_recommendation(
                artifacts,
                &run_id,
                &recommendation_id,
                state,
                &notes,
                &reviewer,
                final_label,
            )
            .context("review failed")?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "run_id": run_id,
                    "recommendation_id": recommendation_id,
                    "state": outcome.review.state,
                    "reviewer": outcome.review.reviewer,
                    "reviewed_at": outcome.review.reviewed_at,
                    "final_label": outcome.review.final_label,
                    "status": outcome.status,
                }))?
            );
        }
        Command::Collect {
            kind,
            endpoint,
            timeout_secs,
            lookback_secs,
            step_secs,
            packet_limit,
            interval_secs,
            mapping,
            diagnose,
            artifacts,
        } => {
            let mapping = load_mapping(mapping)?;
            let token = std::env::var("NETDIAG_API_TOKEN").ok();
            let loaded = match kind.as_str() {
                "http-json" => load_http_json(&HttpJsonConfig {
                    endpoint,
                    bearer_token: token,
                    timeout: Duration::from_secs(timeout_secs),
                })?,
                "prometheus-query" => load_prometheus_query_range(&PrometheusQueryRangeConfig {
                    base_url: endpoint,
                    bearer_token: token,
                    timeout: Duration::from_secs(timeout_secs),
                    lookback_seconds: lookback_secs,
                    step_seconds: step_secs,
                    queries: mapping,
                    sample: "cli_prometheus_query".to_string(),
                })?,
                "prometheus-metrics" => load_prometheus_exposition(&PrometheusExpositionConfig {
                    endpoint,
                    bearer_token: token,
                    timeout: Duration::from_secs(timeout_secs),
                    metrics: mapping,
                    sample: "cli_prometheus_metrics".to_string(),
                })?,
                "otlp-grpc" => load_otlp_grpc_receiver(&OtlpGrpcReceiverConfig {
                    bind_addr: endpoint,
                    timeout: Duration::from_secs(timeout_secs),
                    metrics: mapping,
                    sample: "cli_otlp_grpc".to_string(),
                })?,
                "native-pcap" => load_native_pcap(&NativePcapConfig {
                    source: native_pcap_source(&endpoint),
                    timeout: Duration::from_secs(timeout_secs),
                    packet_limit,
                    sample: "cli_native_pcap".to_string(),
                })?,
                "system-counters" => load_system_counters(&SystemCountersConfig {
                    interface: (!endpoint.trim().is_empty() && endpoint.trim() != "all")
                        .then(|| endpoint.trim().to_string()),
                    interval: Duration::from_secs(interval_secs.clamp(1, 10)),
                    sample: "cli_system_counters".to_string(),
                })?,
                _ => unreachable!("clap restricts connector kind"),
            };
            if diagnose {
                let result = netdiag_core::diagnose_ingest(
                    loaded.ingest,
                    artifacts,
                    Some(("line", "reroute_path_b")),
                )?;
                println!("{}", serde_json::to_string_pretty(&result.report)?);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "sample": loaded.sample,
                        "rows": loaded.ingest.records.len(),
                        "warnings": loaded.ingest.warnings,
                        "provenance": loaded.provenance,
                    }))?
                );
            }
        }
        Command::PerfBudget {
            baseline,
            output,
            artifacts,
            threshold_percent,
            update_baseline,
            baseline_scale,
            samples,
        } => {
            let measurements = run_perf_measurements_sampled(&artifacts, samples)
                .with_context(|| format!("performance run failed in {}", artifacts.display()))?;
            if update_baseline {
                let budget = build_perf_budget(&measurements, threshold_percent, baseline_scale);
                save_perf_budget(&baseline, &budget).with_context(|| {
                    format!(
                        "failed to write performance baseline {}",
                        baseline.display()
                    )
                })?;
                let report = compare_perf_budget(measurements, &budget, threshold_percent);
                ensure_budget_has_measurements(&report)?;
                if let Some(output) = output {
                    save_json(&output, &report).with_context(|| {
                        format!("failed to write performance report {}", output.display())
                    })?;
                }
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                let budget = load_perf_budget(&baseline).with_context(|| {
                    format!("failed to read performance baseline {}", baseline.display())
                })?;
                let report = compare_perf_budget(measurements, &budget, threshold_percent);
                ensure_budget_has_measurements(&report)?;
                if let Some(output) = output {
                    save_json(&output, &report).with_context(|| {
                        format!("failed to write performance report {}", output.display())
                    })?;
                }
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.passed {
                    anyhow::bail!(
                        "performance budget failed for {} scenario(s)",
                        report.failures.len()
                    );
                }
            }
        }
    }
    Ok(())
}

fn native_pcap_source(endpoint: &str) -> NativePcapSource {
    let trimmed = endpoint.trim();
    if let Some(interface) = trimmed.strip_prefix("iface:") {
        return NativePcapSource::Interface(interface.trim().to_string());
    }
    let path = PathBuf::from(trimmed);
    if path.is_file() {
        NativePcapSource::File(path)
    } else {
        NativePcapSource::Interface(trimmed.to_string())
    }
}

fn run_whatif(
    run_id: &str,
    topology: &str,
    action: &str,
    artifacts: PathBuf,
) -> anyhow::Result<()> {
    let dir = run_dir(&artifacts, run_id);
    let summary_path = dir.join("telemetry_summary.json");
    let summary_value = read_json(summary_path)?;
    let summary: TelemetrySummary = serde_json::from_value(summary_value)?;
    let whatif = run_simulated_whatif(&summary.overall, topology, action)?;
    let saved = save_json(dir.join(format!("whatif_{}.json", action)), &whatif)?;
    println!("{}", serde_json::to_string_pretty(&whatif)?);
    eprintln!("saved {}", saved.display());
    Ok(())
}

fn load_mapping(
    path: Option<PathBuf>,
) -> anyhow::Result<std::collections::BTreeMap<String, String>> {
    if let Some(path) = path {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read mapping file: {}", path.display()))?;
        Ok(serde_json::from_str(&raw)
            .with_context(|| format!("mapping file is not valid JSON: {}", path.display()))?)
    } else {
        Ok(default_prometheus_mapping())
    }
}

#[allow(dead_code)]
fn _core_result<T>(value: CoreResult<T>) -> CoreResult<T> {
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use netdiag_core::ingest::ingest_trace;
    use netdiag_core::ml::{MODEL_FILE_NAME, MODEL_MANIFEST_FILE_NAME};
    use netdiag_core::models::{HilState, ModelManifest};
    use std::fs;
    use std::io::Write;

    fn sample(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../data/samples")
            .join(format!("{name}.csv"))
    }

    fn path_str(path: &std::path::Path) -> &str {
        path.to_str().expect("test path is utf-8")
    }

    #[test]
    fn train_command_writes_model_and_manifest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dataset_path = temp.path().join("training.jsonl");
        let mut dataset = fs::File::create(&dataset_path).expect("create dataset");
        for name in [
            "normal",
            "congestion",
            "random_loss",
            "dns_failure",
            "tls_failure",
            "udp_quic_blocked",
        ] {
            let ingest = ingest_trace(sample(name)).expect("sample ingest");
            let row = serde_json::json!({
                "label": name,
                "records": ingest.records,
            });
            writeln!(dataset, "{row}").expect("write training row");
        }

        let model_dir = temp.path().join("model");
        let args = Args::parse_from([
            "netdiag",
            "train",
            "--dataset",
            path_str(&dataset_path),
            "--model-dir",
            path_str(&model_dir),
        ]);
        run(args).expect("train command");

        assert!(model_dir.join(MODEL_FILE_NAME).exists());
        let manifest: ModelManifest = serde_json::from_slice(
            &fs::read(model_dir.join(MODEL_MANIFEST_FILE_NAME)).expect("manifest"),
        )
        .expect("manifest json");
        assert!(!manifest.synthetic_fallback);
        assert_eq!(manifest.training_examples, 6);
    }

    #[test]
    fn feedback_export_command_writes_training_rows() {
        let temp = tempfile::tempdir().expect("tempdir");
        let result = diagnose_file(
            sample("congestion"),
            temp.path(),
            Some(("line", "reroute_path_b")),
        )
        .expect("diagnose");
        let recommendation_id = result.recommendations[0].recommendation_id.clone();
        review_recommendation(
            temp.path(),
            &result.run_id,
            &recommendation_id,
            HilState::Accepted,
            "accepted for supervised training",
            "cli-test",
            Some(FaultLabel::Congestion),
        )
        .expect("review");

        let output = temp.path().join("feedback.jsonl");
        let args = Args::parse_from([
            "netdiag",
            "feedback",
            "export",
            "--artifacts",
            path_str(temp.path()),
            "--output",
            path_str(&output),
        ]);
        run(args).expect("feedback export");

        let body = fs::read_to_string(&output).expect("read jsonl");
        let lines = body.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let row: serde_json::Value = serde_json::from_str(lines[0]).expect("row json");
        assert_eq!(row["label"], row["final_label"]);
        assert_eq!(row["source"], "hil_accepted");
        assert_eq!(row["recommendation_id"], recommendation_id);
        assert!(row["features"]["latency_mean"].is_number());
        assert!(row["rule_labels"].is_array());
        assert_eq!(row["feedback_state"], "accepted");
    }
}
