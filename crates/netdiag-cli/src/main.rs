use anyhow::Context;
use clap::{Parser, Subcommand};
use netdiag_core::connectors::{
    HttpJsonConfig, PrometheusExpositionConfig, PrometheusQueryRangeConfig,
    default_prometheus_mapping, load_http_json, load_prometheus_exposition,
    load_prometheus_query_range,
};
use netdiag_core::models::{HilState, TelemetrySummary};
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
    Review {
        run_id: String,
        recommendation_id: String,
        #[arg(long)]
        state: String,
        #[arg(long, default_value = "")]
        notes: String,
        #[arg(long, default_value = "cli")]
        reviewer: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Collect {
        #[arg(long, value_parser = ["http-json", "prometheus-query", "prometheus-metrics"])]
        kind: String,
        #[arg(long)]
        endpoint: String,
        #[arg(long, default_value_t = 8)]
        timeout_secs: u64,
        #[arg(long, default_value_t = 300)]
        lookback_secs: i64,
        #[arg(long, default_value_t = 15)]
        step_secs: u64,
        #[arg(long)]
        mapping: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        diagnose: bool,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
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
        Command::Review {
            run_id,
            recommendation_id,
            state,
            notes,
            reviewer,
            artifacts,
        } => {
            let state = HilState::from_str(&state)
                .map_err(|_| anyhow::anyhow!("invalid HIL state: {state}"))?;
            let outcome = review_recommendation(
                artifacts,
                &run_id,
                &recommendation_id,
                state,
                &notes,
                &reviewer,
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
    }
    Ok(())
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
