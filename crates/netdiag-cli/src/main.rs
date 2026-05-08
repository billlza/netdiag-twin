use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use netdiag_core::connectors::{
    HttpJsonConfig, NativePcapConfig, NativePcapSource, OtlpGrpcReceiverConfig,
    PrometheusExpositionConfig, PrometheusQueryRangeConfig, SystemCountersConfig,
    default_prometheus_mapping, load_http_json, load_native_pcap, load_otlp_grpc_receiver,
    load_prometheus_exposition, load_prometheus_query_range, load_system_counters,
};
use netdiag_core::dataset::{
    DatasetManifestMetadata, DatasetRegisterOptions, DatasetValidationOptions, compare_datasets,
    inspect_dataset_jsonl, register_dataset_jsonl, split_dataset_jsonl, validate_dataset_jsonl,
    validate_dataset_jsonl_with_options,
};
use netdiag_core::evidence_bundle::export_evidence_bundle;
use netdiag_core::ingest::ingest_trace;
use netdiag_core::lab::{
    ActionVerificationOptions, LabPreflightMode, LabPreflightOptions, LabRunOptions,
    calibrate_lab_uncertainty, preflight_lab_scenario, run_lab_batch, run_lab_scenario,
    summarize_lab_runs, validate_lab_run, verify_action_with_options,
};
use netdiag_core::ml::{
    TrainingOptions, export_feedback_training_dataset, train_model_from_jsonl_with_options,
};
use netdiag_core::models::{
    ConnectorHealthStatus, FaultLabel, HilState, RunHistoryFilter, TelemetrySummary,
};
use netdiag_core::perf_budget::{
    build_perf_budget, compare_perf_budget, ensure_budget_has_measurements, load_perf_budget,
    run_perf_measurements_sampled, save_perf_budget,
};
use netdiag_core::storage::{
    compare_runs, connector_health_from_ingest, list_run_history_filtered, read_json,
    resolve_run_location, review_recommendation, run_artifacts, run_evidence, save_json,
    write_connector_health,
};
use netdiag_core::twin::{
    TopologyFormat, calibrate_topology_from_runs, export_topology, import_policy_action,
    import_topology, run_simulated_whatif, run_simulated_whatif_with_policy,
    validate_policy_action_for_topology, validate_policy_action_shape, validate_topology_model,
};
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
    #[command(name = "validate-trace", hide = true)]
    ValidateTrace { file: PathBuf },
    Whatif {
        run_id: String,
        topology: String,
        action: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    WhatifPolicy {
        run_id: String,
        #[arg(long)]
        topology: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Topology {
        #[command(subcommand)]
        command: TopologyCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Lab {
        #[command(subcommand)]
        command: LabCommand,
    },
    Dataset {
        #[command(subcommand)]
        command: DatasetCommand,
    },
    EvidenceBundle {
        run_id: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Export {
        run_id: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    History {
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        root_cause: Option<String>,
        #[arg(long)]
        quality: Option<String>,
    },
    Evidence {
        run_id: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Compare {
        left_run_id: String,
        right_run_id: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Artifacts {
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
        #[arg(long)]
        shuffle_seed: Option<u64>,
        #[arg(long, default_value_t = false)]
        stratified: bool,
        #[arg(long, default_value_t = 0)]
        min_rows_per_label: usize,
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

#[derive(Debug, Subcommand)]
enum LabCommand {
    Preflight {
        scenario: PathBuf,
        #[arg(long, value_enum, default_value_t = CliLabPreflightMode::Static)]
        mode: CliLabPreflightMode,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Run {
        scenario: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Validate {
        run_id: String,
        #[arg(long)]
        scenario: Option<PathBuf>,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Batch {
        scenarios: Vec<PathBuf>,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Summary {
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    Calibrate {
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    VerifyAction {
        before_run_id: Option<String>,
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        after: String,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long)]
        recommendation_id: Option<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        objective: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliLabPreflightMode {
    Static,
    Live,
}

impl From<CliLabPreflightMode> for LabPreflightMode {
    fn from(value: CliLabPreflightMode) -> Self {
        match value {
            CliLabPreflightMode::Static => LabPreflightMode::Static,
            CliLabPreflightMode::Live => LabPreflightMode::Live,
        }
    }
}

#[derive(Debug, Subcommand)]
enum DatasetCommand {
    Inspect {
        dataset: PathBuf,
    },
    Validate {
        dataset: PathBuf,
        #[arg(long, default_value_t = 0)]
        min_rows_per_label: usize,
    },
    Split {
        dataset: PathBuf,
        #[arg(long)]
        output_dir: Option<PathBuf>,
        #[arg(long, default_value_t = false)]
        stratified: bool,
        #[arg(long, default_value_t = 2026)]
        seed: u64,
        #[arg(long, default_value_t = 0.2)]
        validation_ratio: f64,
        #[arg(long, default_value_t = 0.0)]
        test_ratio: f64,
    },
    Register {
        dataset: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long)]
        dataset_id: Option<String>,
        #[arg(long)]
        source_run: Vec<String>,
        #[arg(long)]
        scenario_id: Vec<String>,
        #[arg(long)]
        operator: Option<String>,
        #[arg(long, default_value = "hil_final_label_required")]
        label_policy: String,
        #[arg(long, default_value_t = 0)]
        min_rows_per_label: usize,
        #[arg(long)]
        notes: Option<String>,
    },
    Compare {
        left: PathBuf,
        right: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TopologyCommand {
    Validate {
        topology: PathBuf,
    },
    Calibrate {
        #[arg(long)]
        topology: PathBuf,
        #[arg(long)]
        runs: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Validate {
        policy: PathBuf,
        #[arg(long)]
        topology: Option<PathBuf>,
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
        Command::ValidateTrace { file } => {
            let ingest = ingest_trace(&file).with_context(|| {
                format!("trace ingest validation failed for {}", file.display())
            })?;
            let temp = tempfile::tempdir().context("failed to create validate-trace tempdir")?;
            let pipeline = diagnose_file(&file, temp.path(), None).with_context(|| {
                format!("trace pipeline validation failed for {}", file.display())
            })?;
            let ml_top = pipeline.report.rule_vs_ml.ml_top.clone();
            let ml_top_prob = pipeline.report.rule_vs_ml.ml_top_prob;
            let root_causes = pipeline
                .report
                .root_causes
                .iter()
                .map(|root| root.symptom.clone())
                .collect::<Vec<_>>();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "valid",
                    "file": file,
                    "rows": ingest.schema.rows,
                    "sample": ingest.schema.sample,
                    "warnings": ingest.warnings,
                    "pipeline": {
                        "run_id": pipeline.run_id,
                        "root_causes": root_causes,
                        "ml_top": ml_top,
                        "ml_top_prob": ml_top_prob,
                        "model_manifest_hash": pipeline.report.model_manifest_hash,
                        "model_file_hash": pipeline.report.model_file_hash,
                        "diagnosis_status": pipeline.report.diagnosis_status,
                        "uncertainty": pipeline.report.uncertainty,
                    },
                }))?
            );
        }
        Command::Whatif {
            run_id,
            topology,
            action,
            artifacts,
        } => run_whatif(&run_id, &topology, &action, artifacts).context("what-if failed")?,
        Command::WhatifPolicy {
            run_id,
            topology,
            policy,
            artifacts,
        } => run_whatif_policy(&run_id, &topology, &policy, artifacts)
            .context("policy what-if failed")?,
        Command::Topology { command } => match command {
            TopologyCommand::Validate { topology } => {
                let model = read_topology(&topology)?;
                validate_topology_model(&model)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "valid",
                        "topology": topology,
                        "key": model.key,
                        "nodes": model.nodes.len(),
                        "links": model.links.len(),
                    }))?
                );
            }
            TopologyCommand::Calibrate {
                topology,
                runs,
                output,
            } => {
                let model = read_topology(&topology)?;
                let report = calibrate_topology_from_runs(&model, &runs).with_context(|| {
                    format!(
                        "topology calibration failed for {} using {}",
                        topology.display(),
                        runs.display()
                    )
                })?;
                let format = format_for_path(&output);
                let encoded = export_topology(&report.calibrated_topology, format)?;
                write_text_atomic(&output, &encoded)
                    .with_context(|| format!("failed to write {}", output.display()))?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        },
        Command::Policy { command } => match command {
            PolicyCommand::Validate { policy, topology } => {
                let action = read_policy(&policy)?;
                if let Some(topology) = topology {
                    let model = read_topology(&topology)?;
                    validate_policy_action_for_topology(&action, &model)?;
                } else {
                    validate_policy_action_shape(&action)?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "valid",
                        "policy": policy,
                        "id": action.id,
                        "kind": action.kind,
                    }))?
                );
            }
        },
        Command::Lab { command } => match command {
            LabCommand::Preflight {
                scenario,
                mode,
                artifacts,
            } => {
                let report = preflight_lab_scenario(
                    &scenario,
                    LabPreflightOptions {
                        artifacts,
                        mode: mode.into(),
                    },
                )
                .with_context(|| format!("lab preflight failed for {}", scenario.display()))?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.passed {
                    anyhow::bail!("lab preflight failed for {}", report.scenario_id);
                }
            }
            LabCommand::Run {
                scenario,
                artifacts,
            } => {
                let result = run_lab_scenario(&scenario, LabRunOptions { artifacts })
                    .with_context(|| format!("lab run failed for {}", scenario.display()))?;
                println!("{}", serde_json::to_string_pretty(&result)?);
                if !result.acceptance.passed {
                    anyhow::bail!(
                        "lab acceptance failed for {}",
                        result.acceptance.scenario_id
                    );
                }
            }
            LabCommand::Validate {
                run_id,
                scenario,
                artifacts,
            } => {
                let report = validate_lab_run(&artifacts, &run_id, scenario.as_deref())
                    .with_context(|| format!("lab validation failed for {run_id}"))?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.passed {
                    anyhow::bail!("lab acceptance failed for {}", report.scenario_id);
                }
            }
            LabCommand::Batch {
                scenarios,
                artifacts,
            } => {
                if scenarios.is_empty() {
                    anyhow::bail!("lab batch requires at least one scenario");
                }
                let report = run_lab_batch(&scenarios, LabRunOptions { artifacts })
                    .context("lab batch failed")?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if report.failed > 0 {
                    anyhow::bail!("lab batch failed for {} scenario(s)", report.failed);
                }
            }
            LabCommand::Summary { artifacts } => {
                let report = summarize_lab_runs(&artifacts)
                    .with_context(|| format!("lab summary failed for {}", artifacts.display()))?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            LabCommand::Calibrate { artifacts, dry_run } => {
                let report = calibrate_lab_uncertainty(&artifacts, dry_run).with_context(|| {
                    format!("lab calibration failed for {}", artifacts.display())
                })?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            LabCommand::VerifyAction {
                before_run_id,
                before,
                after,
                artifacts,
                recommendation_id,
                policy,
                objective,
            } => {
                if before.is_some() && before_run_id.is_some() {
                    anyhow::bail!(
                        "lab verify-action accepts either --before or a positional before run id, not both"
                    );
                }
                let before_run_id = before.or(before_run_id).ok_or_else(|| {
                    anyhow::anyhow!(
                        "lab verify-action requires --before or a positional before run id"
                    )
                })?;
                let verification = verify_action_with_options(
                    &artifacts,
                    &before_run_id,
                    &after,
                    ActionVerificationOptions {
                        recommendation_id,
                        policy_path: policy,
                        objective_path: objective,
                    },
                )
                .with_context(|| {
                    format!("lab action verification failed for {before_run_id} -> {after}")
                })?;
                println!("{}", serde_json::to_string_pretty(&verification)?);
            }
        },
        Command::Dataset { command } => match command {
            DatasetCommand::Inspect { dataset } => {
                let summary = inspect_dataset_jsonl(&dataset)
                    .with_context(|| format!("dataset inspect failed for {}", dataset.display()))?;
                println!("{}", serde_json::to_string_pretty(&summary)?);
            }
            DatasetCommand::Validate {
                dataset,
                min_rows_per_label,
            } => {
                let report = if min_rows_per_label == 0 {
                    validate_dataset_jsonl(&dataset)
                } else {
                    validate_dataset_jsonl_with_options(
                        &dataset,
                        DatasetValidationOptions { min_rows_per_label },
                    )
                }
                .with_context(|| format!("dataset validation failed for {}", dataset.display()))?;
                println!("{}", serde_json::to_string_pretty(&report)?);
                if !report.passed {
                    anyhow::bail!("dataset validation failed");
                }
            }
            DatasetCommand::Split {
                dataset,
                output_dir,
                stratified,
                seed,
                validation_ratio,
                test_ratio,
            } => {
                let output_dir = output_dir.unwrap_or_else(|| {
                    dataset
                        .parent()
                        .map(|parent| parent.join("splits"))
                        .unwrap_or_else(|| PathBuf::from("splits"))
                });
                let report = split_dataset_jsonl(
                    &dataset,
                    &output_dir,
                    stratified,
                    seed,
                    validation_ratio,
                    test_ratio,
                )
                .with_context(|| format!("dataset split failed for {}", dataset.display()))?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            DatasetCommand::Register {
                dataset,
                artifacts,
                dataset_id,
                source_run,
                scenario_id,
                operator,
                label_policy,
                min_rows_per_label,
                notes,
            } => {
                let registration = register_dataset_jsonl(
                    &dataset,
                    DatasetRegisterOptions {
                        artifacts,
                        metadata: DatasetManifestMetadata {
                            dataset_id,
                            sources: vec![
                                "registered_jsonl".to_string(),
                                dataset.display().to_string(),
                            ],
                            source_runs: source_run,
                            scenario_ids: scenario_id,
                            operator,
                            label_policy: Some(label_policy),
                            min_rows_per_label: (min_rows_per_label > 0)
                                .then_some(min_rows_per_label),
                            notes,
                        },
                    },
                )
                .with_context(|| format!("dataset register failed for {}", dataset.display()))?;
                println!("{}", serde_json::to_string_pretty(&registration)?);
            }
            DatasetCommand::Compare { left, right } => {
                let comparison = compare_datasets(&left, &right).with_context(|| {
                    format!(
                        "dataset compare failed for {} and {}",
                        left.display(),
                        right.display()
                    )
                })?;
                println!("{}", serde_json::to_string_pretty(&comparison)?);
            }
        },
        Command::EvidenceBundle {
            run_id,
            artifacts,
            output,
        } => {
            let manifest = export_evidence_bundle(&artifacts, &run_id, &output, &[])
                .with_context(|| format!("evidence bundle failed for {run_id}"))?;
            let location = resolve_run_location(&artifacts, &run_id)?;
            save_json(location.run_dir.join("evidence_bundle.json"), &manifest)?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Command::Export { run_id, artifacts } => {
            let path = resolve_run_location(&artifacts, &run_id)?
                .run_dir
                .join("report.json");
            let report = read_json(path)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::History {
            artifacts,
            limit,
            status,
            root_cause,
            quality,
        } => {
            let history = list_run_history_filtered(
                artifacts,
                RunHistoryFilter {
                    status,
                    root_cause,
                    quality: parse_quality_filter(quality.as_deref())?,
                },
                limit,
            )?;
            println!("{}", serde_json::to_string_pretty(&history)?);
        }
        Command::Evidence { run_id, artifacts } => {
            let evidence = run_evidence(artifacts, &run_id)?;
            println!("{}", serde_json::to_string_pretty(&evidence)?);
        }
        Command::Compare {
            left_run_id,
            right_run_id,
            artifacts,
        } => {
            let comparison = compare_runs(artifacts, &left_run_id, &right_run_id)?;
            println!("{}", serde_json::to_string_pretty(&comparison)?);
        }
        Command::Artifacts { run_id, artifacts } => {
            let artifacts = run_artifacts(artifacts, &run_id)?;
            println!("{}", serde_json::to_string_pretty(&artifacts)?);
        }
        Command::Train {
            dataset,
            model_dir,
            validation_split,
            shuffle_seed,
            stratified,
            min_rows_per_label,
        } => {
            let manifest = train_model_from_jsonl_with_options(
                &dataset,
                &model_dir,
                TrainingOptions {
                    validation_split,
                    shuffle_seed,
                    stratified,
                    min_rows_per_label,
                },
            )
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
                    "dataset_hash_sha256": manifest.dataset_hash_sha256,
                    "training_config": manifest.training_config,
                    "training_gate": manifest.training_gate,
                    "evaluation": manifest.evaluation,
                    "uncertainty_thresholds": manifest.uncertainty_thresholds,
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
                    "evidence_bundle_stale": outcome.evidence_bundle_stale,
                    "next_step": outcome.next_step,
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
            let health = connector_health_from_ingest(&kind, &kind, &loaded.sample, &loaded.ingest);
            if diagnose {
                let mut result = netdiag_core::diagnose_ingest(
                    loaded.ingest,
                    &artifacts,
                    Some(("line", "reroute_path_b")),
                )?;
                write_connector_health(&artifacts, &result.run_id, &health)?;
                result.connector_health = health;
                println!("{}", serde_json::to_string_pretty(&result.report)?);
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "health": health,
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

fn parse_quality_filter(value: Option<&str>) -> anyhow::Result<Option<ConnectorHealthStatus>> {
    value
        .map(|value| {
            ConnectorHealthStatus::from_str(value)
                .map_err(|_| anyhow::anyhow!("invalid quality status: {value}"))
        })
        .transpose()
}

fn run_whatif(
    run_id: &str,
    topology: &str,
    action: &str,
    artifacts: PathBuf,
) -> anyhow::Result<()> {
    let dir = resolve_run_location(&artifacts, run_id)?.run_dir;
    let summary_path = dir.join("telemetry_summary.json");
    let summary_value = read_json(summary_path)?;
    let summary: TelemetrySummary = serde_json::from_value(summary_value)?;
    let whatif = run_simulated_whatif(&summary.overall, topology, action)?;
    let saved = save_json(dir.join(format!("whatif_{}.json", action)), &whatif)?;
    println!("{}", serde_json::to_string_pretty(&whatif)?);
    eprintln!("saved {}", saved.display());
    Ok(())
}

fn run_whatif_policy(
    run_id: &str,
    topology: &std::path::Path,
    policy: &std::path::Path,
    artifacts: PathBuf,
) -> anyhow::Result<()> {
    let dir = resolve_run_location(&artifacts, run_id)?.run_dir;
    let summary_path = dir.join("telemetry_summary.json");
    let summary_value = read_json(summary_path)?;
    let summary: TelemetrySummary = serde_json::from_value(summary_value)?;
    let topology = read_topology(topology)?;
    let policy = read_policy(policy)?;
    validate_policy_action_for_topology(&policy, &topology)?;
    let whatif = run_simulated_whatif_with_policy(&summary.overall, &topology, &policy)?;
    let saved = save_json(dir.join(format!("whatif_{}.json", policy.id)), &whatif)?;
    println!("{}", serde_json::to_string_pretty(&whatif)?);
    eprintln!("saved {}", saved.display());
    Ok(())
}

fn read_topology(path: &std::path::Path) -> anyhow::Result<netdiag_core::models::TopologyModel> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read topology {}", path.display()))?;
    import_topology(&raw, format_for_path(path)).map_err(Into::into)
}

fn read_policy(path: &std::path::Path) -> anyhow::Result<netdiag_core::models::TwinPolicyAction> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read policy {}", path.display()))?;
    import_policy_action(&raw, format_for_path(path)).map_err(Into::into)
}

fn format_for_path(path: &std::path::Path) -> TopologyFormat {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "yaml" | "yml" => TopologyFormat::Yaml,
        _ => TopologyFormat::Json,
    }
}

fn write_text_atomic(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .map(|ext| format!("{ext}."))
            .unwrap_or_default()
    ));
    std::fs::write(&tmp, contents)
        .with_context(|| format!("failed to write temp file {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to move {} to {}", tmp.display(), path.display()))?;
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
    use netdiag_core::ml::{MODEL_FILE_NAME, MODEL_MANIFEST_FILE_NAME, train_model_from_jsonl};
    use netdiag_core::models::{HilState, ModelManifest};
    use netdiag_core::storage::list_run_history;
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

    fn repo_file(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path)
    }

    fn provision_test_model(artifacts: &std::path::Path) {
        fs::create_dir_all(artifacts).expect("artifacts dir");
        let dataset_path = artifacts.join("training.jsonl");
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
        train_model_from_jsonl(&dataset_path, artifacts.join("model")).expect("train model");
    }

    #[test]
    fn train_command_writes_model_and_manifest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dataset_path = temp.path().join("training.jsonl");
        let mut dataset = fs::File::create(&dataset_path).expect("create dataset");
        for _ in 0..2 {
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
        }

        let model_dir = temp.path().join("model");
        let args = Args::parse_from([
            "netdiag",
            "train",
            "--dataset",
            path_str(&dataset_path),
            "--model-dir",
            path_str(&model_dir),
            "--validation-split",
            "0.5",
            "--shuffle-seed",
            "2026",
            "--stratified",
        ]);
        run(args).expect("train command");

        assert!(model_dir.join(MODEL_FILE_NAME).exists());
        let manifest: ModelManifest = serde_json::from_slice(
            &fs::read(model_dir.join(MODEL_MANIFEST_FILE_NAME)).expect("manifest"),
        )
        .expect("manifest json");
        assert!(!manifest.synthetic_fallback);
        assert_eq!(manifest.training_examples, 6);
        assert!(manifest.dataset_hash_sha256.is_some());
        assert_eq!(
            manifest
                .training_config
                .as_ref()
                .and_then(|config| config.shuffle_seed),
            Some(2026)
        );
        assert!(manifest.evaluation.is_some());
        let evaluation = manifest.evaluation.expect("evaluation");
        assert_eq!(evaluation.validation_examples, 6);
        assert_eq!(evaluation.per_label.len(), FaultLabel::ALL.len());
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

    #[test]
    fn history_compare_and_artifacts_commands_read_run_center_data() {
        let temp = tempfile::tempdir().expect("tempdir");
        let left = diagnose_file(
            sample("normal"),
            temp.path(),
            Some(("line", "reroute_path_b")),
        )
        .expect("left diagnose");
        let right = diagnose_file(
            sample("dns_failure"),
            temp.path(),
            Some(("line", "reroute_path_b")),
        )
        .expect("right diagnose");

        let history_args = Args::parse_from([
            "netdiag",
            "history",
            "--artifacts",
            path_str(temp.path()),
            "--limit",
            "5",
            "--quality",
            "ok",
        ]);
        run(history_args).expect("history command");

        let evidence_args = Args::parse_from([
            "netdiag",
            "evidence",
            &right.run_id,
            "--artifacts",
            path_str(temp.path()),
        ]);
        run(evidence_args).expect("evidence command");

        let compare_args = Args::parse_from([
            "netdiag",
            "compare",
            &left.run_id,
            &right.run_id,
            "--artifacts",
            path_str(temp.path()),
        ]);
        run(compare_args).expect("compare command");

        let artifact_args = Args::parse_from([
            "netdiag",
            "artifacts",
            &right.run_id,
            "--artifacts",
            path_str(temp.path()),
        ]);
        run(artifact_args).expect("artifacts command");

        let history = list_run_history(temp.path(), 10).expect("history data");
        assert_eq!(history.len(), 2);
        let comparison =
            compare_runs(temp.path(), &left.run_id, &right.run_id).expect("comparison");
        assert!(!comparison.new_root_causes.is_empty() || comparison.ml_label_changed);
        let artifact_entries = run_artifacts(temp.path(), &right.run_id).expect("artifacts");
        assert!(artifact_entries.iter().any(|entry| entry.key == "report"));
        assert!(artifact_entries.iter().any(|entry| entry.key == "manifest"));
        assert!(
            artifact_entries
                .iter()
                .any(|entry| entry.key == "connector_health")
        );
    }

    #[test]
    fn topology_calibrate_command_writes_calibrated_topology() {
        let temp = tempfile::tempdir().expect("tempdir");
        diagnose_file(
            sample("normal"),
            temp.path(),
            Some(("line", "reroute_path_b")),
        )
        .expect("diagnose");
        let output = temp.path().join("calibrated-ring.yaml");
        let args = Args::parse_from([
            "netdiag",
            "topology",
            "calibrate",
            "--topology",
            path_str(&repo_file("examples/topologies/ring.yaml")),
            "--runs",
            path_str(temp.path()),
            "--output",
            path_str(&output),
        ]);

        run(args).expect("topology calibrate");

        assert!(output.exists());
        let calibrated = read_topology(&output).expect("read calibrated topology");
        assert!(calibrated.metadata.contains_key("calibrated_run_count"));
    }

    #[test]
    fn dataset_commands_inspect_validate_and_split_jsonl() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dataset_path = temp.path().join("feedback.jsonl");
        let mut dataset = fs::File::create(&dataset_path).expect("dataset");
        for label in ["normal", "congestion", "dns_failure", "normal"] {
            let row = serde_json::json!({
                "label": label,
                "features": {
                    "latency_mean": 20.0,
                    "latency_p95": 30.0,
                    "jitter_std": 2.0,
                    "loss_rate": 0.0,
                    "retrans_rate": 0.0,
                    "timeout": 0.0,
                    "retry": 0.0,
                    "throughput": 100.0,
                    "dns_events": 0.0,
                    "tls_events": 0.0,
                    "quic": 0.0
                }
            });
            writeln!(dataset, "{row}").expect("write row");
        }

        for command in ["inspect", "validate"] {
            let args = Args::parse_from(["netdiag", "dataset", command, path_str(&dataset_path)]);
            run(args).expect("dataset command");
        }

        let output_dir = temp.path().join("splits");
        let args = Args::parse_from([
            "netdiag",
            "dataset",
            "split",
            path_str(&dataset_path),
            "--output-dir",
            path_str(&output_dir),
            "--stratified",
            "--seed",
            "2026",
        ]);
        run(args).expect("dataset split");

        assert!(output_dir.join("dataset_manifest.json").exists());
        assert!(output_dir.join("feedback-train.jsonl").exists());
        assert!(output_dir.join("feedback-validation.jsonl").exists());

        let register_args = Args::parse_from([
            "netdiag",
            "dataset",
            "register",
            path_str(&dataset_path),
            "--artifacts",
            path_str(temp.path()),
            "--dataset-id",
            "feedback-test",
            "--source-run",
            "run-a",
            "--scenario-id",
            "lab-congestion-001",
            "--operator",
            "cli-test",
        ]);
        run(register_args).expect("dataset register");

        let registered_manifest = fs::read_dir(temp.path().join("datasets/feedback-test"))
            .expect("registered dataset dir")
            .map(|entry| entry.expect("entry").path())
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with("-manifest.json"))
            })
            .expect("registered manifest");
        let compare_args = Args::parse_from([
            "netdiag",
            "dataset",
            "compare",
            path_str(&dataset_path),
            path_str(&registered_manifest),
        ]);
        run(compare_args).expect("dataset compare");
    }

    #[test]
    fn lab_run_command_writes_acceptance_artifact() {
        let temp = tempfile::tempdir().expect("tempdir");
        provision_test_model(temp.path());
        let scenario = repo_file("examples/scenarios/lab-congestion-001.yaml");
        let preflight_args = Args::parse_from([
            "netdiag",
            "lab",
            "preflight",
            path_str(&scenario),
            "--artifacts",
            path_str(temp.path()),
        ]);
        run(preflight_args).expect("lab preflight");

        let args = Args::parse_from([
            "netdiag",
            "lab",
            "run",
            path_str(&scenario),
            "--artifacts",
            path_str(temp.path()),
        ]);
        run(args).expect("lab run");

        let scenario_root = temp.path().join("lab-runs").join("lab-congestion-001");
        let mut run_dirs = fs::read_dir(&scenario_root)
            .expect("lab run dirs")
            .map(|entry| entry.expect("entry").path())
            .collect::<Vec<_>>();
        run_dirs.sort();
        let latest = run_dirs.pop().expect("latest lab run");
        let acceptance: serde_json::Value =
            serde_json::from_slice(&fs::read(latest.join("acceptance.json")).expect("acceptance"))
                .expect("acceptance json");
        let run_id = acceptance["run_id"].as_str().expect("run id");

        assert_eq!(acceptance["passed"], true);
        assert!(latest.join("evidence_bundle.json").exists());
        assert!(temp.path().join("lab_run_index.json").exists());

        let validate_args = Args::parse_from([
            "netdiag",
            "lab",
            "validate",
            run_id,
            "--artifacts",
            path_str(temp.path()),
        ]);
        run(validate_args).expect("lab validate resolves index");

        let summary_args = Args::parse_from([
            "netdiag",
            "lab",
            "summary",
            "--artifacts",
            path_str(temp.path()),
        ]);
        run(summary_args).expect("lab summary");
    }

    #[test]
    fn validate_trace_runs_full_pipeline_smoke() {
        let args = Args::parse_from(["netdiag", "validate-trace", path_str(&sample("congestion"))]);
        run(args).expect("validate trace");
    }
}
