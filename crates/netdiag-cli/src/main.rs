use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use netdiag_core::dataset::{
    DatasetManifestMetadata, DatasetRegisterOptions, DatasetValidationOptions, compare_datasets,
    inspect_dataset_jsonl, register_dataset_jsonl, split_dataset_jsonl, validate_dataset_jsonl,
    validate_dataset_jsonl_with_options,
};
use netdiag_core::diagnose_file;
use netdiag_core::evidence_bundle::export_evidence_bundle;
use netdiag_core::hil_review::review_recommendation;
use netdiag_core::ingest::ingest_trace;
use netdiag_core::lab::{
    ActionVerificationOptions, LabPreflightMode, LabPreflightOptions, LabRunOptions,
    calibrate_lab_uncertainty, preflight_lab_scenario_with_bearer_bindings,
    run_lab_batch_with_bearer_bindings, run_lab_scenario_with_bearer_bindings, summarize_lab_runs,
    validate_lab_run, verify_action_with_options,
};
use netdiag_core::ml::{
    MODEL_CURRENT_FILE_NAME, MODEL_MANIFEST_FILE_NAME, TrainingOptions,
    export_feedback_training_dataset, load_existing_model_bundle_identity,
    train_model_from_jsonl_with_options,
};
use netdiag_core::models::{
    ConnectorHealthStatus, FaultLabel, HilState, ModelManifest, RunHistoryFilter,
};
use netdiag_core::perf_budget::{
    build_perf_budget, compare_perf_budget, ensure_budget_has_measurements, load_perf_budget,
    run_perf_measurements_sampled, save_perf_budget,
};
use netdiag_core::reliability::write_text_atomic;
use netdiag_core::storage::{
    compare_runs, list_run_history_filtered, read_report, resolve_run_location, run_artifacts,
    run_evidence, save_json,
};
use netdiag_core::twin::{
    calibrate_topology_from_runs, export_topology, validate_policy_action_for_topology,
    validate_policy_action_shape, validate_topology_model,
};
use std::path::{Path, PathBuf};
use std::str::FromStr;

mod commands;
use commands::bearer_bindings::CliBearerBindings;
use commands::twin::{format_for_path, read_policy, read_topology, run_whatif, run_whatif_policy};

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
    ValidateTrace {
        file: PathBuf,
    },
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
    ArtifactRoot(commands::artifact_root::ArtifactRootArgs),
    Collect(commands::collect::CollectCommand),
    Reliability {
        #[command(subcommand)]
        command: commands::reliability::ReliabilityCommand,
    },
    Benchmark {
        #[command(subcommand)]
        command: commands::benchmark::BenchmarkCommand,
    },
    Pilot {
        #[command(subcommand)]
        command: commands::pilot::PilotCommand,
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
        #[command(flatten)]
        bearer_bindings: CliBearerBindings,
    },
    Run {
        scenario: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[command(flatten)]
        bearer_bindings: CliBearerBindings,
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
        #[command(flatten)]
        bearer_bindings: CliBearerBindings,
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
        #[arg(
            long,
            default_value_t = 0.2,
            allow_hyphen_values = true,
            value_parser = parse_dataset_split_ratio
        )]
        validation_ratio: f64,
        #[arg(
            long,
            default_value_t = 0.0,
            allow_hyphen_values = true,
            value_parser = parse_dataset_split_ratio
        )]
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

fn parse_dataset_split_ratio(value: &str) -> std::result::Result<f64, String> {
    let ratio = value
        .parse::<f64>()
        .map_err(|error| format!("invalid dataset split ratio {value:?}: {error}"))?;
    if !ratio.is_finite() || !(0.0..1.0).contains(&ratio) {
        return Err(format!(
            "dataset split ratio must be finite and in [0, 1), got {value:?}"
        ));
    }
    Ok(ratio)
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
            let temp = netdiag_platform::TrustedTempDirectory::create("netdiag-validate-trace-")
                .context("failed to create validate-trace trusted temporary directory")?;
            let pipeline_result = diagnose_file(&file, temp.path(), None);
            let pipeline = temp.finish(pipeline_result).with_context(|| {
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
                bearer_bindings,
            } => {
                let bearer_bindings = bearer_bindings.build()?;
                let report = preflight_lab_scenario_with_bearer_bindings(
                    &scenario,
                    LabPreflightOptions {
                        artifacts,
                        mode: mode.into(),
                    },
                    &bearer_bindings,
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
                bearer_bindings,
            } => {
                let bearer_bindings = bearer_bindings.build()?;
                let result = run_lab_scenario_with_bearer_bindings(
                    &scenario,
                    LabRunOptions { artifacts },
                    &bearer_bindings,
                )
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
                bearer_bindings,
            } => {
                if scenarios.is_empty() {
                    anyhow::bail!("lab batch requires at least one scenario");
                }
                let bearer_bindings = bearer_bindings.build()?;
                let report = run_lab_batch_with_bearer_bindings(
                    &scenarios,
                    LabRunOptions { artifacts },
                    &bearer_bindings,
                )
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
            let report = read_report(&artifacts, &run_id)?;
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
                serde_json::to_string_pretty(&training_output(&dataset, &model_dir, manifest)?)?
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
        Command::ArtifactRoot(command) => commands::artifact_root::run(command)?,
        Command::Collect(command) => commands::collect::run(command)?,
        Command::Reliability { command } => commands::reliability::run(command)?,
        Command::Benchmark { command } => commands::benchmark::run(command)?,
        Command::Pilot { command } => commands::pilot::run(command)?,
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
                let budget = build_perf_budget(&measurements, threshold_percent, baseline_scale)?;
                save_perf_budget(&baseline, &budget).with_context(|| {
                    format!(
                        "failed to write performance baseline {}",
                        baseline.display()
                    )
                })?;
                let report = compare_perf_budget(measurements, &budget, threshold_percent)?;
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
                let report = compare_perf_budget(measurements, &budget, threshold_percent)?;
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

fn training_output(
    dataset: &Path,
    model_dir: &Path,
    manifest: ModelManifest,
) -> anyhow::Result<serde_json::Value> {
    let identity = load_existing_model_bundle_identity(model_dir)
        .context("trained model generation could not be revalidated")?;
    Ok(serde_json::json!({
        "status": "trained",
        "dataset": dataset,
        "model_dir": model_dir,
        "model_file": manifest.model_file,
        "manifest_file": MODEL_MANIFEST_FILE_NAME,
        "current_descriptor": MODEL_CURRENT_FILE_NAME,
        "generation": identity.generation,
        "model_file_hash_sha256": identity.model_file_hash_sha256,
        "model_manifest_hash_sha256": identity.model_manifest_hash_sha256,
        "labels": manifest.labels,
        "training_examples": manifest.training_examples,
        "dataset_hash_sha256": manifest.dataset_hash_sha256,
        "training_config": manifest.training_config,
        "training_gate": manifest.training_gate,
        "evaluation": manifest.evaluation,
        "uncertainty_thresholds": manifest.uncertainty_thresholds,
    }))
}

fn parse_quality_filter(value: Option<&str>) -> anyhow::Result<Option<ConnectorHealthStatus>> {
    value
        .map(|value| {
            ConnectorHealthStatus::from_str(value)
                .map_err(|_| anyhow::anyhow!("invalid quality status: {value}"))
        })
        .transpose()
}

#[cfg(test)]
mod main_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use netdiag_core::ingest::ingest_trace;
    use netdiag_core::ml::{
        MODEL_CURRENT_FILE_NAME, load_existing_model_bundle_identity, train_model_from_jsonl,
    };
    use netdiag_core::models::HilState;
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
        netdiag_core::storage::ensure_artifact_root_owned(artifacts).expect("owned artifacts dir");
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

        assert!(model_dir.join(MODEL_CURRENT_FILE_NAME).exists());
        let manifest = load_existing_model_bundle_identity(&model_dir)
            .expect("model identity")
            .manifest;
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
        let runs = temp.path().join("runs");
        diagnose_file(sample("normal"), &runs, Some(("line", "reroute_path_b"))).expect("diagnose");
        let output = temp.path().join("calibrated-ring.yaml");
        #[cfg(unix)]
        let (victim, legacy_temp) = {
            use std::os::unix::fs::symlink;

            let victim = temp.path().join("victim.txt");
            fs::write(&victim, "preserve me").expect("victim fixture");
            symlink(&victim, &output).expect("output symlink fixture");
            let legacy_temp = output.with_extension("yaml.tmp");
            symlink(&victim, &legacy_temp).expect("legacy temp symlink fixture");
            (victim, legacy_temp)
        };
        let args = Args::parse_from([
            "netdiag",
            "topology",
            "calibrate",
            "--topology",
            path_str(&repo_file("examples/topologies/ring.yaml")),
            "--runs",
            path_str(&runs),
            "--output",
            path_str(&output),
        ]);

        run(args).expect("topology calibrate");

        assert!(output.exists());
        let calibrated = read_topology(&output).expect("read calibrated topology");
        assert!(calibrated.metadata.contains_key("calibrated_run_count"));
        #[cfg(unix)]
        {
            assert_eq!(
                fs::read_to_string(victim).expect("victim remains readable"),
                "preserve me"
            );
            assert!(
                fs::symlink_metadata(legacy_temp)
                    .expect("legacy temp symlink remains")
                    .file_type()
                    .is_symlink()
            );
            assert!(
                fs::symlink_metadata(output)
                    .expect("published output metadata")
                    .file_type()
                    .is_file()
            );
        }
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

        let artifacts = temp.path().join("artifacts");
        let register_args = Args::parse_from([
            "netdiag",
            "dataset",
            "register",
            path_str(&dataset_path),
            "--artifacts",
            path_str(&artifacts),
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

        let registered_manifest = fs::read_dir(artifacts.join("datasets/feedback-test"))
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
