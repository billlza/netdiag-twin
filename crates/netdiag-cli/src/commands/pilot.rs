use anyhow::Context;
use clap::Subcommand;
use netdiag_core::pilot::{
    ModelPromotionOptions, PilotOptions, PilotWorkflowOptions, PilotWorkflowVerificationOptions,
    evaluate_model_promotion, preflight_pilot_with_bearer_bindings, run_pilot_with_bearer_bindings,
    run_pilot_workflow_with_bearer_bindings,
};
use std::path::PathBuf;

use super::bearer_bindings::CliBearerBindings;

#[derive(Debug, Subcommand)]
pub enum PilotCommand {
    Preflight {
        pilot: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_active: bool,
        #[command(flatten)]
        bearer_bindings: CliBearerBindings,
    },
    Run {
        pilot: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_active: bool,
        /// Execute manifest-declared trusted adapter code within its configured root.
        #[arg(long, default_value_t = false)]
        allow_adapter_execution: bool,
        #[command(flatten)]
        bearer_bindings: CliBearerBindings,
    },
    Workflow {
        pilot: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_active: bool,
        /// Execute manifest-declared trusted adapter code within its configured root.
        #[arg(long, default_value_t = false)]
        allow_adapter_execution: bool,
        #[arg(long)]
        after_run_id: Option<String>,
        #[arg(long)]
        recommendation_id: Option<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        objective: Option<PathBuf>,
        #[command(flatten)]
        bearer_bindings: CliBearerBindings,
    },
    ModelGate {
        #[arg(long)]
        model_dir: PathBuf,
        #[arg(long)]
        benchmark_report: PathBuf,
        #[arg(long)]
        calibration_report: PathBuf,
        #[arg(long, default_value_t = 1)]
        min_rows_per_label: usize,
        #[arg(long, default_value_t = 0.90)]
        min_accuracy: f64,
        #[arg(long, default_value_t = 0.90)]
        min_macro_f1: f64,
        #[arg(long, default_value_t = false)]
        allow_missing_evaluation: bool,
        #[arg(long, default_value_t = 0.05)]
        max_ood_false_positive_rate: f64,
        #[arg(long, default_value_t = 0.05)]
        max_ood_false_negative_rate: f64,
        #[arg(long, default_value_t = 0.10)]
        max_rule_ml_disagreement_hotspot_rate: f64,
        #[arg(long, default_value_t = 30)]
        max_calibration_age_days: u64,
        #[arg(long, default_value_t = 1)]
        min_expected_ood_runs: usize,
    },
}

pub fn run(command: PilotCommand) -> anyhow::Result<()> {
    match command {
        PilotCommand::Preflight {
            pilot,
            artifacts,
            allow_active,
            bearer_bindings,
        } => {
            let bearer_bindings = bearer_bindings.build()?;
            let report = preflight_pilot_with_bearer_bindings(
                &pilot,
                PilotOptions {
                    artifacts,
                    allow_active,
                    allow_adapter_execution: false,
                },
                &bearer_bindings,
            )
            .with_context(|| format!("pilot preflight failed for {}", pilot.display()))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.passed {
                anyhow::bail!("pilot preflight failed for {}", report.pilot_id);
            }
        }
        PilotCommand::Run {
            pilot,
            artifacts,
            allow_active,
            allow_adapter_execution,
            bearer_bindings,
        } => {
            let bearer_bindings = bearer_bindings.build()?;
            let report = run_pilot_with_bearer_bindings(
                &pilot,
                PilotOptions {
                    artifacts,
                    allow_active,
                    allow_adapter_execution,
                },
                &bearer_bindings,
            )
            .with_context(|| format!("pilot run failed for {}", pilot.display()))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.passed {
                anyhow::bail!("pilot gates failed for {}", report.pilot_id);
            }
        }
        PilotCommand::Workflow {
            pilot,
            artifacts,
            allow_active,
            allow_adapter_execution,
            after_run_id,
            recommendation_id,
            policy,
            objective,
            bearer_bindings,
        } => {
            let bearer_bindings = bearer_bindings.build()?;
            let verification = after_run_id.map(|after_run_id| PilotWorkflowVerificationOptions {
                after_run_id,
                recommendation_id,
                policy_path: policy,
                objective_path: objective,
            });
            let report = run_pilot_workflow_with_bearer_bindings(
                &pilot,
                PilotWorkflowOptions {
                    artifacts,
                    allow_active,
                    allow_adapter_execution,
                    verification,
                },
                &bearer_bindings,
            )
            .with_context(|| format!("pilot workflow failed for {}", pilot.display()))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.passed {
                anyhow::bail!("pilot workflow gates failed for {}", report.pilot_id);
            }
        }
        PilotCommand::ModelGate {
            model_dir,
            benchmark_report,
            calibration_report,
            min_rows_per_label,
            min_accuracy,
            min_macro_f1,
            allow_missing_evaluation,
            max_ood_false_positive_rate,
            max_ood_false_negative_rate,
            max_rule_ml_disagreement_hotspot_rate,
            max_calibration_age_days,
            min_expected_ood_runs,
        } => {
            let report = evaluate_model_promotion(ModelPromotionOptions {
                model_dir,
                benchmark_report,
                calibration_report,
                min_rows_per_label,
                min_accuracy,
                min_macro_f1,
                allow_missing_evaluation,
                max_ood_false_positive_rate,
                max_ood_false_negative_rate,
                max_rule_ml_disagreement_hotspot_rate,
                max_calibration_age_days,
                min_expected_ood_runs,
            })
            .context("model promotion gate failed")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.passed {
                anyhow::bail!("model promotion gates failed");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
