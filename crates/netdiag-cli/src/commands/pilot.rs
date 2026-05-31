use anyhow::Context;
use clap::Subcommand;
use netdiag_core::pilot::{
    ModelPromotionOptions, PilotOptions, PilotWorkflowOptions, PilotWorkflowVerificationOptions,
    evaluate_model_promotion, preflight_pilot, run_pilot, run_pilot_workflow,
};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum PilotCommand {
    Preflight {
        pilot: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_active: bool,
    },
    Run {
        pilot: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_active: bool,
    },
    Workflow {
        pilot: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value_t = false)]
        allow_active: bool,
        #[arg(long)]
        after_run_id: Option<String>,
        #[arg(long)]
        recommendation_id: Option<String>,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        objective: Option<PathBuf>,
    },
    ModelGate {
        #[arg(long)]
        model_dir: PathBuf,
        #[arg(long)]
        benchmark_report: PathBuf,
        #[arg(long, default_value_t = 1)]
        min_rows_per_label: usize,
        #[arg(long, default_value_t = 0.90)]
        min_accuracy: f64,
        #[arg(long, default_value_t = 0.90)]
        min_macro_f1: f64,
        #[arg(long, default_value_t = false)]
        allow_missing_evaluation: bool,
    },
}

pub fn run(command: PilotCommand) -> anyhow::Result<()> {
    match command {
        PilotCommand::Preflight {
            pilot,
            artifacts,
            allow_active,
        } => {
            let report = preflight_pilot(
                &pilot,
                PilotOptions {
                    artifacts,
                    allow_active,
                },
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
        } => {
            let report = run_pilot(
                &pilot,
                PilotOptions {
                    artifacts,
                    allow_active,
                },
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
            after_run_id,
            recommendation_id,
            policy,
            objective,
        } => {
            let verification = after_run_id.map(|after_run_id| PilotWorkflowVerificationOptions {
                after_run_id,
                recommendation_id,
                policy_path: policy,
                objective_path: objective,
            });
            let report = run_pilot_workflow(
                &pilot,
                PilotWorkflowOptions {
                    artifacts,
                    allow_active,
                    verification,
                },
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
            min_rows_per_label,
            min_accuracy,
            min_macro_f1,
            allow_missing_evaluation,
        } => {
            let report = evaluate_model_promotion(ModelPromotionOptions {
                model_dir,
                benchmark_report,
                min_rows_per_label,
                min_accuracy,
                min_macro_f1,
                allow_missing_evaluation,
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
mod tests {
    use super::*;
    use netdiag_core::diagnose_file;
    use netdiag_core::ml::{TrainingOptions, train_model_from_jsonl_with_options};
    use tempfile::tempdir;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(std::path::Path::parent)
            .expect("repo root")
            .to_path_buf()
    }

    fn sample(name: &str) -> PathBuf {
        repo_root().join("data/samples").join(format!("{name}.csv"))
    }

    fn provision_model(artifacts: &std::path::Path) {
        train_model_from_jsonl_with_options(
            repo_root().join("examples/datasets/pilot-smoke-training.jsonl"),
            artifacts.join("model"),
            TrainingOptions {
                min_rows_per_label: 1,
                ..TrainingOptions::default()
            },
        )
        .expect("trained model");
    }

    fn write_passing_benchmark(path: &std::path::Path) {
        let report = serde_json::json!({
            "schema": "netdiag-benchmark-report/v1",
            "generated_at": "2026-01-01T00:00:00Z",
            "suite": "test",
            "passed": true,
            "artifacts": "test",
            "output": "test",
            "environment": {
                "os": "test",
                "arch": "test",
                "profile": "test"
            },
            "sections": [{
                "name": "ood benchmark preflight",
                "status": "ok",
                "elapsed_millis": 1.0,
                "checks": [{
                    "name": "ood-cpu-saturation",
                    "status": "ok",
                    "message": "static preflight passed"
                }]
            }]
        });
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&report).expect("benchmark json"),
        )
        .expect("benchmark report");
    }

    #[test]
    fn preflight_command_succeeds_for_connector_family_manifest() {
        let temp = tempdir().expect("tempdir");
        let artifacts = temp.path().join("artifacts");
        provision_model(&artifacts);

        run(PilotCommand::Preflight {
            pilot: repo_root().join("examples/pilots/connector-family-readonly.yaml"),
            artifacts,
            allow_active: false,
        })
        .expect("preflight command");
    }

    #[test]
    fn run_command_succeeds_for_loopback_manifest() {
        let temp = tempdir().expect("tempdir");
        let artifacts = temp.path().join("artifacts");
        provision_model(&artifacts);

        run(PilotCommand::Run {
            pilot: repo_root().join("examples/pilots/loopback-mock.yaml"),
            artifacts,
            allow_active: false,
        })
        .expect("run command");
    }

    #[test]
    fn workflow_command_fails_without_after_run_verification() {
        let temp = tempdir().expect("tempdir");
        let artifacts = temp.path().join("artifacts");
        provision_model(&artifacts);

        let error = run(PilotCommand::Workflow {
            pilot: repo_root().join("examples/pilots/generic-lab-kit.yaml"),
            artifacts,
            allow_active: false,
            after_run_id: None,
            recommendation_id: None,
            policy: None,
            objective: None,
        })
        .expect_err("workflow should not pass with pending verification");

        assert!(error.to_string().contains("pilot workflow gates failed"));
    }

    #[test]
    fn workflow_command_succeeds_with_after_run_verification() {
        let temp = tempdir().expect("tempdir");
        let artifacts = temp.path().join("artifacts");
        provision_model(&artifacts);
        let after = diagnose_file(
            sample("normal"),
            &artifacts,
            Some(("line", "reroute_path_b")),
        )
        .expect("after run");

        run(PilotCommand::Workflow {
            pilot: repo_root().join("examples/pilots/generic-lab-kit.yaml"),
            artifacts,
            allow_active: false,
            after_run_id: Some(after.run_id),
            recommendation_id: None,
            policy: None,
            objective: None,
        })
        .expect("workflow command");
    }

    #[test]
    fn model_gate_command_succeeds_with_missing_evaluation_override() {
        let temp = tempdir().expect("tempdir");
        let artifacts = temp.path().join("artifacts");
        provision_model(&artifacts);
        let benchmark_report = temp.path().join("benchmark_report.json");
        write_passing_benchmark(&benchmark_report);

        run(PilotCommand::ModelGate {
            model_dir: artifacts.join("model"),
            benchmark_report,
            min_rows_per_label: 1,
            min_accuracy: 0.9,
            min_macro_f1: 0.9,
            allow_missing_evaluation: true,
        })
        .expect("model gate command");
    }
}
