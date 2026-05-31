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
mod tests {
    use super::*;
    use netdiag_core::diagnose_file;
    use netdiag_core::ml::{
        MODEL_FILE_NAME, MODEL_MANIFEST_FILE_NAME, TrainingOptions, sha256_file,
        train_model_from_jsonl_with_options,
    };
    use netdiag_core::models::{FaultLabel, ModelManifest, ModelUncertaintyThresholds};
    use netdiag_core::storage::{read_json, save_json_atomic};
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

    fn write_passing_calibration(artifacts: &std::path::Path) -> PathBuf {
        let model_dir = artifacts.join("model");
        let manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
        let mut manifest: ModelManifest =
            serde_json::from_value(read_json(&manifest_path).expect("manifest"))
                .expect("manifest json");
        let thresholds = ModelUncertaintyThresholds::default();
        manifest.uncertainty_thresholds = Some(thresholds.clone());
        save_json_atomic(&manifest_path, &manifest).expect("manifest thresholds");

        let per_label = FaultLabel::ALL
            .iter()
            .map(|label| {
                (
                    label.as_str().to_string(),
                    serde_json::json!({
                        "runs": 1,
                        "accepted_known_runs": 1,
                        "rule_correct": 1,
                        "ml_correct": 1,
                        "rule_accuracy": 1.0,
                        "ml_accuracy": 1.0,
                        "known_rate": 1.0,
                        "uncertain_rate": 0.0,
                        "out_of_distribution_rate": 0.0
                    }),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let report = serde_json::json!({
            "schema": "netdiag-lab-calibration/v1",
            "generated_at": "2026-01-01T00:00:00Z",
            "artifact_root": artifacts.display().to_string(),
            "model_manifest_path": manifest_path.display().to_string(),
            "model_manifest_hash_sha256": sha256_file(&manifest_path).expect("manifest hash"),
            "model_file_hash_sha256": sha256_file(&model_dir.join(MODEL_FILE_NAME)).expect("model hash"),
            "dataset_hash_sha256": manifest.dataset_hash_sha256,
            "evaluated_runs": FaultLabel::ALL.len() + 1,
            "known_runs": FaultLabel::ALL.len(),
            "uncertain_runs": 0,
            "out_of_distribution_runs": 1,
            "skipped_runs": 0,
            "per_label": per_label,
            "ood": {
                "expected_ood_runs": 1,
                "expected_known_runs": FaultLabel::ALL.len(),
                "false_positive_runs": 0,
                "false_negative_runs": 0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0
            },
            "rule_ml_disagreement_hotspots": [],
            "feature_distance_distribution": {
                "count": FaultLabel::ALL.len() + 1,
                "p50": 1.0,
                "p95": 2.0,
                "max": 3.0
            },
            "suggested_rule_thresholds": {},
            "applied": true,
            "calibrated_thresholds": thresholds,
            "warnings": []
        });
        let calibration_path = artifacts.join("lab_calibration_report.json");
        save_json_atomic(&calibration_path, &report).expect("calibration report");
        calibration_path
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
        let calibration_report = write_passing_calibration(&artifacts);

        run(PilotCommand::ModelGate {
            model_dir: artifacts.join("model"),
            benchmark_report,
            calibration_report,
            min_rows_per_label: 1,
            min_accuracy: 0.9,
            min_macro_f1: 0.9,
            allow_missing_evaluation: true,
            max_ood_false_positive_rate: 0.05,
            max_ood_false_negative_rate: 0.05,
            max_rule_ml_disagreement_hotspot_rate: 0.10,
            max_calibration_age_days: 1000,
            min_expected_ood_runs: 1,
        })
        .expect("model gate command");
    }
}
