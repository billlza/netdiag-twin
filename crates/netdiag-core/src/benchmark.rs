use crate::error::{IoContext, NetdiagError, Result};
use crate::evidence_bundle::export_evidence_bundle;
use crate::ingest::ingest_trace;
use crate::lab::{LabPreflightMode, LabPreflightOptions, preflight_lab_scenario};
use crate::ml::ModelBundleSnapshot;
use crate::models::{ConnectorHealthStatus, DiagnosisStatus, FaultLabel};
use crate::perf_budget::{
    compare_perf_budget, load_perf_budget, run_perf_measurements_sampled_with_capability,
};
use crate::pipeline::{
    diagnose_ingest_with_whatif_and_model_snapshot_and_capability,
    ensure_run_directory_publication_supported,
};
use crate::reliability::{
    ReliabilityCheckOptions, ReliabilityCheckReport, check_reliability, write_text_atomic,
};
use crate::storage::{
    ArtifactRootCapability, prepare_artifact_root, run_dir, save_json_atomic,
    with_artifact_root_capability,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::time::Instant;

mod adapter_validation;
mod benchmark_model_identity;
mod ood_scenarios;
use adapter_validation::run_adapter_validation_section;
use benchmark_model_identity::{candidate_model_identity, provision_benchmark_model};
use ood_scenarios::ood_scenario_paths;

pub(crate) const BENCHMARK_SCHEMA: &str = "netdiag-benchmark-report/v1";
const DEFAULT_SUITE: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkOptions {
    pub artifacts: PathBuf,
    pub output: PathBuf,
    #[serde(default)]
    pub suite: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub suite: String,
    pub passed: bool,
    pub artifacts: String,
    pub output: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_model_manifest_hash_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_model_file_hash_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_dataset_hash_sha256: Option<String>,
    pub environment: BenchmarkEnvironment,
    #[serde(default)]
    pub sections: Vec<BenchmarkSection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reliability: Option<ReliabilityCheckReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkEnvironment {
    pub os: String,
    pub arch: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSection {
    pub name: String,
    pub status: ConnectorHealthStatus,
    pub elapsed_millis: f64,
    #[serde(default)]
    pub checks: Vec<BenchmarkCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkCheck {
    pub name: String,
    pub status: ConnectorHealthStatus,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

pub fn run_benchmark(options: BenchmarkOptions) -> Result<BenchmarkReport> {
    let suite = options
        .suite
        .clone()
        .unwrap_or_else(|| DEFAULT_SUITE.to_string());
    if suite != DEFAULT_SUITE {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported benchmark suite: {suite}"
        )));
    }
    let known_sample_root = options.artifacts.join("known-samples");
    ensure_run_directory_publication_supported(&known_sample_root)?;
    let capability = prepare_artifact_root(&known_sample_root)?;
    std::fs::create_dir_all(&options.output).with_path(&options.output)?;

    let mut sections = Vec::new();
    let mut known_run_ids = Vec::new();
    let candidate_model = match options.model_dir.as_deref() {
        Some(model_dir) => Some(candidate_model_identity(model_dir)?),
        None => None,
    };
    sections.push(run_known_sample_section(
        &known_sample_root,
        &capability,
        candidate_model.as_ref().map(|identity| &identity.snapshot),
        &mut known_run_ids,
    )?);
    sections.push(run_ood_preflight_section(&known_sample_root)?);
    sections.push(run_adapter_validation_section()?);
    sections.push(run_perf_section(&capability)?);
    sections.push(run_evidence_bundle_section(
        &known_sample_root,
        &known_sample_root.join("benchmark-evidence"),
        known_run_ids.first(),
        &capability,
    )?);
    let reliability = with_artifact_root_capability(&capability, |_| {
        check_reliability(ReliabilityCheckOptions {
            artifact_root: known_sample_root.clone(),
            run_id: None,
        })
    })?;
    sections.push(BenchmarkSection {
        name: "artifact integrity".to_string(),
        status: reliability.status,
        elapsed_millis: 0.0,
        checks: reliability
            .checks
            .iter()
            .map(|check| BenchmarkCheck {
                name: check.name.clone(),
                status: check.status,
                message: check.message.clone(),
                details: Some(json!({
                    "run_id": check.run_id,
                    "artifact": check.artifact,
                    "reason_codes": check.reason_codes,
                })),
            })
            .collect(),
    });

    let passed = sections
        .iter()
        .all(|section| section.status == ConnectorHealthStatus::Ok);
    let report = BenchmarkReport {
        schema: BENCHMARK_SCHEMA.to_string(),
        generated_at: Utc::now(),
        suite,
        passed,
        artifacts: options.artifacts.display().to_string(),
        output: options.output.display().to_string(),
        candidate_model_manifest_hash_sha256: candidate_model
            .as_ref()
            .map(|identity| identity.model_manifest_hash_sha256.clone()),
        candidate_model_file_hash_sha256: candidate_model
            .as_ref()
            .map(|identity| identity.model_file_hash_sha256.clone()),
        candidate_dataset_hash_sha256: candidate_model
            .as_ref()
            .and_then(|identity| identity.dataset_hash_sha256.clone()),
        environment: BenchmarkEnvironment {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            profile: if cfg!(debug_assertions) {
                "debug".to_string()
            } else {
                "release".to_string()
            },
        },
        sections,
        reliability: Some(reliability),
    };
    save_json_atomic(options.output.join("benchmark_report.json"), &report)?;
    write_text_atomic(
        options.output.join("benchmark_report.md"),
        &render_benchmark_markdown(&report),
    )?;
    Ok(report)
}

fn run_known_sample_section(
    artifact_root: &Path,
    capability: &ArtifactRootCapability,
    candidate_model: Option<&ModelBundleSnapshot>,
    known_run_ids: &mut Vec<String>,
) -> Result<BenchmarkSection> {
    let provisioned_model;
    let model = match candidate_model {
        Some(model) => model,
        None => {
            provisioned_model = with_artifact_root_capability(capability, |_| {
                provision_benchmark_model(artifact_root)
            })?;
            &provisioned_model
        }
    };
    timed_section("known sample diagnosis", || {
        let mut checks = Vec::new();
        for (label, path) in known_sample_paths() {
            let ingest = ingest_trace(&path)?;
            let result = diagnose_ingest_with_whatif_and_model_snapshot_and_capability(
                ingest, model, None, capability,
            )?;
            with_artifact_root_capability(capability, |_| {
                let evidence_bundle = export_evidence_bundle(
                    artifact_root,
                    &result.run_id,
                    artifact_root
                        .join("evidence")
                        .join(format!("netdiag-evidence-{}.zip", result.run_id)),
                    &[],
                )?;
                save_json_atomic(
                    run_dir(artifact_root, &result.run_id)?.join("evidence_bundle.json"),
                    &evidence_bundle,
                )
            })?;
            known_run_ids.push(result.run_id.clone());
            let actual = result.report.diagnosis_decision.primary_label;
            let status = if result.report.diagnosis_status == DiagnosisStatus::Known
                && actual == Some(label)
            {
                ConnectorHealthStatus::Ok
            } else {
                ConnectorHealthStatus::Error
            };
            checks.push(BenchmarkCheck {
                name: label.as_str().to_string(),
                status,
                message: format!(
                    "expected {}, got {:?} with status {}",
                    label, actual, result.report.diagnosis_status
                ),
                details: Some(json!({
                    "run_id": result.run_id,
                    "ml_top": result.report.rule_vs_ml.ml_top,
                    "ml_top_probability": result.report.rule_vs_ml.ml_top_prob,
                })),
            });
        }
        Ok(checks)
    })
}

fn run_ood_preflight_section(artifact_root: &Path) -> Result<BenchmarkSection> {
    timed_section("ood benchmark preflight", || {
        let mut checks = Vec::new();
        for scenario in ood_scenario_paths(&repo_root())? {
            let report = preflight_lab_scenario(
                &scenario,
                LabPreflightOptions {
                    artifacts: artifact_root.to_path_buf(),
                    mode: LabPreflightMode::Static,
                },
            )?;
            checks.push(BenchmarkCheck {
                name: scenario
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or("ood-scenario")
                    .to_string(),
                status: if report.passed {
                    ConnectorHealthStatus::Ok
                } else {
                    ConnectorHealthStatus::Error
                },
                message: if report.passed {
                    "static preflight passed".to_string()
                } else {
                    "static preflight failed".to_string()
                },
                details: Some(json!({
                    "scenario_id": report.scenario_id,
                    "checks": report.checks,
                })),
            });
        }
        Ok(checks)
    })
}

fn run_perf_section(capability: &ArtifactRootCapability) -> Result<BenchmarkSection> {
    timed_section("performance budget", || {
        let baseline_path = repo_root().join("perf-baseline.json");
        let budget = load_perf_budget(&baseline_path)?;
        let measurements = run_perf_measurements_sampled_with_capability(capability, 1)?;
        let report = compare_perf_budget(measurements, &budget, budget.threshold_percent)?;
        let mut checks = report
            .measurements
            .iter()
            .map(|measurement| BenchmarkCheck {
                name: measurement.name.clone(),
                status: ConnectorHealthStatus::Ok,
                message: format!("{} ms", measurement.elapsed_millis),
                details: Some(json!({
                    "rows": measurement.rows,
                    "iterations": measurement.iterations,
                    "elapsed_millis": measurement.elapsed_millis,
                })),
            })
            .collect::<Vec<_>>();
        for failure in &report.failures {
            checks.push(BenchmarkCheck {
                name: format!("{} budget", failure.name),
                status: ConnectorHealthStatus::Error,
                message: format!(
                    "{} ms exceeded allowed {} ms",
                    failure.elapsed_millis, failure.allowed_millis
                ),
                details: Some(json!(failure)),
            });
        }
        Ok(checks)
    })
}

fn run_evidence_bundle_section(
    artifact_root: &Path,
    output_root: &Path,
    run_id: Option<&String>,
    capability: &ArtifactRootCapability,
) -> Result<BenchmarkSection> {
    timed_section("evidence bundle export", || {
        let Some(run_id) = run_id else {
            return Ok(vec![BenchmarkCheck {
                name: "evidence bundle export".to_string(),
                status: ConnectorHealthStatus::Error,
                message: "no known-sample run id was available".to_string(),
                details: None,
            }]);
        };
        let output = output_root.join(format!("netdiag-evidence-{run_id}.zip"));
        let manifest = with_artifact_root_capability(capability, |_| {
            let manifest = export_evidence_bundle(artifact_root, run_id, &output, &[])?;
            save_json_atomic(
                run_dir(artifact_root, run_id)?.join("evidence_bundle.json"),
                &manifest,
            )?;
            Ok(manifest)
        })?;
        Ok(vec![BenchmarkCheck {
            name: "evidence bundle export".to_string(),
            status: if manifest.files.is_empty() {
                ConnectorHealthStatus::Error
            } else {
                ConnectorHealthStatus::Ok
            },
            message: format!("exported {} files", manifest.files.len()),
            details: Some(json!({
                "output": manifest.output,
                "files": manifest.files.len(),
            })),
        }])
    })
}

fn timed_section(
    name: &str,
    action: impl FnOnce() -> Result<Vec<BenchmarkCheck>>,
) -> Result<BenchmarkSection> {
    let started = Instant::now();
    let checks = action()?;
    if checks.is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "benchmark section {name:?} produced no checks"
        )));
    }
    let status = checks
        .iter()
        .map(|check| check.status)
        .max()
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("benchmark section {name:?} produced no status"))
        })?;
    Ok(BenchmarkSection {
        name: name.to_string(),
        status,
        elapsed_millis: round_millis(started.elapsed().as_secs_f64() * 1_000.0),
        checks,
    })
}

fn render_benchmark_markdown(report: &BenchmarkReport) -> String {
    let mut body = String::new();
    body.push_str("# NetDiag Twin Benchmark Report\n\n");
    body.push_str(&format!(
        "- Schema: `{}`\n- Suite: `{}`\n- Status: `{}`\n- Generated: `{}`\n- Environment: `{}` `{}` `{}`\n\n",
        report.schema,
        report.suite,
        if report.passed { "passed" } else { "failed" },
        report.generated_at,
        report.environment.os,
        report.environment.arch,
        report.environment.profile,
    ));
    for section in &report.sections {
        body.push_str(&format!(
            "## {} ({})\n\n",
            section.name,
            section.status.as_str()
        ));
        body.push_str("| Check | Status | Message |\n| --- | --- | --- |\n");
        for check in &section.checks {
            body.push_str(&format!(
                "| {} | {} | {} |\n",
                markdown_cell(&check.name),
                check.status.as_str(),
                markdown_cell(&check.message)
            ));
        }
        body.push('\n');
    }
    body
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn known_sample_paths() -> Vec<(FaultLabel, PathBuf)> {
    [
        (FaultLabel::Normal, "normal"),
        (FaultLabel::Congestion, "congestion"),
        (FaultLabel::RandomLoss, "random_loss"),
        (FaultLabel::DnsFailure, "dns_failure"),
        (FaultLabel::TlsFailure, "tls_failure"),
        (FaultLabel::UdpQuicBlocked, "udp_quic_blocked"),
    ]
    .into_iter()
    .map(|(label, name)| {
        (
            label,
            repo_root().join("data/samples").join(format!("{name}.csv")),
        )
    })
    .collect()
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn round_millis(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml::{
        TrainingOptions, load_existing_model_bundle_snapshot, train_model_from_jsonl_with_options,
    };

    #[test]
    fn benchmark_model_identity_reads_candidate_hashes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dataset = repo_root().join("examples/datasets/pilot-smoke-training.jsonl");
        let model_dir = temp.path().join("model");
        let manifest = train_model_from_jsonl_with_options(
            &dataset,
            &model_dir,
            TrainingOptions {
                min_rows_per_label: 1,
                ..TrainingOptions::default()
            },
        )
        .expect("model");

        let identity = candidate_model_identity(&model_dir).expect("candidate identity");
        let snapshot = load_existing_model_bundle_snapshot(&model_dir).expect("snapshot");

        assert_eq!(identity.dataset_hash_sha256, manifest.dataset_hash_sha256);
        assert_eq!(
            identity.model_manifest_hash_sha256,
            snapshot.model_manifest_hash_sha256
        );
        assert_eq!(
            identity.model_file_hash_sha256,
            snapshot.model_file_hash_sha256
        );
    }

    #[test]
    fn benchmark_markdown_includes_sections() {
        let report = BenchmarkReport {
            schema: BENCHMARK_SCHEMA.to_string(),
            generated_at: Utc::now(),
            suite: DEFAULT_SUITE.to_string(),
            passed: true,
            artifacts: "artifacts".to_string(),
            output: "target/report".to_string(),
            candidate_model_manifest_hash_sha256: None,
            candidate_model_file_hash_sha256: None,
            candidate_dataset_hash_sha256: None,
            environment: BenchmarkEnvironment {
                os: "test".to_string(),
                arch: "test".to_string(),
                profile: "debug".to_string(),
            },
            sections: vec![BenchmarkSection {
                name: "known sample diagnosis".to_string(),
                status: ConnectorHealthStatus::Ok,
                elapsed_millis: 1.0,
                checks: vec![BenchmarkCheck {
                    name: "normal".to_string(),
                    status: ConnectorHealthStatus::Ok,
                    message: "ok".to_string(),
                    details: None,
                }],
            }],
            reliability: None,
        };
        let markdown = render_benchmark_markdown(&report);
        assert!(markdown.contains("NetDiag Twin Benchmark Report"));
        assert!(markdown.contains("known sample diagnosis"));
    }

    #[test]
    fn benchmark_section_with_no_checks_fails_closed() {
        let error = timed_section("empty", || Ok(Vec::new()))
            .expect_err("empty benchmark section must fail");
        assert!(error.to_string().contains("produced no checks"));
    }

    #[test]
    fn ood_scenario_paths_fail_closed_when_directory_is_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join("missing-scenarios");

        let message = ood_scenarios::ood_scenario_paths_in(&missing)
            .expect_err("missing OOD scenario directory should fail")
            .to_string();

        assert!(message.contains("missing-scenarios"));
    }

    #[test]
    fn ood_scenario_paths_fail_closed_when_no_ood_scenarios_exist() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join("lab-congestion-001.yaml"),
            "schema: netdiag-lab-scenario/v1\n",
        )
        .expect("write non-ood scenario");

        let message = ood_scenarios::ood_scenario_paths_in(temp.path())
            .expect_err("empty OOD benchmark suite should fail")
            .to_string();

        assert!(message.contains("no OOD benchmark scenarios"));
    }

    #[test]
    fn ood_scenario_paths_return_sorted_ood_yaml_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join("ood-z.yaml"),
            "schema: netdiag-lab-scenario/v1\n",
        )
        .expect("write ood z");
        std::fs::write(
            temp.path().join("ood-a.yaml"),
            "schema: netdiag-lab-scenario/v1\n",
        )
        .expect("write ood a");
        std::fs::write(temp.path().join("ood-not-yaml.txt"), "ignored").expect("write ignored");

        let paths = ood_scenarios::ood_scenario_paths_in(temp.path()).expect("ood paths");

        let names = paths
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["ood-a.yaml", "ood-z.yaml"]);
    }
}
