use crate::error::{IoContext, NetdiagError, Result};
use crate::evidence_bundle::export_evidence_bundle;
use crate::ingest::ingest_trace;
use crate::lab::{LabPreflightMode, LabPreflightOptions, preflight_lab_scenario};
use crate::ml::{TrainingOptions, train_model_from_jsonl_with_options};
use crate::models::{ConnectorHealthStatus, DiagnosisStatus, FaultLabel};
use crate::perf_budget::{compare_perf_budget, load_perf_budget, run_perf_measurements_sampled};
use crate::pipeline::diagnose_ingest_with_whatif_and_existing_model_dir;
use crate::reliability::{
    ReliabilityCheckOptions, ReliabilityCheckReport, check_reliability, write_text_atomic,
};
use crate::storage::{run_dir, save_json_atomic};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const BENCHMARK_SCHEMA: &str = "netdiag-benchmark-report/v1";
const DEFAULT_SUITE: &str = "default";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkOptions {
    pub artifacts: PathBuf,
    pub output: PathBuf,
    #[serde(default)]
    pub suite: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub suite: String,
    pub passed: bool,
    pub artifacts: String,
    pub output: String,
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
    let suite = options.suite.unwrap_or_else(|| DEFAULT_SUITE.to_string());
    if suite != DEFAULT_SUITE {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported benchmark suite: {suite}"
        )));
    }
    std::fs::create_dir_all(&options.artifacts).with_path(&options.artifacts)?;
    std::fs::create_dir_all(&options.output).with_path(&options.output)?;

    let mut sections = Vec::new();
    let mut known_run_ids = Vec::new();
    sections.push(run_known_sample_section(
        &options.artifacts.join("known-samples"),
        &mut known_run_ids,
    )?);
    sections.push(run_ood_preflight_section(&options.artifacts)?);
    sections.push(run_adapter_validation_section()?);
    sections.push(run_perf_section(&options.artifacts.join("perf"))?);
    sections.push(run_evidence_bundle_section(
        &options.artifacts.join("known-samples"),
        &options.artifacts.join("evidence"),
        known_run_ids.first(),
    )?);
    let reliability = check_reliability(ReliabilityCheckOptions {
        artifact_root: options.artifacts.join("known-samples"),
        run_id: None,
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
        .all(|section| section.status != ConnectorHealthStatus::Error);
    let report = BenchmarkReport {
        schema: BENCHMARK_SCHEMA.to_string(),
        generated_at: Utc::now(),
        suite,
        passed,
        artifacts: options.artifacts.display().to_string(),
        output: options.output.display().to_string(),
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
    known_run_ids: &mut Vec<String>,
) -> Result<BenchmarkSection> {
    let model_dir = provision_benchmark_model(artifact_root)?;
    timed_section("known sample diagnosis", || {
        let mut checks = Vec::new();
        for (label, path) in known_sample_paths() {
            let ingest = ingest_trace(&path)?;
            let result = diagnose_ingest_with_whatif_and_existing_model_dir(
                ingest,
                artifact_root,
                &model_dir,
                None,
            )?;
            let evidence_bundle = export_evidence_bundle(
                artifact_root,
                &result.run_id,
                artifact_root
                    .join("evidence")
                    .join(format!("netdiag-evidence-{}.zip", result.run_id)),
                &[],
            )?;
            save_json_atomic(
                run_dir(artifact_root, &result.run_id).join("evidence_bundle.json"),
                &evidence_bundle,
            )?;
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

fn provision_benchmark_model(artifact_root: &Path) -> Result<PathBuf> {
    let dataset = repo_root().join("examples/datasets/pilot-smoke-training.jsonl");
    let model_dir = artifact_root.join("model");
    train_model_from_jsonl_with_options(
        &dataset,
        &model_dir,
        TrainingOptions {
            validation_split: 0.0,
            shuffle_seed: Some(2026),
            stratified: false,
            min_rows_per_label: 1,
        },
    )?;
    Ok(model_dir)
}

fn run_ood_preflight_section(artifact_root: &Path) -> Result<BenchmarkSection> {
    timed_section("ood benchmark preflight", || {
        let mut checks = Vec::new();
        for scenario in ood_scenario_paths() {
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

fn run_adapter_validation_section() -> Result<BenchmarkSection> {
    timed_section("adapter schema and ingest", || {
        let python = repo_root().join(".venv-jsonschema/bin/python");
        let python = if python.exists() {
            python
        } else {
            PathBuf::from("python3")
        };
        [
            "validate_adapter_samples.py",
            "validate_adapter_contract.py",
        ]
        .into_iter()
        .map(|script_name| {
            let script = repo_root().join("scripts").join(script_name);
            let output = Command::new(&python)
                .arg(&script)
                .current_dir(repo_root())
                .output()
                .map_err(|err| {
                    NetdiagError::Connector(format!(
                        "failed to run adapter validator {script_name}: {err}"
                    ))
                })?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let status = if output.status.success() {
                ConnectorHealthStatus::Ok
            } else {
                ConnectorHealthStatus::Error
            };
            Ok(BenchmarkCheck {
                name: script_name.to_string(),
                status,
                message: if output.status.success() {
                    "adapter contract passed schema and Rust ingest validation".to_string()
                } else {
                    "adapter contract validation failed".to_string()
                },
                details: Some(json!({
                    "stdout": stdout.lines().collect::<Vec<_>>(),
                    "stderr": stderr.lines().collect::<Vec<_>>(),
                })),
            })
        })
        .collect()
    })
}

fn run_perf_section(artifact_root: &Path) -> Result<BenchmarkSection> {
    timed_section("performance budget", || {
        let baseline_path = repo_root().join("perf-baseline.json");
        let budget = load_perf_budget(&baseline_path)?;
        let measurements = run_perf_measurements_sampled(artifact_root, 1)?;
        let report = compare_perf_budget(measurements, &budget, budget.threshold_percent);
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
        let manifest = export_evidence_bundle(artifact_root, run_id, &output, &[])?;
        save_json_atomic(
            run_dir(artifact_root, run_id).join("evidence_bundle.json"),
            &manifest,
        )?;
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
    let status = checks
        .iter()
        .map(|check| check.status)
        .max()
        .unwrap_or(ConnectorHealthStatus::Ok);
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

fn ood_scenario_paths() -> Vec<PathBuf> {
    let scenario_root = repo_root().join("examples/scenarios");
    let mut paths = std::fs::read_dir(&scenario_root)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|value| value.to_str())
                        .is_some_and(|name| name.starts_with("ood-") && name.ends_with(".yaml"))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    paths.sort();
    paths
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn round_millis(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_markdown_includes_sections() {
        let report = BenchmarkReport {
            schema: BENCHMARK_SCHEMA.to_string(),
            generated_at: Utc::now(),
            suite: DEFAULT_SUITE.to_string(),
            passed: true,
            artifacts: "artifacts".to_string(),
            output: "target/report".to_string(),
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
}
