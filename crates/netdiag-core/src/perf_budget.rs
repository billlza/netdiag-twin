use crate::error::{NetdiagError, Result};
use crate::models::{PerfBudget, PerfBudgetEntry};
use crate::pipeline::ensure_run_directory_publication_supported;
use crate::storage::{
    ArtifactRootCapability, prepare_artifact_root, read_stable_regular_file_bounded,
    save_json_atomic,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

mod measurements;
mod workspace;

const PERF_SCHEMA_VERSION: u32 = 1;
const MAX_PERF_SAMPLES: usize = 100;
const MAX_PERF_BUDGET_BYTES: u64 = 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfMeasurement {
    pub name: String,
    pub elapsed_millis: f64,
    #[serde(default)]
    pub min_millis: f64,
    #[serde(default)]
    pub max_millis: f64,
    #[serde(default)]
    pub sample_millis: Vec<f64>,
    pub rows: usize,
    pub iterations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfBudgetFailure {
    pub name: String,
    #[serde(default)]
    pub reason: String,
    pub elapsed_millis: f64,
    pub allowed_millis: f64,
    pub budget_millis: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfBudgetReport {
    pub schema_version: u32,
    pub generated_at: chrono::DateTime<Utc>,
    pub threshold_percent: f64,
    pub passed: bool,
    pub measurements: Vec<PerfMeasurement>,
    pub failures: Vec<PerfBudgetFailure>,
}

pub fn run_perf_measurements(artifact_root: impl AsRef<Path>) -> Result<Vec<PerfMeasurement>> {
    let artifact_root = artifact_root.as_ref();
    ensure_run_directory_publication_supported(artifact_root)?;
    let capability = prepare_artifact_root(artifact_root)?;
    run_perf_measurements_with_capability(&capability)
}

fn run_perf_measurements_with_capability(
    capability: &ArtifactRootCapability,
) -> Result<Vec<PerfMeasurement>> {
    workspace::run(capability, measurements::run)
}

pub fn run_perf_measurements_sampled(
    artifact_root: impl AsRef<Path>,
    samples: usize,
) -> Result<Vec<PerfMeasurement>> {
    validate_sample_count(samples)?;
    let artifact_root = artifact_root.as_ref();
    ensure_run_directory_publication_supported(artifact_root)?;
    let capability = prepare_artifact_root(artifact_root)?;
    run_perf_measurements_sampled_with_capability(&capability, samples)
}

pub(crate) fn run_perf_measurements_sampled_with_capability(
    capability: &ArtifactRootCapability,
    samples: usize,
) -> Result<Vec<PerfMeasurement>> {
    validate_sample_count(samples)?;
    if samples == 1 {
        return run_perf_measurements_with_capability(capability);
    }
    let mut grouped: BTreeMap<String, Vec<PerfMeasurement>> = BTreeMap::new();
    for _ in 0..samples {
        for measurement in run_perf_measurements_with_capability(capability)? {
            grouped
                .entry(measurement.name.clone())
                .or_default()
                .push(measurement);
        }
    }
    let mut combined = Vec::new();
    for (_name, mut measurements) in grouped {
        measurements.sort_by(|left, right| left.elapsed_millis.total_cmp(&right.elapsed_millis));
        let mut median = measurements[measurements.len() / 2].clone();
        let sample_millis = measurements
            .iter()
            .map(|measurement| measurement.elapsed_millis)
            .collect::<Vec<_>>();
        median.min_millis = sample_millis.iter().copied().fold(f64::INFINITY, f64::min);
        median.max_millis = sample_millis
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);
        median.sample_millis = sample_millis;
        combined.push(median);
    }
    combined.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(combined)
}

fn validate_sample_count(samples: usize) -> Result<()> {
    if (1..=MAX_PERF_SAMPLES).contains(&samples) {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "performance sample count must be between 1 and {MAX_PERF_SAMPLES}"
        )))
    }
}

pub fn build_perf_budget(
    measurements: &[PerfMeasurement],
    threshold_percent: f64,
    scale: f64,
) -> Result<PerfBudget> {
    validate_threshold_percent("threshold_percent", threshold_percent)?;
    if !scale.is_finite() || scale < 1.0 {
        return Err(NetdiagError::InvalidTrace(
            "performance baseline scale must be finite and at least 1".to_string(),
        ));
    }
    validate_measurements(measurements)?;
    let mut scenarios = BTreeMap::new();
    for measurement in measurements {
        let scaled_millis = measurement.elapsed_millis * scale;
        if !scaled_millis.is_finite() {
            return Err(NetdiagError::InvalidTrace(format!(
                "performance baseline for {} overflowed",
                measurement.name
            )));
        }
        scenarios.insert(
            measurement.name.clone(),
            PerfBudgetEntry {
                max_millis: round_millis(scaled_millis.max(min_budget_millis(&measurement.name))),
                rows: measurement.rows,
                iterations: measurement.iterations,
            },
        );
    }
    Ok(PerfBudget {
        schema_version: PERF_SCHEMA_VERSION,
        generated_at: Utc::now(),
        threshold_percent,
        scenarios,
    })
}

pub fn compare_perf_budget(
    measurements: Vec<PerfMeasurement>,
    budget: &PerfBudget,
    threshold_percent: f64,
) -> Result<PerfBudgetReport> {
    validate_threshold_percent("threshold_percent", threshold_percent)?;
    validate_perf_budget(budget)?;
    validate_measurements(&measurements)?;
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for measurement in &measurements {
        seen.insert(measurement.name.as_str());
        let Some(entry) = budget.scenarios.get(&measurement.name) else {
            failures.push(PerfBudgetFailure {
                name: measurement.name.clone(),
                reason: "measurement is missing from the performance baseline".to_string(),
                elapsed_millis: measurement.elapsed_millis,
                allowed_millis: 0.0,
                budget_millis: 0.0,
            });
            continue;
        };
        if measurement.rows != entry.rows || measurement.iterations != entry.iterations {
            failures.push(PerfBudgetFailure {
                name: measurement.name.clone(),
                reason: format!(
                    "measurement shape changed: rows {}/{} iterations {}/{}",
                    measurement.rows, entry.rows, measurement.iterations, entry.iterations
                ),
                elapsed_millis: measurement.elapsed_millis,
                allowed_millis: entry.max_millis,
                budget_millis: entry.max_millis,
            });
            continue;
        }
        let allowed = entry.max_millis * (1.0 + threshold_percent / 100.0);
        if !allowed.is_finite() {
            return Err(NetdiagError::InvalidTrace(format!(
                "performance allowance for {} overflowed",
                measurement.name
            )));
        }
        if measurement.elapsed_millis > allowed {
            failures.push(PerfBudgetFailure {
                name: measurement.name.clone(),
                reason: "measurement exceeded the allowed performance budget".to_string(),
                elapsed_millis: measurement.elapsed_millis,
                allowed_millis: round_millis(allowed),
                budget_millis: entry.max_millis,
            });
        }
    }
    for (name, entry) in &budget.scenarios {
        if !seen.contains(name.as_str()) {
            failures.push(PerfBudgetFailure {
                name: name.clone(),
                reason: "baseline scenario is missing from current measurements".to_string(),
                elapsed_millis: 0.0,
                allowed_millis: entry.max_millis,
                budget_millis: entry.max_millis,
            });
        }
    }
    Ok(PerfBudgetReport {
        schema_version: PERF_SCHEMA_VERSION,
        generated_at: Utc::now(),
        threshold_percent,
        passed: failures.is_empty(),
        measurements,
        failures,
    })
}

fn validate_threshold_percent(name: &str, value: f64) -> Result<()> {
    if value.is_finite() && (0.0..=100.0).contains(&value) {
        return Ok(());
    }
    Err(NetdiagError::InvalidTrace(format!(
        "{name} must be finite and between 0 and 100"
    )))
}

fn validate_measurements(measurements: &[PerfMeasurement]) -> Result<()> {
    if measurements.is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "performance measurements are empty".to_string(),
        ));
    }
    let mut names = BTreeSet::new();
    for measurement in measurements {
        if measurement.name.trim().is_empty() {
            return Err(NetdiagError::InvalidTrace(
                "performance measurement name is empty".to_string(),
            ));
        }
        if !names.insert(measurement.name.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate performance measurement: {}",
                measurement.name
            )));
        }
        if measurement.iterations == 0 {
            return Err(NetdiagError::InvalidTrace(format!(
                "performance measurement {} has zero iterations",
                measurement.name
            )));
        }
        for (field, value) in [
            ("elapsed_millis", measurement.elapsed_millis),
            ("min_millis", measurement.min_millis),
            ("max_millis", measurement.max_millis),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(NetdiagError::InvalidTrace(format!(
                    "performance measurement {} {field} must be finite and non-negative",
                    measurement.name
                )));
            }
        }
        if measurement.min_millis > measurement.elapsed_millis
            || measurement.elapsed_millis > measurement.max_millis
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "performance measurement {} median must be within its min/max range",
                measurement.name
            )));
        }
        if measurement.sample_millis.is_empty()
            || measurement
                .sample_millis
                .iter()
                .any(|value| !value.is_finite() || *value < 0.0)
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "performance measurement {} samples must be non-empty, finite, and non-negative",
                measurement.name
            )));
        }
        let mut samples = measurement.sample_millis.clone();
        samples.sort_by(f64::total_cmp);
        let sample_min = samples[0];
        let sample_median = samples[samples.len() / 2];
        let sample_max = samples[samples.len() - 1];
        if measurement.min_millis != sample_min
            || measurement.elapsed_millis != sample_median
            || measurement.max_millis != sample_max
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "performance measurement {} summary does not match sample_millis",
                measurement.name
            )));
        }
    }
    Ok(())
}

fn validate_perf_budget(budget: &PerfBudget) -> Result<()> {
    if budget.schema_version != PERF_SCHEMA_VERSION {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported performance budget schema version: {}",
            budget.schema_version
        )));
    }
    validate_threshold_percent("baseline threshold_percent", budget.threshold_percent)?;
    if budget.scenarios.is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "performance budget has no scenarios".to_string(),
        ));
    }
    for (name, entry) in &budget.scenarios {
        if name.trim().is_empty() {
            return Err(NetdiagError::InvalidTrace(
                "performance budget scenario name is empty".to_string(),
            ));
        }
        if !entry.max_millis.is_finite() || entry.max_millis < 0.0 {
            return Err(NetdiagError::InvalidTrace(format!(
                "performance budget scenario {name} duration must be finite and non-negative"
            )));
        }
        if entry.iterations == 0 {
            return Err(NetdiagError::InvalidTrace(format!(
                "performance budget scenario {name} has zero iterations"
            )));
        }
    }
    Ok(())
}

pub fn load_perf_budget(path: impl AsRef<Path>) -> Result<PerfBudget> {
    let path = path.as_ref();
    let bytes =
        read_stable_regular_file_bounded(path, MAX_PERF_BUDGET_BYTES)?.ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("performance budget is missing: {}", path.display()))
        })?;
    let budget = crate::strict_json::from_slice(&bytes).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "performance budget is invalid at {}: {}",
            path.display(),
            crate::strict_json::error_summary(&source)
        ))
    })?;
    validate_perf_budget(&budget)?;
    Ok(budget)
}

pub fn save_perf_budget(path: impl AsRef<Path>, budget: &PerfBudget) -> Result<PathBuf> {
    validate_perf_budget(budget)?;
    save_json_atomic(path, budget)
}

fn round_millis(value: f64) -> f64 {
    let whole = value.trunc();
    whole + ((value - whole) * 100.0).round() / 100.0
}

fn min_budget_millis(name: &str) -> f64 {
    match name {
        "ingest_six_samples" => 25.0,
        "telemetry_synthetic_100k" => 500.0,
        "rules_synthetic_100k" => 25.0,
        "ml_cold_model_train" => 1_000.0,
        "ml_secure_bundle_load" => 50.0,
        "ml_cached_infer_20" => 50.0,
        "whatif_synthetic_100" => 25.0,
        "artifact_write_large_10k" => 250.0,
        "pipeline_six_samples_cached_model" => 2_500.0,
        "evidence_bundle_export_cached_run" => 250.0,
        _ => 100.0,
    }
}

pub fn ensure_budget_has_measurements(report: &PerfBudgetReport) -> Result<()> {
    if report.measurements.is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "performance budget produced no measurements".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measurement(name: &str, elapsed_millis: f64) -> PerfMeasurement {
        PerfMeasurement {
            name: name.to_string(),
            elapsed_millis,
            min_millis: elapsed_millis,
            max_millis: elapsed_millis,
            sample_millis: vec![elapsed_millis],
            rows: 10,
            iterations: 2,
        }
    }

    fn budget(names: &[&str]) -> PerfBudget {
        PerfBudget {
            schema_version: PERF_SCHEMA_VERSION,
            generated_at: Utc::now(),
            threshold_percent: 15.0,
            scenarios: names
                .iter()
                .map(|name| {
                    (
                        (*name).to_string(),
                        PerfBudgetEntry {
                            max_millis: 100.0,
                            rows: 10,
                            iterations: 2,
                        },
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn perf_budget_requires_every_baseline_scenario() {
        let report = compare_perf_budget(
            vec![measurement("present", 10.0)],
            &budget(&["present", "missing"]),
            15.0,
        )
        .expect("valid comparison");

        assert!(!report.passed);
        assert!(report.failures.iter().any(|failure| {
            failure.name == "missing"
                && failure.reason == "baseline scenario is missing from current measurements"
        }));
    }

    #[test]
    fn perf_budget_rejects_duplicate_measurements() {
        let error = compare_perf_budget(
            vec![
                measurement("duplicate", 10.0),
                measurement("duplicate", 11.0),
            ],
            &budget(&["duplicate"]),
            15.0,
        )
        .expect_err("duplicate must fail fast");

        assert!(
            error
                .to_string()
                .contains("duplicate performance measurement")
        );
    }

    #[test]
    fn perf_budget_reports_unknown_and_shape_changed_measurements() {
        let mut shape_changed = measurement("shape", 10.0);
        shape_changed.rows = 11;
        let report = compare_perf_budget(
            vec![measurement("unknown", 10.0), shape_changed],
            &budget(&["shape"]),
            15.0,
        )
        .expect("structurally valid comparison");

        assert!(!report.passed);
        assert!(report.failures.iter().any(|failure| {
            failure.reason == "measurement is missing from the performance baseline"
        }));
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.reason.starts_with("measurement shape changed"))
        );
    }

    #[test]
    fn perf_budget_rejects_non_finite_thresholds_and_measurements() {
        let threshold_error = compare_perf_budget(
            vec![measurement("scenario", 10.0)],
            &budget(&["scenario"]),
            f64::NAN,
        )
        .expect_err("non-finite threshold must fail fast");
        assert!(threshold_error.to_string().contains("threshold_percent"));

        let measurement_error = compare_perf_budget(
            vec![measurement("scenario", f64::NAN)],
            &budget(&["scenario"]),
            15.0,
        )
        .expect_err("non-finite measurement must fail fast");
        assert!(measurement_error.to_string().contains("elapsed_millis"));
    }

    #[test]
    fn perf_budget_builder_rejects_silent_normalization_inputs() {
        let measurements = vec![measurement("scenario", 10.0)];
        assert!(build_perf_budget(&measurements, f64::NAN, 3.0).is_err());
        assert!(build_perf_budget(&measurements, 15.0, 0.0).is_err());
        assert!(build_perf_budget(&measurements, 15.0, f64::INFINITY).is_err());
    }

    #[test]
    fn sampled_measurements_reject_zero_or_unbounded_work() {
        let temp = tempfile::tempdir().expect("tempdir");
        assert!(run_perf_measurements_sampled(temp.path(), 0).is_err());
        assert!(run_perf_measurements_sampled(temp.path(), MAX_PERF_SAMPLES + 1).is_err());
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("unchanged artifact root")
                .count(),
            0
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn measurements_preserve_an_unowned_current_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let artifact_root = temp.path().join("external-artifacts");
        let current = artifact_root.join(Path::new("current"));
        std::fs::create_dir(&artifact_root).expect("unowned artifact root");
        std::fs::create_dir(&current).expect("unowned current directory");
        std::fs::write(current.join("sentinel"), b"preserve-me").expect("sentinel");

        let error = run_perf_measurements(&artifact_root)
            .expect_err("unowned non-empty root must require explicit migration");

        assert!(error.to_string().contains("explicit migration"), "{error}");
        assert_eq!(
            std::fs::read(current.join("sentinel")).expect("preserved sentinel"),
            b"preserve-me"
        );
        assert!(!artifact_root.join(".netdiag-artifact-root.json").exists());
    }

    #[test]
    fn perf_budget_rejects_inconsistent_sample_summaries() {
        let mut invalid = measurement("scenario", 10.0);
        invalid.sample_millis = vec![5.0, 10.0, 15.0];
        invalid.min_millis = 4.0;
        invalid.max_millis = 15.0;
        let error = compare_perf_budget(vec![invalid], &budget(&["scenario"]), 15.0)
            .expect_err("inconsistent summary must fail");
        assert!(error.to_string().contains("does not match sample_millis"));
    }

    #[test]
    fn perf_budget_load_is_bounded_and_validated() {
        let temp = tempfile::tempdir().expect("tempdir");
        let oversized = temp.path().join("oversized.json");
        std::fs::File::create(&oversized)
            .expect("oversized fixture")
            .set_len(MAX_PERF_BUDGET_BYTES + 1)
            .expect("oversized length");
        let error = load_perf_budget(&oversized).expect_err("oversized budget");
        assert!(error.to_string().contains("exceeds"), "{error}");

        let invalid = temp.path().join("invalid.json");
        let mut invalid_budget = budget(&["scenario"]);
        invalid_budget.schema_version += 1;
        std::fs::write(
            &invalid,
            serde_json::to_vec(&invalid_budget).expect("invalid budget JSON"),
        )
        .expect("invalid budget");
        let error = load_perf_budget(&invalid).expect_err("invalid schema");
        assert!(error.to_string().contains("schema version"), "{error}");
    }

    #[test]
    fn perf_budget_rejects_duplicate_scenarios_without_echoing_input() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("duplicate.json");
        std::fs::write(
            &path,
            br#"{
                "schema_version":1,
                "generated_at":"2026-01-01T00:00:00Z",
                "threshold_percent":15.0,
                "scenarios":{
                    "private-scenario":{"max_millis":10.0,"rows":1,"iterations":1},
                    "private-scenario":{"max_millis":20.0,"rows":1,"iterations":1}
                }
            }"#,
        )
        .expect("duplicate-key budget fixture");

        let error = load_perf_budget(&path).expect_err("duplicate scenario must fail");
        let message = error.to_string();
        assert!(message.contains("duplicate key"), "{message}");
        assert!(!message.contains("private-scenario"), "{message}");
    }
}
