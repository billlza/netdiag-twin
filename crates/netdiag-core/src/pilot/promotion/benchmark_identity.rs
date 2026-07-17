use super::{ModelPromotionGate, gate};
use crate::benchmark::BenchmarkReport;
use crate::models::ModelManifest;

pub(super) fn benchmark_model_match_gate(
    benchmark: &BenchmarkReport,
    manifest: &ModelManifest,
    current_manifest_hash: Option<&str>,
    current_model_hash: Option<&str>,
) -> ModelPromotionGate {
    let mut failures = Vec::new();
    match (
        benchmark.candidate_model_manifest_hash_sha256.as_deref(),
        current_manifest_hash,
    ) {
        (Some(report_hash), Some(current_hash)) if report_hash == current_hash => {}
        (Some(report_hash), Some(current_hash)) => failures.push(format!(
            "benchmark report manifest hash mismatch benchmark={report_hash} current={current_hash}"
        )),
        _ => failures.push("benchmark report is missing candidate model manifest hash".to_string()),
    }
    match (
        benchmark.candidate_model_file_hash_sha256.as_deref(),
        current_model_hash,
    ) {
        (Some(report_hash), Some(current_hash)) if report_hash == current_hash => {}
        (Some(report_hash), Some(current_hash)) => failures.push(format!(
            "benchmark report model file hash mismatch benchmark={report_hash} current={current_hash}"
        )),
        _ => failures.push("benchmark report is missing candidate model file hash".to_string()),
    }
    match (
        benchmark.candidate_dataset_hash_sha256.as_deref(),
        manifest.dataset_hash_sha256.as_deref(),
    ) {
        (Some(report_hash), Some(manifest_hash)) if report_hash == manifest_hash => {}
        (Some(report_hash), Some(manifest_hash)) => failures.push(format!(
            "benchmark report dataset hash mismatch benchmark={report_hash} manifest={manifest_hash}"
        )),
        _ => failures.push("benchmark report is missing candidate dataset hash".to_string()),
    }
    gate(
        "benchmark_model_match",
        failures.is_empty(),
        if failures.is_empty() {
            "benchmark report matches candidate model and dataset hashes".to_string()
        } else {
            failures.join("; ")
        },
    )
}
