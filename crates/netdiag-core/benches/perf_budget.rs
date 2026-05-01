use netdiag_core::perf_budget::run_perf_measurements;
use std::path::PathBuf;

fn main() {
    let artifact_root = std::env::var_os("NETDIAG_PERF_ARTIFACTS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/perf-bench-artifacts")
        });
    let measurements =
        run_perf_measurements(&artifact_root).expect("NetDiag performance measurements");
    println!(
        "{}",
        serde_json::to_string_pretty(&measurements).expect("serialize performance measurements")
    );
}
