use netdiag_core::perf_budget::run_perf_measurements;
use netdiag_platform::TrustedTempDirectory;
use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args_os().any(|arg| arg == "--list") {
        return Ok(());
    }
    let measurements = match std::env::var_os("NETDIAG_PERF_ARTIFACTS") {
        Some(path) => run_perf_measurements(PathBuf::from(path))?,
        None => {
            let workspace = TrustedTempDirectory::create("netdiag-perf-bench-")?;
            let operation = run_perf_measurements(workspace.path());
            workspace.finish(operation)?
        }
    };
    println!("{}", serde_json::to_string_pretty(&measurements)?);
    Ok(())
}
