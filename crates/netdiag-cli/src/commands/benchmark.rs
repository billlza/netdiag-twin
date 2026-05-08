use anyhow::Context;
use clap::Subcommand;
use netdiag_core::benchmark::{BenchmarkOptions, run_benchmark};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum BenchmarkCommand {
    Run {
        #[arg(long, default_value = "target/benchmark-artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value = "target/benchmark-report")]
        output: PathBuf,
        #[arg(long)]
        suite: Option<String>,
    },
}

pub fn run(command: BenchmarkCommand) -> anyhow::Result<()> {
    match command {
        BenchmarkCommand::Run {
            artifacts,
            output,
            suite,
        } => {
            let report = run_benchmark(BenchmarkOptions {
                artifacts: artifacts.clone(),
                output: output.clone(),
                suite,
            })
            .with_context(|| {
                format!(
                    "benchmark run failed with artifacts {} and output {}",
                    artifacts.display(),
                    output.display()
                )
            })?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.passed {
                anyhow::bail!("benchmark report failed");
            }
        }
    }
    Ok(())
}
