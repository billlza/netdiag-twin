use anyhow::Context;
use clap::Subcommand;
use netdiag_core::reliability::{ReliabilityCheckOptions, check_reliability};
use std::path::PathBuf;

#[derive(Debug, Subcommand)]
pub enum ReliabilityCommand {
    Check {
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long)]
        run_id: Option<String>,
    },
}

pub fn run(command: ReliabilityCommand) -> anyhow::Result<()> {
    match command {
        ReliabilityCommand::Check { artifacts, run_id } => {
            let report = check_reliability(ReliabilityCheckOptions {
                artifact_root: artifacts.clone(),
                run_id,
            })
            .with_context(|| format!("reliability check failed for {}", artifacts.display()))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report.status == netdiag_core::models::ConnectorHealthStatus::Error {
                anyhow::bail!("reliability check failed");
            }
        }
    }
    Ok(())
}
