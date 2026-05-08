use anyhow::Context;
use clap::Subcommand;
use netdiag_core::pilot::{PilotOptions, preflight_pilot, run_pilot};
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
    }
    Ok(())
}
