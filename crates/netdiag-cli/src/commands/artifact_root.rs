use anyhow::Context;
use clap::{Args, Subcommand};
use std::path::PathBuf;

mod output;

#[derive(Debug, Args)]
pub(crate) struct ArtifactRootArgs {
    #[command(subcommand)]
    command: ArtifactRootCommand,
}

#[derive(Debug, Subcommand)]
enum ArtifactRootCommand {
    /// Initialize a new empty artifact root or validate an existing owned root.
    Initialize {
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
    /// Validate and claim an artifact root created before v0.5.3.
    Migrate {
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
    },
}

pub(crate) fn run(args: ArtifactRootArgs) -> anyhow::Result<()> {
    let output = match &args.command {
        ArtifactRootCommand::Initialize { artifacts }
        | ArtifactRootCommand::Migrate { artifacts } => output::OwnedOutput::prepare(artifacts)?,
    };
    let (artifacts, result, action) = match args.command {
        ArtifactRootCommand::Initialize { artifacts } => {
            let result = netdiag_core::storage::ensure_artifact_root_owned(&artifacts);
            (artifacts, result, "initialize")
        }
        ArtifactRootCommand::Migrate { artifacts } => {
            let result = netdiag_core::migrate_legacy_artifact_root(&artifacts);
            (artifacts, result, "validate and migrate")
        }
    };
    result.with_context(|| format!("failed to {action} artifact root {}", artifacts.display()))?;
    output.write()
}
