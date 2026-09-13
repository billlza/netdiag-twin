use anyhow::Context;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(crate) struct ModelArgs {
    #[command(subcommand)]
    command: ModelCommand,
}

#[derive(Debug, Subcommand)]
enum ModelCommand {
    /// Migrate an existing model without retraining or changing its weights.
    Migrate {
        #[arg(long)]
        model_dir: PathBuf,
    },
}

pub(crate) fn run(args: ModelArgs) -> anyhow::Result<()> {
    let ModelCommand::Migrate { model_dir } = args.command;
    let output_path = model_dir
        .to_str()
        .context("model directory must be valid UTF-8")?;
    let identity = netdiag_core::ml::migrate_legacy_model_bundle(&model_dir)
        .with_context(|| format!("failed to migrate model bundle {}", model_dir.display()))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema": "netdiag-model-migration/v1",
            "model_dir": output_path,
            "generation": identity.generation,
            "model_file_hash_sha256": identity.model_file_hash_sha256,
            "model_manifest_hash_sha256": identity.model_manifest_hash_sha256,
            "manifest": identity.manifest,
        }))?
    );
    Ok(())
}
