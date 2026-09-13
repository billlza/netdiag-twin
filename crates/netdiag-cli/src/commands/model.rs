use anyhow::Context;
use clap::{Args, Subcommand};
use netdiag_core::ml::{
    MODEL_CURRENT_FILE_NAME, MODEL_MANIFEST_FILE_NAME, load_existing_model_bundle_identity,
};
use netdiag_core::models::ModelManifest;
use std::path::{Path, PathBuf};

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

pub(crate) fn training_output(
    dataset: &Path,
    model_dir: &Path,
    manifest: ModelManifest,
) -> anyhow::Result<serde_json::Value> {
    let identity = load_existing_model_bundle_identity(model_dir)
        .context("trained model generation could not be revalidated")?;
    Ok(serde_json::json!({
        "status": "trained",
        "dataset": dataset,
        "model_dir": model_dir,
        "model_file": manifest.model_file,
        "manifest_file": MODEL_MANIFEST_FILE_NAME,
        "current_descriptor": MODEL_CURRENT_FILE_NAME,
        "generation": identity.generation,
        "model_file_hash_sha256": identity.model_file_hash_sha256,
        "model_manifest_hash_sha256": identity.model_manifest_hash_sha256,
        "labels": manifest.labels,
        "training_examples": manifest.training_examples,
        "dataset_hash_sha256": manifest.dataset_hash_sha256,
        "training_config": manifest.training_config,
        "training_gate": manifest.training_gate,
        "evaluation": manifest.evaluation,
        "uncertainty_thresholds": manifest.uncertainty_thresholds,
    }))
}
