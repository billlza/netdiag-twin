use crate::error::Result;
use crate::ml::{
    ModelBundleSnapshot, TrainingOptions, load_existing_model_bundle_snapshot,
    train_model_from_jsonl_with_options,
};
use std::path::Path;

#[derive(Debug, Clone)]
pub(crate) struct CandidateModelIdentity {
    pub(crate) snapshot: ModelBundleSnapshot,
    pub(crate) model_manifest_hash_sha256: String,
    pub(crate) model_file_hash_sha256: String,
    pub(crate) dataset_hash_sha256: Option<String>,
}

pub(crate) fn candidate_model_identity(model_dir: &Path) -> Result<CandidateModelIdentity> {
    let snapshot = load_existing_model_bundle_snapshot(model_dir)?;
    Ok(CandidateModelIdentity {
        model_manifest_hash_sha256: snapshot.model_manifest_hash_sha256.clone(),
        model_file_hash_sha256: snapshot.model_file_hash_sha256.clone(),
        dataset_hash_sha256: snapshot.manifest.dataset_hash_sha256.clone(),
        snapshot,
    })
}

pub(crate) fn provision_benchmark_model(artifact_root: &Path) -> Result<ModelBundleSnapshot> {
    let dataset = super::repo_root().join("examples/datasets/pilot-smoke-training.jsonl");
    let model_dir = artifact_root.join("model");
    train_model_from_jsonl_with_options(
        &dataset,
        &model_dir,
        TrainingOptions {
            validation_split: 0.0,
            shuffle_seed: Some(2026),
            stratified: false,
            min_rows_per_label: 1,
        },
    )?;
    load_existing_model_bundle_snapshot(&model_dir)
}
