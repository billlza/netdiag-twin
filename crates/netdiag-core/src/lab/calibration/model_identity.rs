use super::super::{LabAcceptanceReport, LabRunIndex, LabRunIndexEntry, read_lab_run_index};
use crate::error::{NetdiagError, Result};
use crate::ml::{
    ModelBundleSnapshot, load_existing_model_bundle_snapshot,
    replace_model_manifest_snapshot_if_current,
};
use crate::models::ModelManifest;
use std::path::Path;

pub(super) fn require_lab_run_index(artifact_root: &Path) -> Result<LabRunIndex> {
    read_lab_run_index(artifact_root)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "lab calibration requires {}, but no lab run index exists under {}",
            artifact_root.join("lab_run_index.json").display(),
            artifact_root.display()
        ))
    })
}

#[derive(Debug, Clone)]
pub(super) struct CalibrationModelIdentity {
    pub(super) source_manifest_hash_sha256: String,
    pub(super) model_file_hash_sha256: String,
    pub(super) dataset_hash_sha256: String,
    source_snapshot: ModelBundleSnapshot,
}

impl CalibrationModelIdentity {
    pub(super) fn load(model_dir: &Path) -> Result<(ModelManifest, Self)> {
        let source_snapshot = load_existing_model_bundle_snapshot(model_dir)?;
        let manifest = source_snapshot.manifest.clone();
        let dataset_hash_sha256 = manifest.dataset_hash_sha256.clone().ok_or_else(|| {
            NetdiagError::InvalidTrace(
                "lab calibration requires model manifest dataset_hash_sha256 to bind indexed evidence"
                    .to_string(),
            )
        })?;
        let identity = Self {
            source_manifest_hash_sha256: source_snapshot.model_manifest_hash_sha256.clone(),
            model_file_hash_sha256: source_snapshot.model_file_hash_sha256.clone(),
            dataset_hash_sha256,
            source_snapshot,
        };
        Ok((manifest, identity))
    }

    pub(super) fn ensure_source_bundle_unchanged(&self, model_dir: &Path) -> Result<()> {
        let current = load_existing_model_bundle_snapshot(model_dir)?;
        if self.source_snapshot.same_identity(&current) {
            Ok(())
        } else {
            Err(NetdiagError::InvalidTrace(
                "lab calibration model generation changed while calibration was running"
                    .to_string(),
            ))
        }
    }

    pub(super) fn source_manifest_path(&self) -> &Path {
        &self.source_snapshot.manifest_path
    }

    pub(super) fn publish_manifest(
        &self,
        model_dir: &Path,
        updated_manifest: &ModelManifest,
    ) -> Result<ModelBundleSnapshot> {
        replace_model_manifest_snapshot_if_current(
            model_dir,
            &self.source_manifest_hash_sha256,
            updated_manifest,
        )
    }

    pub(super) fn validate_acceptance(
        &self,
        entry: &LabRunIndexEntry,
        acceptance: &LabAcceptanceReport,
    ) -> Result<()> {
        validate_identity_field(
            entry,
            "model_dataset_hash",
            acceptance.model_dataset_hash.as_deref(),
            &self.dataset_hash_sha256,
        )?;
        validate_identity_field(
            entry,
            "model_manifest_hash",
            acceptance.model_manifest_hash.as_deref(),
            &self.source_manifest_hash_sha256,
        )?;
        validate_identity_field(
            entry,
            "model_file_hash",
            acceptance.model_file_hash.as_deref(),
            &self.model_file_hash_sha256,
        )
    }
}

fn validate_identity_field(
    entry: &LabRunIndexEntry,
    field: &str,
    actual: Option<&str>,
    expected: &str,
) -> Result<()> {
    match actual {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(NetdiagError::InvalidTrace(format!(
            "lab calibration indexed run {} {field} mismatch: acceptance={actual} source_model={expected}",
            entry.run_id
        ))),
        None => Err(NetdiagError::InvalidTrace(format!(
            "lab calibration indexed run {} is missing {field}",
            entry.run_id
        ))),
    }
}
