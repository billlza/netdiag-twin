use crate::error::{NetdiagError, Result};
use crate::storage::{PathStatus, path_status};
use std::path::Path;

mod run_anchor;

pub fn migrate_legacy_artifact_root(path: impl AsRef<Path>) -> Result<()> {
    crate::storage::migrate_legacy_artifact_root_with_validator(path, validate_product_artifacts)
}

fn validate_product_artifacts(directory: &netdiag_platform::TrustedDirectory) -> Result<()> {
    let root = directory.resolved_path();
    let mut verified_anchor = false;

    if path_status(&root.join("model"))? == PathStatus::Directory {
        verified_anchor |=
            crate::ml::validate_model_bundle_for_artifact_root_migration(&root.join("model"))?;
    }
    verified_anchor |= run_anchor::validate(root)?;
    if path_status(&root.join("lab_run_index.json"))? == PathStatus::RegularFile {
        let index = crate::lab::read_lab_run_index(root)?.ok_or_else(|| {
            NetdiagError::InvalidTrace(
                "legacy lab run index disappeared during validation".to_string(),
            )
        })?;
        verified_anchor |= crate::lab::validate_legacy_run_index_artifacts(root, &index)?;
    }
    if path_status(&root.join("lab_calibration_report.json"))? == PathStatus::RegularFile {
        let report: crate::lab::LabCalibrationReport =
            crate::storage::typed_json::read_required_stable_json_bounded(
                &root.join("lab_calibration_report.json"),
                crate::storage::typed_json::MAX_GENERIC_JSON_BYTES,
                "legacy lab calibration report",
            )?;
        if report.schema != "netdiag-lab-calibration/v2"
            || !is_lowercase_sha256(&report.source_model_manifest_hash_sha256)
        {
            return Err(NetdiagError::InvalidTrace(
                "legacy lab calibration report has an unsupported schema or source model identity"
                    .to_string(),
            ));
        }
        verified_anchor = true;
    }
    if path_status(&root.join("datasets"))? == PathStatus::Directory {
        verified_anchor |= crate::dataset::validate_legacy_artifacts(&root.join("datasets"))?;
    }
    if !verified_anchor {
        return Err(NetdiagError::InvalidTrace(format!(
            "legacy artifact root has no verifiable product artifact and cannot be claimed: {}",
            root.display()
        )));
    }
    directory
        .validate_identity()
        .map_err(|source| NetdiagError::FilesystemTrust {
            context: "legacy artifact root migration",
            source,
        })
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
