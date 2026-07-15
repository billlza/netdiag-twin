use super::{
    DatasetManifest, DatasetRegistry, inspect_dataset_jsonl, validate_dataset_jsonl,
    validate_dataset_registry,
};
use crate::error::{IoContext, NetdiagError, Result};
use crate::storage::{PathStatus, path_status, typed_json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

const LEGACY_FEEDBACK_NAME: &str = "lab-feedback.jsonl";
const REGISTRY_NAME: &str = "registry.json";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub(crate) fn validate_legacy_artifacts(root: &Path) -> Result<bool> {
    let registry = read_registry(root)?;
    let feedback = validate_legacy_feedback(root)?;
    if registry.is_none() && feedback.is_none() {
        return Err(NetdiagError::InvalidTrace(format!(
            "legacy datasets directory has neither a valid registry nor {LEGACY_FEEDBACK_NAME}: {}",
            root.display()
        )));
    }
    let dataset_ids = match registry.as_ref() {
        Some(registry) => validate_registered_datasets(root, registry)?,
        None => BTreeSet::new(),
    };
    validate_directory_entries(root, registry.is_some(), feedback.is_some(), &dataset_ids)?;
    Ok(registry
        .as_ref()
        .is_some_and(|registry| !registry.datasets.is_empty())
        || feedback == Some(true))
}

fn read_registry(root: &Path) -> Result<Option<DatasetRegistry>> {
    let path = root.join(REGISTRY_NAME);
    match path_status(&path)? {
        PathStatus::Missing => Ok(None),
        PathStatus::RegularFile => {
            let registry = typed_json::read_required_stable_json_bounded::<DatasetRegistry>(
                &path,
                typed_json::MAX_DATASET_REGISTRY_BYTES,
                "legacy dataset registry",
            )?;
            validate_dataset_registry(Some(registry)).map(Some)
        }
        _ => Err(NetdiagError::InvalidTrace(format!(
            "legacy dataset registry is not a regular file: {}",
            path.display()
        ))),
    }
}

fn validate_legacy_feedback(root: &Path) -> Result<Option<bool>> {
    let path = root.join(LEGACY_FEEDBACK_NAME);
    match path_status(&path)? {
        PathStatus::Missing => Ok(None),
        PathStatus::RegularFile => {
            let report = validate_dataset_jsonl(&path)?;
            if report.passed {
                return Ok(Some(true));
            }
            let empty_export = report.rows == 0
                && report.hash_sha256 == EMPTY_SHA256
                && report.failures.len() == 1
                && report.failures[0].contains("contains no rows");
            if !empty_export {
                return Err(NetdiagError::InvalidTrace(format!(
                    "legacy feedback dataset is invalid at {}: {}",
                    path.display(),
                    report.failures.join("; ")
                )));
            }
            Ok(Some(false))
        }
        _ => Err(NetdiagError::InvalidTrace(format!(
            "legacy feedback dataset is not a regular file: {}",
            path.display()
        ))),
    }
}

fn validate_registered_datasets(
    root: &Path,
    registry: &DatasetRegistry,
) -> Result<BTreeSet<String>> {
    let mut dataset_ids = BTreeSet::new();
    let mut case_insensitive_ids = BTreeMap::new();
    let mut hashes = BTreeSet::new();
    for entry in &registry.datasets {
        crate::identifiers::validate_portable_id("legacy dataset id", &entry.dataset_id)?;
        let folded_id = entry.dataset_id.to_ascii_lowercase();
        if let Some(existing) = case_insensitive_ids.insert(folded_id, &entry.dataset_id)
            && existing != &entry.dataset_id
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "legacy dataset registry contains a case-insensitive dataset id collision: {existing} and {}",
                entry.dataset_id
            )));
        }
        if !is_lowercase_sha256(&entry.hash_sha256) || !hashes.insert(&entry.hash_sha256) {
            return Err(NetdiagError::InvalidTrace(format!(
                "legacy dataset registry contains an invalid or duplicate hash for {}",
                entry.dataset_id
            )));
        }
        dataset_ids.insert(entry.dataset_id.clone());
        validate_registered_dataset(root, entry)?;
    }
    Ok(dataset_ids)
}

fn validate_registered_dataset(root: &Path, entry: &super::DatasetRegistryEntry) -> Result<()> {
    let directory = root.join(&entry.dataset_id);
    require_status(
        &directory,
        PathStatus::Directory,
        "registered dataset directory",
    )?;
    let prefix = &entry.hash_sha256[..12];
    let dataset = directory.join(format!("{prefix}.jsonl"));
    let manifest_path = directory.join(format!("{prefix}-manifest.json"));
    require_status(&dataset, PathStatus::RegularFile, "registered dataset")?;
    require_status(
        &manifest_path,
        PathStatus::RegularFile,
        "registered dataset manifest",
    )?;

    let inspection = inspect_dataset_jsonl(&dataset)?;
    let manifest = typed_json::read_required_stable_json_bounded::<DatasetManifest>(
        &manifest_path,
        typed_json::MAX_DATASET_MANIFEST_BYTES,
        "legacy dataset manifest",
    )?;
    if inspection.manifest.hash_sha256 != entry.hash_sha256
        || inspection.manifest.rows != entry.rows
        || inspection.manifest.label_distribution != entry.label_distribution
        || manifest.schema != "netdiag-dataset/v1"
        || manifest.dataset_id != entry.dataset_id
        || manifest.hash_sha256 != entry.hash_sha256
        || manifest.rows != entry.rows
        || manifest.label_distribution != entry.label_distribution
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "legacy registered dataset content, manifest, and registry disagree for {}",
            entry.dataset_id
        )));
    }
    Ok(())
}

fn validate_directory_entries(
    root: &Path,
    registry_present: bool,
    feedback_present: bool,
    dataset_ids: &BTreeSet<String>,
) -> Result<()> {
    for entry in fs::read_dir(root).with_path(root)? {
        let entry = entry.with_path(root)?;
        let name = entry.file_name().into_string().map_err(|_| {
            NetdiagError::InvalidTrace(format!(
                "legacy datasets directory contains a non-UTF-8 entry: {}",
                entry.path().display()
            ))
        })?;
        let expected = (registry_present && name == REGISTRY_NAME)
            || (feedback_present && name == LEGACY_FEEDBACK_NAME)
            || dataset_ids.contains(&name);
        if !expected {
            return Err(NetdiagError::InvalidTrace(format!(
                "legacy datasets directory contains an unsupported entry: {}",
                entry.path().display()
            )));
        }
        let expected_status = if dataset_ids.contains(&name) {
            PathStatus::Directory
        } else {
            PathStatus::RegularFile
        };
        require_status(&entry.path(), expected_status, "legacy dataset entry")?;
    }
    Ok(())
}

fn require_status(path: &Path, expected: PathStatus, description: &str) -> Result<()> {
    let actual = path_status(path)?;
    if actual != expected {
        return Err(NetdiagError::InvalidTrace(format!(
            "{description} has an invalid filesystem type at {}",
            path.display()
        )));
    }
    Ok(())
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
