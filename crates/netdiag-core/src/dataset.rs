use crate::error::{NetdiagError, Result};
use crate::identifiers::validate_portable_id;
use crate::models::FaultLabel;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

mod input_snapshot;
mod limits;
mod migration;
mod registration;
mod registration_snapshot;
mod row_reader;
mod rows;
mod split_publication;
mod training;
mod trusted_root;

pub(crate) use migration::validate_legacy_artifacts;
pub(crate) use training::prepare as prepare_training_dataset;

use input_snapshot::DatasetInputSnapshot;
use rows::{
    DatasetRow, DatasetSummary, label_distribution, read_dataset_rows_from_reader,
    read_dataset_summary_from_reader, summarize_rows,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatasetManifest {
    pub schema: String,
    pub dataset_id: String,
    pub hash_sha256: String,
    pub rows: usize,
    pub label_distribution: BTreeMap<String, usize>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub source_runs: Vec<String>,
    #[serde(default)]
    pub scenario_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_rows_per_label: Option<usize>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DatasetManifestMetadata {
    pub dataset_id: Option<String>,
    pub sources: Vec<String>,
    pub source_runs: Vec<String>,
    pub scenario_ids: Vec<String>,
    pub operator: Option<String>,
    pub label_policy: Option<String>,
    pub min_rows_per_label: Option<usize>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetInspection {
    pub manifest: DatasetManifest,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetValidationReport {
    pub path: String,
    pub hash_sha256: String,
    pub rows: usize,
    pub passed: bool,
    #[serde(default)]
    pub min_rows_per_label: usize,
    #[serde(default)]
    pub failures: Vec<String>,
    #[serde(default)]
    pub label_distribution: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DatasetValidationOptions {
    pub min_rows_per_label: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetPartition {
    pub path: String,
    pub rows: usize,
    pub hash_sha256: String,
    #[serde(default)]
    pub label_distribution: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSplitReport {
    pub input: String,
    pub output_dir: String,
    pub seed: u64,
    pub stratified: bool,
    pub validation_ratio: f64,
    pub test_ratio: f64,
    #[serde(default)]
    pub split_warnings: Vec<String>,
    pub train: DatasetPartition,
    pub validation: DatasetPartition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<DatasetPartition>,
    pub manifest: DatasetManifest,
    pub manifest_path: String,
}

#[derive(Debug, Clone)]
pub struct DatasetRegisterOptions {
    pub artifacts: PathBuf,
    pub metadata: DatasetManifestMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRegistration {
    pub schema: String,
    pub registered_at: DateTime<Utc>,
    pub dataset_path: String,
    pub manifest_path: String,
    pub registry_path: String,
    pub manifest: DatasetManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRegistry {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    #[serde(default)]
    pub datasets: Vec<DatasetRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetRegistryEntry {
    pub dataset_id: String,
    pub hash_sha256: String,
    pub rows: usize,
    pub label_distribution: BTreeMap<String, usize>,
    pub dataset_path: String,
    pub manifest_path: String,
    pub registered_at: DateTime<Utc>,
    #[serde(default)]
    pub source_runs: Vec<String>,
    #[serde(default)]
    pub scenario_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_rows_per_label: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetComparison {
    pub schema: String,
    pub left: DatasetManifest,
    pub right: DatasetManifest,
    pub same_hash: bool,
    pub row_delta: isize,
    #[serde(default)]
    pub label_delta: BTreeMap<String, isize>,
    #[serde(default)]
    pub source_runs_added: Vec<String>,
    #[serde(default)]
    pub source_runs_removed: Vec<String>,
    #[serde(default)]
    pub scenario_ids_added: Vec<String>,
    #[serde(default)]
    pub scenario_ids_removed: Vec<String>,
}

pub fn inspect_dataset_jsonl(path: impl AsRef<Path>) -> Result<DatasetInspection> {
    let path = path.as_ref();
    let metadata = DatasetManifestMetadata::default();
    let dataset_id = manifest_dataset_id(path, &metadata)?;
    let snapshot = DatasetInputSnapshot::capture(path)?;
    let hash_sha256 = snapshot.hash_sha256().to_string();
    let summary_result = snapshot.read(|reader| read_dataset_summary_from_reader(path, reader));
    let summary = snapshot.finish(summary_result)?;
    let manifest =
        manifest_for_summary_with_identity(path, summary, metadata, dataset_id, hash_sha256);
    Ok(DatasetInspection {
        manifest,
        path: path.display().to_string(),
    })
}

pub fn validate_dataset_jsonl(path: impl AsRef<Path>) -> Result<DatasetValidationReport> {
    validate_dataset_jsonl_with_options(path, DatasetValidationOptions::default())
}

pub fn validate_dataset_jsonl_with_options(
    path: impl AsRef<Path>,
    options: DatasetValidationOptions,
) -> Result<DatasetValidationReport> {
    let path = path.as_ref();
    let snapshot = DatasetInputSnapshot::capture(path)?;
    let hash_sha256 = snapshot.hash_sha256().to_string();
    let summary_result = snapshot.read(|reader| read_dataset_summary_from_reader(path, reader));
    let summary_result = snapshot.finish(summary_result);
    let mut failures = Vec::new();
    let summary = match summary_result {
        Ok(summary) => summary,
        Err(NetdiagError::Ml(detail)) => {
            failures.push(detail);
            DatasetSummary::default()
        }
        Err(error) => return Err(error),
    };
    if summary.rows == 0 && failures.is_empty() {
        failures.push("dataset contains no rows".to_string());
    }
    if options.min_rows_per_label > 0 {
        for label in FaultLabel::ALL {
            let count = summary
                .label_distribution
                .get(label.as_str())
                .copied()
                .unwrap_or_default();
            if count < options.min_rows_per_label {
                failures.push(format!(
                    "label {} has {} rows, below required {}",
                    label.as_str(),
                    count,
                    options.min_rows_per_label
                ));
            }
        }
    }
    Ok(DatasetValidationReport {
        path: path.display().to_string(),
        hash_sha256,
        rows: summary.rows,
        passed: failures.is_empty(),
        min_rows_per_label: options.min_rows_per_label,
        failures,
        label_distribution: summary.label_distribution,
    })
}

pub fn split_dataset_jsonl(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    stratified: bool,
    seed: u64,
    validation_ratio: f64,
    test_ratio: f64,
) -> Result<DatasetSplitReport> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    validate_split_ratios(validation_ratio, test_ratio)?;
    ensure_publication_supported(output_dir)?;
    let snapshot = DatasetInputSnapshot::capture(input)?;
    let hash_sha256 = snapshot.hash_sha256().to_string();
    let rows_result = snapshot.read(|reader| read_dataset_rows_from_reader(input, reader));
    let rows = snapshot.finish(rows_result)?;
    if rows.len() < 2 {
        return Err(NetdiagError::Ml(
            "dataset split needs at least two rows".to_string(),
        ));
    }
    let input_summary = summarize_rows(&rows);
    let (train_rows, validation_rows, test_rows) =
        partition_rows(rows, stratified, seed, validation_ratio, test_ratio);
    if train_rows.is_empty() {
        return Err(NetdiagError::Ml(
            "dataset split would leave no training rows".to_string(),
        ));
    }
    let split_warnings = split_warnings(
        &input_summary.label_distribution,
        &validation_rows,
        &test_rows,
        stratified,
        validation_ratio,
        test_ratio,
    );

    let dataset_id = dataset_id(input);
    validate_portable_id("dataset id", &dataset_id)?;
    let manifest = DatasetManifest {
        schema: "netdiag-dataset/v1".to_string(),
        dataset_id,
        hash_sha256,
        rows: input_summary.rows,
        label_distribution: input_summary.label_distribution,
        sources: vec![
            "input_jsonl".to_string(),
            input.display().to_string(),
            format!("split_seed:{seed}"),
        ],
        source_runs: Vec::new(),
        scenario_ids: Vec::new(),
        operator: None,
        label_policy: None,
        min_rows_per_label: None,
        created_at: Utc::now(),
        notes: Some("Deterministic split manifest generated by netdiag dataset split".to_string()),
    };
    let published = split_publication::publish(
        output_dir,
        &manifest.dataset_id,
        &train_rows,
        &validation_rows,
        &test_rows,
        &manifest,
        split_publication::SplitRequest {
            seed,
            stratified,
            validation_ratio,
            test_ratio,
        },
    )?;

    Ok(DatasetSplitReport {
        input: input.display().to_string(),
        output_dir: published.output_dir,
        seed,
        stratified,
        validation_ratio,
        test_ratio,
        split_warnings,
        train: published.train,
        validation: published.validation,
        test: published.test,
        manifest: published.manifest,
        manifest_path: published.manifest_path.display().to_string(),
    })
}

pub fn register_dataset_jsonl(
    dataset: impl AsRef<Path>,
    options: DatasetRegisterOptions,
) -> Result<DatasetRegistration> {
    registration::register(dataset.as_ref(), options)
}

fn ensure_publication_supported(path: &Path) -> Result<()> {
    validate_publication_support(path, cfg!(unix))
}

fn validate_publication_support(path: &Path, supported: bool) -> Result<()> {
    if supported {
        Ok(())
    } else {
        Err(NetdiagError::AtomicPublish {
            path: path.to_path_buf(),
            phase: crate::error::AtomicPublishPhase::NotPublished,
            source: Box::new(NetdiagError::InvalidTrace(
                "dataset publication is disabled on platforms where durable directory creation and parent-directory flush are unavailable"
                    .to_string(),
            )),
        })
    }
}

pub fn compare_datasets(
    left: impl AsRef<Path>,
    right: impl AsRef<Path>,
) -> Result<DatasetComparison> {
    let left = dataset_manifest_or_inspect(left.as_ref())?;
    let right = dataset_manifest_or_inspect(right.as_ref())?;
    let labels = left
        .label_distribution
        .keys()
        .chain(right.label_distribution.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let label_delta = labels
        .into_iter()
        .map(|label| {
            let right_count = right
                .label_distribution
                .get(&label)
                .copied()
                .unwrap_or_default();
            let left_count = left
                .label_distribution
                .get(&label)
                .copied()
                .unwrap_or_default();
            (label, right_count as isize - left_count as isize)
        })
        .filter(|(_, delta)| *delta != 0)
        .collect::<BTreeMap<_, _>>();
    Ok(DatasetComparison {
        schema: "netdiag-dataset-comparison/v1".to_string(),
        same_hash: left.hash_sha256 == right.hash_sha256,
        row_delta: right.rows as isize - left.rows as isize,
        source_runs_added: string_set_difference(&right.source_runs, &left.source_runs),
        source_runs_removed: string_set_difference(&left.source_runs, &right.source_runs),
        scenario_ids_added: string_set_difference(&right.scenario_ids, &left.scenario_ids),
        scenario_ids_removed: string_set_difference(&left.scenario_ids, &right.scenario_ids),
        left,
        right,
        label_delta,
    })
}

fn manifest_dataset_id(path: &Path, metadata: &DatasetManifestMetadata) -> Result<String> {
    let dataset_id = metadata
        .dataset_id
        .clone()
        .unwrap_or_else(|| dataset_id(path))
        .replace('_', "-");
    validate_portable_id("dataset id", &dataset_id)?;
    Ok(dataset_id)
}

fn manifest_for_summary_with_identity(
    path: &Path,
    summary: DatasetSummary,
    mut metadata: DatasetManifestMetadata,
    dataset_id: String,
    hash_sha256: String,
) -> DatasetManifest {
    if metadata.sources.is_empty() {
        metadata.sources.push(path.display().to_string());
    }
    DatasetManifest {
        schema: "netdiag-dataset/v1".to_string(),
        dataset_id,
        hash_sha256,
        rows: summary.rows,
        label_distribution: summary.label_distribution,
        sources: metadata.sources,
        source_runs: metadata.source_runs,
        scenario_ids: metadata.scenario_ids,
        operator: metadata.operator,
        label_policy: metadata.label_policy,
        min_rows_per_label: metadata.min_rows_per_label,
        created_at: Utc::now(),
        notes: metadata.notes,
    }
}

#[cfg(test)]
fn read_dataset_registry(path: &Path) -> Result<DatasetRegistry> {
    let registry = crate::storage::typed_json::read_optional_stable_json_bounded::<DatasetRegistry>(
        path,
        crate::storage::typed_json::MAX_DATASET_REGISTRY_BYTES,
        "dataset registry",
    )?;
    validate_dataset_registry(registry)
}

fn read_dataset_registry_at(
    target: &crate::storage::BoundAtomicFileTarget,
) -> Result<DatasetRegistry> {
    let registry =
        crate::storage::typed_json::read_optional_stable_json_bounded_at::<DatasetRegistry>(
            target,
            crate::storage::typed_json::MAX_DATASET_REGISTRY_BYTES,
            "dataset registry",
        )?;
    validate_dataset_registry(registry)
}

fn validate_dataset_registry(registry: Option<DatasetRegistry>) -> Result<DatasetRegistry> {
    let Some(registry) = registry else {
        return Ok(DatasetRegistry {
            schema: "netdiag-dataset-registry/v1".to_string(),
            generated_at: Utc::now(),
            datasets: Vec::new(),
        });
    };
    crate::storage::typed_json::ensure_collection_limit(
        "dataset registry",
        registry.datasets.len(),
        crate::storage::typed_json::MAX_DATASET_REGISTRY_ENTRIES,
    )?;
    if registry.schema != "netdiag-dataset-registry/v1" {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported dataset registry schema: {}",
            registry.schema
        )));
    }
    Ok(registry)
}

fn dataset_manifest_or_inspect(path: &Path) -> Result<DatasetManifest> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("jsonl") => Ok(inspect_dataset_jsonl(path)?.manifest),
        Some("json") => {
            let manifest =
                crate::storage::typed_json::read_required_stable_json_bounded::<DatasetManifest>(
                    path,
                    crate::storage::typed_json::MAX_DATASET_MANIFEST_BYTES,
                    "dataset manifest",
                )?;
            if manifest.schema != "netdiag-dataset/v1" {
                return Err(NetdiagError::InvalidTrace(format!(
                    "unsupported dataset manifest schema {} at {}",
                    manifest.schema,
                    path.display()
                )));
            }
            Ok(manifest)
        }
        _ => Err(NetdiagError::InvalidTrace(format!(
            "dataset comparison input must use .jsonl data or a .json manifest: {}",
            path.display()
        ))),
    }
}

fn string_set_difference(left: &[String], right: &[String]) -> Vec<String> {
    left.iter()
        .filter(|value| !right.iter().any(|existing| existing == *value))
        .cloned()
        .collect()
}

fn partition_rows(
    rows: Vec<DatasetRow>,
    stratified: bool,
    seed: u64,
    validation_ratio: f64,
    test_ratio: f64,
) -> (Vec<DatasetRow>, Vec<DatasetRow>, Vec<DatasetRow>) {
    if stratified {
        let mut train = Vec::new();
        let mut validation = Vec::new();
        let mut test = Vec::new();
        let mut buckets = BTreeMap::<FaultLabel, Vec<DatasetRow>>::new();
        for row in rows {
            buckets.entry(row.label).or_default().push(row);
        }
        for label in FaultLabel::ALL {
            let bucket = buckets.remove(&label).unwrap_or_default();
            let (bucket_train, bucket_validation, bucket_test) =
                partition_ordered(order_rows(bucket, seed), validation_ratio, test_ratio);
            train.extend(bucket_train);
            validation.extend(bucket_validation);
            test.extend(bucket_test);
        }
        sort_by_original_line(&mut train);
        sort_by_original_line(&mut validation);
        sort_by_original_line(&mut test);
        (train, validation, test)
    } else {
        partition_ordered(order_rows(rows, seed), validation_ratio, test_ratio)
    }
}

fn partition_ordered(
    rows: Vec<DatasetRow>,
    validation_ratio: f64,
    test_ratio: f64,
) -> (Vec<DatasetRow>, Vec<DatasetRow>, Vec<DatasetRow>) {
    if rows.len() < 2 {
        return (rows, Vec::new(), Vec::new());
    }
    let mut test_count = ratio_count(rows.len(), test_ratio);
    let mut validation_count = ratio_count(rows.len(), validation_ratio);
    while rows.len().saturating_sub(test_count + validation_count) == 0 {
        if test_count > 0 {
            test_count -= 1;
        } else if validation_count > 0 {
            validation_count -= 1;
        } else {
            break;
        }
    }
    let validation_start = rows.len().saturating_sub(test_count + validation_count);
    let test_start = rows.len().saturating_sub(test_count);
    let mut train = rows;
    let test = train.split_off(test_start);
    let validation = train.split_off(validation_start);
    (train, validation, test)
}

fn order_rows(mut rows: Vec<DatasetRow>, seed: u64) -> Vec<DatasetRow> {
    rows.sort_by_cached_key(|row| seeded_row_key(seed, row));
    rows
}

fn seeded_row_key(seed: u64, row: &DatasetRow) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(row.line_number.to_le_bytes());
    hasher.update(row.label.as_str().as_bytes());
    hasher.update(row.line.as_bytes());
    hasher.finalize().into()
}

fn sort_by_original_line(rows: &mut [DatasetRow]) {
    rows.sort_by_key(|row| row.line_number);
}

fn ratio_count(len: usize, ratio: f64) -> usize {
    if len < 2 || ratio <= 0.0 {
        0
    } else {
        ((len as f64) * ratio).round() as usize
    }
}

fn validate_split_ratios(validation_ratio: f64, test_ratio: f64) -> Result<()> {
    for (name, ratio) in [
        ("validation_ratio", validation_ratio),
        ("test_ratio", test_ratio),
    ] {
        if !ratio.is_finite() || !(0.0..1.0).contains(&ratio) {
            return Err(NetdiagError::Ml(format!(
                "dataset split {name} must be finite and in [0, 1), got {ratio}"
            )));
        }
    }
    if validation_ratio + test_ratio >= 1.0 {
        return Err(NetdiagError::Ml(format!(
            "dataset split validation_ratio + test_ratio must be less than 1, got {}",
            validation_ratio + test_ratio
        )));
    }
    Ok(())
}

fn split_warnings(
    input_distribution: &BTreeMap<String, usize>,
    validation_rows: &[DatasetRow],
    test_rows: &[DatasetRow],
    stratified: bool,
    validation_ratio: f64,
    test_ratio: f64,
) -> Vec<String> {
    if !stratified {
        return Vec::new();
    }
    let validation_distribution = label_distribution(validation_rows);
    let test_distribution = label_distribution(test_rows);
    let mut warnings = Vec::new();
    for (label, count) in input_distribution {
        if validation_ratio > 0.0 {
            match validation_distribution
                .get(label)
                .copied()
                .unwrap_or_default()
            {
                0 => warnings.push(format!(
                    "label {label} has only {count} row(s); validation set has no {label} examples"
                )),
                1 => warnings.push(format!(
                    "label {label} validation set has only 1 example; evaluation will be noisy"
                )),
                _ => {}
            }
        }
        if test_ratio > 0.0 {
            match test_distribution.get(label).copied().unwrap_or_default() {
                0 => warnings.push(format!(
                    "label {label} has only {count} row(s); test set has no {label} examples"
                )),
                1 => warnings.push(format!(
                    "label {label} test set has only 1 example; test metrics will be noisy"
                )),
                _ => {}
            }
        }
    }
    warnings
}

fn dataset_id(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("dataset")
        .replace('_', "-")
}

#[cfg(test)]
mod tests;
