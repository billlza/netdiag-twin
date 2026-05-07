use crate::error::{IoContext, NetdiagError, Result};
use crate::ingest::build_ingest_result;
use crate::ml::FEATURES;
use crate::models::{FaultLabel, TraceRecord};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetManifest {
    pub schema: String,
    pub dataset_id: String,
    pub hash_sha256: String,
    pub rows: usize,
    pub label_distribution: BTreeMap<String, usize>,
    #[serde(default)]
    pub sources: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub failures: Vec<String>,
    #[serde(default)]
    pub label_distribution: BTreeMap<String, usize>,
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
    pub train: DatasetPartition,
    pub validation: DatasetPartition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test: Option<DatasetPartition>,
    pub manifest: DatasetManifest,
    pub manifest_path: String,
}

#[derive(Debug, Clone)]
struct DatasetRow {
    line_number: usize,
    line: String,
    label: FaultLabel,
}

pub fn inspect_dataset_jsonl(path: impl AsRef<Path>) -> Result<DatasetInspection> {
    let path = path.as_ref();
    let rows = read_dataset_rows(path)?;
    let manifest = DatasetManifest {
        schema: "netdiag-dataset/v1".to_string(),
        dataset_id: dataset_id(path),
        hash_sha256: sha256_file(path)?,
        rows: rows.len(),
        label_distribution: label_distribution(&rows),
        sources: vec![path.display().to_string()],
        created_at: Utc::now(),
        notes: None,
    };
    Ok(DatasetInspection {
        manifest,
        path: path.display().to_string(),
    })
}

pub fn validate_dataset_jsonl(path: impl AsRef<Path>) -> Result<DatasetValidationReport> {
    let path = path.as_ref();
    let mut failures = Vec::new();
    let rows = match read_dataset_rows(path) {
        Ok(rows) => rows,
        Err(err) => {
            failures.push(err.to_string());
            Vec::new()
        }
    };
    let hash_sha256 = sha256_file(path).unwrap_or_default();
    if rows.is_empty() && failures.is_empty() {
        failures.push("dataset contains no rows".to_string());
    }
    Ok(DatasetValidationReport {
        path: path.display().to_string(),
        hash_sha256,
        rows: rows.len(),
        passed: failures.is_empty(),
        failures,
        label_distribution: label_distribution(&rows),
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
    let rows = read_dataset_rows(input)?;
    if rows.len() < 2 {
        return Err(NetdiagError::Ml(
            "dataset split needs at least two rows".to_string(),
        ));
    }
    std::fs::create_dir_all(output_dir).with_path(output_dir)?;

    let validation_ratio = clean_ratio(validation_ratio);
    let test_ratio = clean_ratio(test_ratio).min((0.9 - validation_ratio).max(0.0));
    let (train_rows, validation_rows, test_rows) =
        partition_rows(&rows, stratified, seed, validation_ratio, test_ratio);
    if train_rows.is_empty() {
        return Err(NetdiagError::Ml(
            "dataset split would leave no training rows".to_string(),
        ));
    }

    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("dataset");
    let train_path = output_dir.join(format!("{stem}-train.jsonl"));
    let validation_path = output_dir.join(format!("{stem}-validation.jsonl"));
    let test_path = output_dir.join(format!("{stem}-test.jsonl"));
    write_jsonl_lines(&train_path, &train_rows)?;
    write_jsonl_lines(&validation_path, &validation_rows)?;
    if !test_rows.is_empty() {
        write_jsonl_lines(&test_path, &test_rows)?;
    }

    let train = partition_report(&train_path, &train_rows)?;
    let validation = partition_report(&validation_path, &validation_rows)?;
    let test = (!test_rows.is_empty())
        .then(|| partition_report(&test_path, &test_rows))
        .transpose()?;
    let manifest = DatasetManifest {
        schema: "netdiag-dataset/v1".to_string(),
        dataset_id: dataset_id(input),
        hash_sha256: sha256_file(input)?,
        rows: rows.len(),
        label_distribution: label_distribution(&rows),
        sources: vec![
            "input_jsonl".to_string(),
            input.display().to_string(),
            format!("split_seed:{seed}"),
        ],
        created_at: Utc::now(),
        notes: Some("Deterministic split manifest generated by netdiag dataset split".to_string()),
    };
    let manifest_path = output_dir.join("dataset_manifest.json");
    crate::storage::save_json(&manifest_path, &manifest)?;

    Ok(DatasetSplitReport {
        input: input.display().to_string(),
        output_dir: output_dir.display().to_string(),
        seed,
        stratified,
        validation_ratio,
        test_ratio,
        train,
        validation,
        test,
        manifest,
        manifest_path: manifest_path.display().to_string(),
    })
}

fn read_dataset_rows(path: &Path) -> Result<Vec<DatasetRow>> {
    let file = File::open(path).with_path(path)?;
    let reader = BufReader::new(file);
    let mut rows = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_path(path)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(trimmed).map_err(|err| {
            NetdiagError::Ml(format!(
                "{} line {} is not valid JSON: {err}",
                path.display(),
                idx + 1
            ))
        })?;
        let label = row_label(path, idx + 1, &value)?;
        validate_row_payload(path, idx + 1, &value)?;
        rows.push(DatasetRow {
            line_number: idx + 1,
            line: trimmed.to_string(),
            label,
        });
    }
    if rows.is_empty() {
        return Err(NetdiagError::Ml(format!(
            "dataset {} contains no rows",
            path.display()
        )));
    }
    Ok(rows)
}

fn row_label(path: &Path, line_number: usize, value: &serde_json::Value) -> Result<FaultLabel> {
    let label = value
        .get("label")
        .or_else(|| value.get("final_label"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            NetdiagError::Ml(format!(
                "{} line {} is missing label or final_label",
                path.display(),
                line_number
            ))
        })?;
    FaultLabel::from_str(label).map_err(|_| {
        NetdiagError::Ml(format!(
            "{} line {} has unknown label {label}",
            path.display(),
            line_number
        ))
    })
}

fn validate_row_payload(path: &Path, line_number: usize, value: &serde_json::Value) -> Result<()> {
    let records = value.get("records");
    let features = value.get("features").and_then(serde_json::Value::as_object);
    if let Some(records) = records {
        let records =
            serde_json::from_value::<Vec<TraceRecord>>(records.clone()).map_err(|err| {
                NetdiagError::Ml(format!(
                    "{} line {} records are not valid TraceRecord[]: {err}",
                    path.display(),
                    line_number
                ))
            })?;
        build_ingest_result(records, format!("{}:line-{line_number}", path.display())).map_err(
            |err| {
                NetdiagError::Ml(format!(
                    "{} line {} records failed canonical validation: {err}",
                    path.display(),
                    line_number
                ))
            },
        )?;
        return Ok(());
    }
    let Some(features) = features else {
        return Err(NetdiagError::Ml(format!(
            "{} line {} must include non-empty records or features",
            path.display(),
            line_number
        )));
    };
    for feature in FEATURES {
        let Some(value) = features.get(feature).and_then(serde_json::Value::as_f64) else {
            return Err(NetdiagError::Ml(format!(
                "{} line {} feature map is missing numeric {feature}",
                path.display(),
                line_number
            )));
        };
        if !value.is_finite() {
            return Err(NetdiagError::Ml(format!(
                "{} line {} feature {feature} is not finite",
                path.display(),
                line_number
            )));
        }
    }
    Ok(())
}

fn partition_rows(
    rows: &[DatasetRow],
    stratified: bool,
    seed: u64,
    validation_ratio: f64,
    test_ratio: f64,
) -> (Vec<DatasetRow>, Vec<DatasetRow>, Vec<DatasetRow>) {
    if stratified {
        let mut train = Vec::new();
        let mut validation = Vec::new();
        let mut test = Vec::new();
        for label in FaultLabel::ALL {
            let bucket = rows
                .iter()
                .filter(|row| row.label == label)
                .cloned()
                .collect::<Vec<_>>();
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
        partition_ordered(
            order_rows(rows.to_vec(), seed),
            validation_ratio,
            test_ratio,
        )
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
    (
        rows[..validation_start].to_vec(),
        rows[validation_start..test_start].to_vec(),
        rows[test_start..].to_vec(),
    )
}

fn order_rows(mut rows: Vec<DatasetRow>, seed: u64) -> Vec<DatasetRow> {
    rows.sort_by_key(|row| seeded_row_key(seed, row));
    rows
}

fn seeded_row_key(seed: u64, row: &DatasetRow) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(row.line_number.to_le_bytes());
    hasher.update(row.label.as_str().as_bytes());
    hasher.update(row.line.as_bytes());
    hasher.finalize().to_vec()
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

fn clean_ratio(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 0.8)
    } else {
        0.0
    }
}

fn write_jsonl_lines(path: &Path, rows: &[DatasetRow]) -> Result<()> {
    let tmp_path = temp_path(path);
    let write_result = (|| -> Result<()> {
        let file = File::create(&tmp_path).with_path(&tmp_path)?;
        let mut writer = BufWriter::new(file);
        for row in rows {
            writer.write_all(row.line.as_bytes()).with_path(&tmp_path)?;
            writer.write_all(b"\n").with_path(&tmp_path)?;
        }
        writer.flush().with_path(&tmp_path)?;
        writer.get_ref().sync_all().with_path(&tmp_path)?;
        Ok(())
    })();
    if let Err(err) = write_result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err);
    }
    std::fs::rename(&tmp_path, path).with_path(path)?;
    Ok(())
}

fn partition_report(path: &Path, rows: &[DatasetRow]) -> Result<DatasetPartition> {
    Ok(DatasetPartition {
        path: path.display().to_string(),
        rows: rows.len(),
        hash_sha256: sha256_file(path)?,
        label_distribution: label_distribution(rows),
    })
}

fn label_distribution(rows: &[DatasetRow]) -> BTreeMap<String, usize> {
    let mut labels = BTreeMap::new();
    for row in rows {
        *labels.entry(row.label.as_str().to_string()).or_default() += 1;
    }
    labels
}

fn dataset_id(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("dataset")
        .replace('_', "-")
}

fn temp_path(path: &Path) -> PathBuf {
    path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or("jsonl")
    ))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_path(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer).with_path(path)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_validate_rejects_malformed_records_payload() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dataset = temp.path().join("feedback.jsonl");
        std::fs::write(
            &dataset,
            serde_json::json!({
                "label": "normal",
                "records": [
                    {
                        "timestamp": "not-a-timestamp",
                        "latency_ms": -1.0,
                        "jitter_ms": 1.0,
                        "packet_loss_rate": 0.0,
                        "retransmission_rate": 0.0,
                        "timeout_events": 0.0,
                        "retry_events": 0.0,
                        "throughput_mbps": 100.0,
                        "dns_failure_events": 0.0,
                        "tls_failure_events": 0.0,
                        "quic_blocked_ratio": 0.0
                    }
                ]
            })
            .to_string(),
        )
        .expect("write dataset");

        let report = validate_dataset_jsonl(&dataset).expect("validation report");

        assert!(!report.passed);
        assert!(
            report
                .failures
                .iter()
                .any(|failure| failure.contains("records are not valid TraceRecord[]")),
            "{:?}",
            report.failures
        );
    }
}
