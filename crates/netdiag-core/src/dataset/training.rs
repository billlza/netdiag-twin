use super::input_snapshot::DatasetInputSnapshot;
use super::row_reader;
use super::rows::{
    ValidatedDatasetPayload, ValidatedDatasetRow, parse_and_validate_row, projected_bytes,
};
use crate::error::{NetdiagError, Result};
use crate::feature_schema::FEATURES;
use crate::models::FaultLabel;
use crate::telemetry::{extract_features_from_windows, summarize_telemetry};
use std::io::BufRead;
use std::path::Path;

pub(crate) struct PreparedTrainingDataset {
    pub(crate) hash_sha256: String,
    pub(crate) rows: Vec<TrainingDatasetRow>,
}

pub(crate) struct TrainingDatasetRow {
    pub(crate) label: FaultLabel,
    pub(crate) features: Vec<f64>,
}

pub(crate) fn prepare(path: &Path) -> Result<PreparedTrainingDataset> {
    prepare_with_hook(path, || {})
}

fn prepare_with_hook(path: &Path, after_capture: impl FnOnce()) -> Result<PreparedTrainingDataset> {
    let snapshot = DatasetInputSnapshot::capture(path)?;
    let hash_sha256 = snapshot.hash_sha256().to_string();
    after_capture();
    let rows_result = snapshot.read(|reader| read_rows(path, reader));
    let rows = snapshot.finish(rows_result)?;
    Ok(PreparedTrainingDataset { hash_sha256, rows })
}

fn read_rows(path: &Path, reader: impl BufRead) -> Result<Vec<TrainingDatasetRow>> {
    let mut rows = Vec::new();
    let mut retained_bytes = 0_u64;
    row_reader::for_each_nonempty_line(path, reader, |line_number, line| {
        let projected = projected_bytes(path, rows.len(), retained_bytes, line.len())?;
        rows.try_reserve(1).map_err(|error| {
            NetdiagError::Ml(format!(
                "training dataset {} row allocation failed: {error}",
                path.display()
            ))
        })?;
        let validated: ValidatedDatasetRow = parse_and_validate_row(path, line_number, line)?;
        let features = match validated.payload {
            ValidatedDatasetPayload::Records(records) => {
                let summary = summarize_telemetry(&records, 5)?;
                extract_features_from_windows(&summary.windows)
            }
            ValidatedDatasetPayload::Features(features) => FEATURES
                .iter()
                .map(|name| features[*name])
                .collect::<Vec<_>>(),
        };
        rows.push(TrainingDatasetRow {
            label: validated.label,
            features,
        });
        retained_bytes = projected;
        Ok(())
    })?;
    if rows.is_empty() {
        return Err(NetdiagError::Ml(format!(
            "training dataset {} contains no rows",
            path.display()
        )));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs;

    #[test]
    fn preparation_keeps_one_generation_after_source_replacement() {
        let root = tempfile::tempdir().expect("tempdir");
        let path = root.path().join("training.jsonl");
        let original = row(10.0);
        fs::write(&path, &original).expect("original dataset");
        let expected_hash = format!("{:x}", Sha256::digest(original.as_bytes()));

        let prepared = prepare_with_hook(&path, || {
            fs::write(&path, row(99.0)).expect("replacement dataset");
        })
        .expect("prepared immutable generation");

        assert_eq!(prepared.hash_sha256, expected_hash);
        assert_eq!(prepared.rows.len(), 1);
        assert_eq!(prepared.rows[0].features[0], 10.0);
    }

    fn row(latency: f64) -> String {
        serde_json::json!({
            "label": "normal",
            "features": FEATURES
                .iter()
                .map(|name| ((*name).to_string(), latency))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .to_string()
    }
}
