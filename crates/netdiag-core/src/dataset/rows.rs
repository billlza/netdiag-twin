use super::row_reader;
use crate::error::{NetdiagError, Result};
use crate::models::FaultLabel;
use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::Path;

mod retained;
mod validation;
pub(super) use retained::projected_bytes;
pub(super) use validation::{ValidatedDatasetPayload, ValidatedDatasetRow, parse_and_validate_row};

#[derive(Debug, Clone)]
pub(super) struct DatasetRow {
    pub(super) line_number: usize,
    pub(super) line: String,
    pub(super) label: FaultLabel,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct DatasetSummary {
    pub(super) rows: usize,
    pub(super) label_distribution: BTreeMap<String, usize>,
}

pub(super) fn read_dataset_rows_from_reader(
    path: &Path,
    reader: impl BufRead,
) -> Result<Vec<DatasetRow>> {
    let mut rows = Vec::new();
    let mut retained_bytes = 0_u64;
    for_each_validated_dataset_row(path, reader, |line_number, line, label| {
        retained_bytes = retained::projected_bytes(path, rows.len(), retained_bytes, line.len())?;
        rows.try_reserve(1)
            .map_err(|error| retained::budget_error(path, error))?;
        rows.push(DatasetRow {
            line_number,
            line: retained::copy_line(path, line)?,
            label,
        });
        Ok(())
    })?;
    ensure_nonempty(path, rows.len())?;
    Ok(rows)
}

pub(super) fn read_dataset_summary_from_reader(
    path: &Path,
    reader: impl BufRead,
) -> Result<DatasetSummary> {
    let mut summary = DatasetSummary::default();
    for_each_validated_dataset_row(path, reader, |_, _, label| {
        summary.rows = summary.rows.checked_add(1).ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "dataset {} effective row count overflowed while summarizing",
                path.display()
            ))
        })?;
        *summary
            .label_distribution
            .entry(label.as_str().to_string())
            .or_default() += 1;
        Ok(())
    })?;
    ensure_nonempty(path, summary.rows)?;
    Ok(summary)
}

pub(super) fn label_distribution(rows: &[DatasetRow]) -> BTreeMap<String, usize> {
    let mut labels = BTreeMap::new();
    for row in rows {
        *labels.entry(row.label.as_str().to_string()).or_default() += 1;
    }
    labels
}

pub(super) fn summarize_rows(rows: &[DatasetRow]) -> DatasetSummary {
    DatasetSummary {
        rows: rows.len(),
        label_distribution: label_distribution(rows),
    }
}

fn for_each_validated_dataset_row(
    path: &Path,
    reader: impl BufRead,
    mut visitor: impl FnMut(usize, &str, FaultLabel) -> Result<()>,
) -> Result<()> {
    row_reader::for_each_nonempty_line(path, reader, |line_number, line| {
        let label = validation::parse_and_validate(path, line_number, line)?;
        visitor(line_number, line, label)
    })
    .map(drop)
}

fn ensure_nonempty(path: &Path, rows: usize) -> Result<()> {
    if rows == 0 {
        return Err(NetdiagError::Ml(format!(
            "dataset {} contains no rows",
            path.display()
        )));
    }
    Ok(())
}
