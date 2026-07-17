use super::super::limits;
use crate::error::{NetdiagError, Result};
use std::path::Path;

pub(in crate::dataset) fn projected_bytes(
    path: &Path,
    retained_rows: usize,
    retained_bytes: u64,
    line_bytes: usize,
) -> Result<u64> {
    if retained_rows >= limits::MAX_RETAINED_ROWS {
        return Err(budget_error(
            path,
            format!("exceeds {} retained rows", limits::MAX_RETAINED_ROWS),
        ));
    }
    let line_bytes = u64::try_from(line_bytes)
        .map_err(|_| budget_error(path, "line byte count cannot be represented"))?;
    let projected = retained_bytes
        .checked_add(line_bytes)
        .ok_or_else(|| budget_error(path, "byte count overflowed"))?;
    if projected > limits::MAX_RETAINED_BYTES {
        return Err(budget_error(
            path,
            format!(
                "exceeds the {}-byte retained-row limit",
                limits::MAX_RETAINED_BYTES
            ),
        ));
    }
    Ok(projected)
}

pub(super) fn copy_line(path: &Path, line: &str) -> Result<String> {
    let mut retained = String::new();
    retained
        .try_reserve_exact(line.len())
        .map_err(|error| budget_error(path, error))?;
    retained.push_str(line);
    Ok(retained)
}

pub(super) fn budget_error(path: &Path, detail: impl std::fmt::Display) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "dataset {} retained-row budget failed: {detail}",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_row_limit_is_exact() {
        let path = Path::new("dataset.jsonl");
        projected_bytes(path, limits::MAX_RETAINED_ROWS - 1, 0, 1).expect("last permitted row");
        let error =
            projected_bytes(path, limits::MAX_RETAINED_ROWS, 0, 1).expect_err("row limit plus one");
        assert!(error.to_string().contains("retained rows"), "{error}");
    }

    #[test]
    fn retained_byte_limit_is_exact() {
        let path = Path::new("dataset.jsonl");
        projected_bytes(path, 0, limits::MAX_RETAINED_BYTES - 1, 1).expect("last permitted byte");
        let error = projected_bytes(path, 0, limits::MAX_RETAINED_BYTES, 1)
            .expect_err("byte limit plus one");
        assert!(error.to_string().contains("retained-row limit"), "{error}");
    }
}
