use super::limits;
use crate::error::{IoContext, NetdiagError, Result};
use std::io::BufRead;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReadSummary {
    pub(super) bytes: u64,
    pub(super) physical_lines: usize,
    pub(super) rows: usize,
}

#[derive(Debug, Clone, Copy)]
struct Limits {
    max_bytes: u64,
    max_line_bytes: usize,
    max_physical_lines: usize,
    max_rows: usize,
}

const DATASET_LIMITS: Limits = Limits {
    max_bytes: limits::MAX_INPUT_BYTES,
    max_line_bytes: limits::MAX_LINE_BYTES,
    max_physical_lines: limits::MAX_PHYSICAL_LINES,
    max_rows: limits::MAX_ROWS,
};

pub(super) fn for_each_nonempty_line(
    path: &Path,
    reader: impl BufRead,
    visitor: impl FnMut(usize, &str) -> Result<()>,
) -> Result<ReadSummary> {
    for_each_nonempty_line_with_limits(path, reader, DATASET_LIMITS, visitor)
}

fn for_each_nonempty_line_with_limits(
    path: &Path,
    mut reader: impl BufRead,
    limits: Limits,
    mut visitor: impl FnMut(usize, &str) -> Result<()>,
) -> Result<ReadSummary> {
    validate_limits(limits)?;
    let mut line = Vec::new();
    let mut bytes = 0_u64;
    let mut physical_lines = 0_usize;
    let mut rows = 0_usize;

    loop {
        let (consumed, ends_line) = {
            let available = reader.fill_buf().with_path(path)?;
            if available.is_empty() {
                break;
            }
            let consumed = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |position| position + 1);
            let chunk = &available[..consumed];
            bytes = checked_total_bytes(path, bytes, chunk.len(), limits.max_bytes)?;
            ensure_line_capacity(path, physical_lines + 1, line.len(), chunk.len(), limits)?;
            line.try_reserve(chunk.len()).map_err(|error| {
                NetdiagError::InvalidTrace(format!(
                    "dataset {} line buffer allocation failed: {error}",
                    path.display()
                ))
            })?;
            line.extend_from_slice(chunk);
            (consumed, chunk.last() == Some(&b'\n'))
        };
        reader.consume(consumed);

        if ends_line {
            physical_lines = checked_physical_line(path, physical_lines, limits)?;
            process_line(
                path,
                physical_lines,
                &line[..line.len() - 1],
                &mut rows,
                limits,
                &mut visitor,
            )?;
            line.clear();
        }
    }

    if !line.is_empty() {
        physical_lines = checked_physical_line(path, physical_lines, limits)?;
        process_line(path, physical_lines, &line, &mut rows, limits, &mut visitor)?;
    }

    Ok(ReadSummary {
        bytes,
        physical_lines,
        rows,
    })
}

fn process_line(
    path: &Path,
    line_number: usize,
    bytes: &[u8],
    rows: &mut usize,
    limits: Limits,
    visitor: &mut impl FnMut(usize, &str) -> Result<()>,
) -> Result<()> {
    let line = std::str::from_utf8(bytes).map_err(|error| {
        NetdiagError::InvalidTrace(format!(
            "dataset {} line {line_number} is not valid UTF-8: {error}",
            path.display()
        ))
    })?;
    let line = line.trim();
    if line.is_empty() {
        return Ok(());
    }
    *rows = rows.checked_add(1).ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "dataset {} effective row count overflowed",
            path.display()
        ))
    })?;
    if *rows > limits.max_rows {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset {} exceeds {} effective rows at physical line {line_number}",
            path.display(),
            limits.max_rows
        )));
    }
    visitor(line_number, line)
}

fn checked_total_bytes(path: &Path, current: u64, added: usize, max_bytes: u64) -> Result<u64> {
    let added = u64::try_from(added).map_err(|_| {
        NetdiagError::InvalidTrace(format!(
            "dataset {} input byte count could not be represented",
            path.display()
        ))
    })?;
    let total = current.checked_add(added).ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "dataset {} input byte count overflowed",
            path.display()
        ))
    })?;
    if total > max_bytes {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset {} exceeds the {max_bytes}-byte input limit",
            path.display()
        )));
    }
    Ok(total)
}

fn ensure_line_capacity(
    path: &Path,
    line_number: usize,
    current: usize,
    added: usize,
    limits: Limits,
) -> Result<()> {
    let length = current.checked_add(added).ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "dataset {} line {line_number} byte count overflowed",
            path.display()
        ))
    })?;
    if length > limits.max_line_bytes {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset {} line {line_number} exceeds {} bytes including its newline",
            path.display(),
            limits.max_line_bytes
        )));
    }
    Ok(())
}

fn checked_physical_line(path: &Path, current: usize, limits: Limits) -> Result<usize> {
    let lines = current.checked_add(1).ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "dataset {} physical line count overflowed",
            path.display()
        ))
    })?;
    if lines > limits.max_physical_lines {
        return Err(NetdiagError::InvalidTrace(format!(
            "dataset {} exceeds {} physical lines",
            path.display(),
            limits.max_physical_lines
        )));
    }
    Ok(lines)
}

fn validate_limits(limits: Limits) -> Result<()> {
    if limits.max_bytes == 0
        || limits.max_line_bytes == 0
        || limits.max_physical_lines == 0
        || limits.max_rows == 0
    {
        return Err(NetdiagError::InvalidTrace(
            "dataset row reader limits must all be positive".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    fn limits(max_bytes: u64, max_line_bytes: usize, lines: usize, rows: usize) -> Limits {
        Limits {
            max_bytes,
            max_line_bytes,
            max_physical_lines: lines,
            max_rows: rows,
        }
    }

    fn read(input: &[u8], limits: Limits) -> Result<(ReadSummary, Vec<(usize, String)>)> {
        let mut seen = Vec::new();
        let summary = for_each_nonempty_line_with_limits(
            Path::new("fixture.jsonl"),
            BufReader::with_capacity(2, Cursor::new(input)),
            limits,
            |line, value| {
                seen.push((line, value.to_string()));
                Ok(())
            },
        )?;
        Ok((summary, seen))
    }

    #[test]
    fn exact_byte_and_line_limits_are_accepted() {
        let (summary, seen) = read(b"{}\n", limits(3, 3, 1, 1)).expect("exact limits");
        assert_eq!(
            summary,
            ReadSummary {
                bytes: 3,
                physical_lines: 1,
                rows: 1
            }
        );
        assert_eq!(seen, vec![(1, "{}".to_string())]);
    }

    #[test]
    fn input_byte_limit_plus_one_is_rejected() {
        let error = read(b"{}\n", limits(2, 3, 1, 1)).expect_err("byte limit");
        assert!(error.to_string().contains("2-byte input limit"), "{error}");
    }

    #[test]
    fn line_limit_plus_one_is_rejected_before_allocation() {
        let error = read(b"{}\n", limits(3, 2, 1, 1)).expect_err("line limit");
        assert!(
            error
                .to_string()
                .contains("line 1 exceeds 2 bytes including its newline"),
            "{error}"
        );
    }

    #[test]
    fn empty_lines_count_as_physical_lines_but_not_rows() {
        let (summary, seen) = read(b"\n \n{}", limits(5, 2, 3, 1)).expect("empty lines");
        assert_eq!(summary.physical_lines, 3);
        assert_eq!(summary.rows, 1);
        assert_eq!(seen, vec![(3, "{}".to_string())]);
    }

    #[test]
    fn physical_line_limit_is_independent_from_row_limit() {
        let error = read(b"\n\n{}", limits(4, 2, 2, 1)).expect_err("physical lines");
        assert!(
            error.to_string().contains("exceeds 2 physical lines"),
            "{error}"
        );
    }

    #[test]
    fn effective_row_limit_plus_one_is_rejected() {
        let error = read(b"{}\n{}", limits(5, 3, 2, 1)).expect_err("row limit");
        assert!(
            error.to_string().contains("exceeds 1 effective rows"),
            "{error}"
        );
    }

    #[test]
    fn final_line_without_newline_uses_the_same_line_limit() {
        let (summary, seen) = read(b"{}", limits(2, 2, 1, 1)).expect("final line");
        assert_eq!(summary.bytes, 2);
        assert_eq!(summary.physical_lines, 1);
        assert_eq!(seen, vec![(1, "{}".to_string())]);
    }
}
