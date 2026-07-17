use super::FileScanIssue;
use std::path::Path;

#[derive(Clone, Copy, Debug)]
pub(super) struct ScanByteBudget {
    consumed: u64,
    limit: u64,
}

impl ScanByteBudget {
    pub(super) fn new(limit: u64) -> Self {
        Self { consumed: 0, limit }
    }

    pub(super) fn reserve(&mut self, path: &Path, bytes: u64) -> Result<(), FileScanIssue> {
        let projected = self
            .consumed
            .checked_add(bytes)
            .ok_or_else(|| FileScanIssue::malformed(path, "total scan byte count overflowed"))?;
        if projected > self.limit {
            let unit = if projected == 1 { "byte" } else { "bytes" };
            return Err(FileScanIssue::malformed(
                path,
                format!(
                    "total scanned file size {projected} {unit} exceeds the {}-byte scan limit",
                    self.limit
                ),
            ));
        }
        self.consumed = projected;
        Ok(())
    }
}
