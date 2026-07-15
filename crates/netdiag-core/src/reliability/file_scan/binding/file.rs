use super::digest::hash_opened_file;
use super::metadata::MetadataBinding;
use super::root::ScanRoot;
use crate::reliability::file_scan::FileScanIssue;
use crate::reliability::file_scan::budget::ScanByteBudget;
use std::fs::{File, Metadata};
use std::path::Path;

#[derive(Debug)]
pub(in crate::reliability::file_scan) struct FileBinding {
    metadata: MetadataBinding,
    content_sha256: [u8; 32],
}

impl ScanRoot {
    pub(in crate::reliability::file_scan) fn capture_file(
        &self,
        path: &Path,
        max_bytes: u64,
        total_budget: &mut ScanByteBudget,
    ) -> Result<FileBinding, FileScanIssue> {
        self.capture_file_with_hasher(path, max_bytes, total_budget, hash_opened_file)
    }

    fn capture_file_with_hasher(
        &self,
        path: &Path,
        max_bytes: u64,
        total_budget: &mut ScanByteBudget,
        hash_file: impl FnOnce(&mut File, &Path, &Path, u64, u64) -> Result<[u8; 32], FileScanIssue>,
    ) -> Result<FileBinding, FileScanIssue> {
        let (metadata, mut file) = self.capture_metadata(path, max_bytes)?;
        total_budget.reserve(path, metadata.byte_len())?;
        let content_sha256 = hash_file(
            &mut file,
            path,
            metadata.root_path(),
            metadata.byte_len(),
            metadata.max_bytes(),
        )?;
        metadata.verify_opened(&file)?;
        Ok(FileBinding {
            metadata,
            content_sha256,
        })
    }
}

impl FileBinding {
    pub(in crate::reliability::file_scan) fn path(&self) -> &Path {
        self.metadata.path()
    }

    pub(in crate::reliability::file_scan) fn max_bytes(&self) -> u64 {
        self.metadata.max_bytes()
    }

    pub(in crate::reliability::file_scan) fn root_path(&self) -> &Path {
        self.metadata.root_path()
    }

    pub(in crate::reliability::file_scan) fn open_current(
        &self,
    ) -> Result<(File, Metadata), FileScanIssue> {
        self.metadata.open_current()
    }

    pub(in crate::reliability::file_scan) fn verify_opened(
        &self,
        file: &File,
    ) -> Result<(), FileScanIssue> {
        self.metadata.verify_opened(file)
    }

    pub(in crate::reliability::file_scan) fn verify_content_digest(
        &self,
        actual: [u8; 32],
    ) -> Result<(), FileScanIssue> {
        if actual != self.content_sha256 {
            return Err(FileScanIssue::content_changed(
                self.path(),
                self.root_path(),
            ));
        }
        Ok(())
    }
}

pub(in crate::reliability::file_scan) fn capture_confined_file(
    root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Result<FileBinding, FileScanIssue> {
    let mut budget = ScanByteBudget::new(max_bytes);
    ScanRoot::capture(root)?.capture_file(path, max_bytes, &mut budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn total_budget_is_reserved_before_content_hashing() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("one.json");
        fs::write(&path, "x").expect("file");
        let root = ScanRoot::capture(temp.path()).expect("root");
        let mut budget = ScanByteBudget::new(0);
        let hasher_called = Cell::new(false);

        let issue = root
            .capture_file_with_hasher(&path, 1, &mut budget, |_, _, _, _, _| {
                hasher_called.set(true);
                Ok([0_u8; 32])
            })
            .expect_err("one byte exceeds zero-byte total budget");

        assert!(!hasher_called.get());
        assert!(issue.message.contains("total scanned file size 1 byte"));
    }

    #[test]
    fn failed_hash_does_not_refund_the_total_budget() {
        let temp = tempdir().expect("tempdir");
        let first = temp.path().join("a.json");
        let second = temp.path().join("b.json");
        fs::write(&first, "a").expect("first");
        fs::write(&second, "b").expect("second");
        let root = ScanRoot::capture(temp.path()).expect("root");
        let mut budget = ScanByteBudget::new(1);
        root.capture_file_with_hasher(&first, 1, &mut budget, |_, path, _, _, _| {
            Err(FileScanIssue::malformed(path, "injected digest failure"))
        })
        .expect_err("first hash fails after reserving its byte");
        let second_hasher_called = Cell::new(false);

        let issue = root
            .capture_file_with_hasher(&second, 1, &mut budget, |_, _, _, _, _| {
                second_hasher_called.set(true);
                Ok([0_u8; 32])
            })
            .expect_err("reserved byte leaves no budget for second hash");

        assert!(!second_hasher_called.get());
        assert!(issue.message.contains("total scanned file size 2 bytes"));
    }
}
