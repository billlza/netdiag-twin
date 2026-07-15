use super::StagedAtomicFile;
use crate::error::{NetdiagError, Result};

impl StagedAtomicFile {
    pub(crate) fn close_file(&mut self) {
        drop(self.file.take());
    }

    pub(crate) fn disarm_cleanup(&mut self) {
        self.cleanup_armed = false;
    }

    pub(crate) fn abort(mut self, original: NetdiagError) -> NetdiagError {
        match self.cleanup() {
            Ok(()) => original,
            Err(cleanup) => original.with_secondary_failure(
                "staged atomic file operation failed",
                "staged file cleanup also failed",
                cleanup,
            ),
        }
    }

    pub(crate) fn finish<T>(mut self, operation: Result<T>) -> Result<T> {
        match (operation, self.cleanup()) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(error), Err(cleanup)) => Err(error.with_secondary_failure(
                "staged atomic file operation failed",
                "staged file cleanup also failed",
                cleanup,
            )),
        }
    }

    pub(super) fn cleanup(&mut self) -> Result<()> {
        self.close_file();
        self.cleanup_armed = false;
        match netdiag_platform::remove_file_at(&self.directory, &self.name) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(NetdiagError::Io {
                path: self.path.clone(),
                source,
            }),
        }
    }
}

impl Drop for StagedAtomicFile {
    fn drop(&mut self) {
        if !self.cleanup_armed {
            return;
        }
        self.close_file();
        let _ = netdiag_platform::remove_file_at(&self.directory, &self.name);
    }
}
