use super::RegistrationSnapshot;
use crate::error::{NetdiagError, Result};
use std::fs::File;

impl RegistrationSnapshot {
    pub(in crate::dataset) fn reopen(&self) -> Result<File> {
        self.file
            .as_ref()
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(
                    "dataset registration snapshot is no longer staged".to_string(),
                )
            })?
            .reopen_rewound()
    }

    pub(in crate::dataset) fn finish<T>(mut self, operation: Result<T>) -> Result<T> {
        match self.file.take() {
            None => operation,
            Some(staged) => staged.finish(operation),
        }
    }

    pub(in crate::dataset) fn finish_registration<T>(mut self, operation: Result<T>) -> Result<T> {
        match self.file.take() {
            None => operation,
            Some(staged) => match operation {
                Err(error) => staged.finish(Err(error)),
                Ok(_) => staged.finish(Err(NetdiagError::InvalidTrace(
                    "dataset registration completed without resolving its staged snapshot"
                        .to_string(),
                ))),
            },
        }
    }
}
