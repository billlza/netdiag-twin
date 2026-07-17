use super::TrustedDatasetRoot;
use crate::error::Result;
use std::path::Path;

mod child;
mod directory;
mod path;

impl TrustedDatasetRoot {
    pub(in crate::dataset) fn open(path: &Path) -> Result<Self> {
        directory::open(path, false)
    }

    pub(in crate::dataset) fn open_durable(path: &Path) -> Result<Self> {
        directory::open(path, true)
    }
}
