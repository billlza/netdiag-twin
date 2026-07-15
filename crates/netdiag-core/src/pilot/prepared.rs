use super::PilotManifest;
use super::pilot_sources::AdapterExecutionBoundary;
use crate::error::{IoContext, NetdiagError, Result};
use std::path::{Path, PathBuf};

mod finish;
mod manifest;
pub(super) use manifest::read_manifest;

#[derive(Debug)]
pub(super) struct PreparedPilot {
    pub(super) manifest: PilotManifest,
    pub(super) manifest_dir: PathBuf,
    pub(super) adapter_boundary: Option<AdapterExecutionBoundary>,
}

impl PreparedPilot {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let manifest = read_manifest(path)?;
        let manifest_parent = manifest_parent(path)?;
        let manifest_dir = manifest_parent.canonicalize().with_path(manifest_parent)?;
        let adapter_boundary = AdapterExecutionBoundary::from_manifest(&manifest, &manifest_dir)?;
        Ok(Self {
            manifest,
            manifest_dir,
            adapter_boundary,
        })
    }
}

fn manifest_parent(path: &Path) -> Result<&Path> {
    match path.parent() {
        Some(parent) => Ok(parent),
        None => Err(NetdiagError::InvalidTrace(format!(
            "pilot manifest path has no parent: {}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests;
