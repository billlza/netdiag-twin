use super::super::{PilotManifest, PilotSourceKind};
use crate::error::{IoContext, NetdiagError, Result};
use crate::managed_temp_directory::ManagedTempDirectory;
use crate::pilot::adapter_contract::{ResolvedInterpreter, resolve_python_interpreter};
use crate::storage::{PathStatus, path_status};
use std::path::Path;

mod staging;
use staging::StagedAdapters;

const MAX_ADAPTER_PATH_BYTES: usize = 4 * 1024;
#[cfg(unix)]
const MAX_ADAPTER_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Canonical filesystem boundary for trusted adapter code.
///
/// Adapters are executable code, not data. A manifest that contains adapters
/// must declare one relative trusted root. The root is canonicalized and
/// trust-checked; each endpoint is component-normalized, confined to that
/// root, opened without following symlinks, and copied into private staging.
#[derive(Debug)]
pub(in crate::pilot) struct AdapterExecutionBoundary {
    interpreter: ResolvedInterpreter,
    staged_adapters: StagedAdapters,
}

impl AdapterExecutionBoundary {
    pub(in crate::pilot) fn ensure_authorized(
        manifest: &PilotManifest,
        allow_adapter_execution: bool,
    ) -> Result<()> {
        let adapter_sources = manifest
            .sources
            .iter()
            .filter(|source| source.kind == PilotSourceKind::AdapterSample)
            .map(|source| source.name.as_str())
            .collect::<Vec<_>>();
        if adapter_sources.is_empty() || allow_adapter_execution {
            return Ok(());
        }
        Err(NetdiagError::Connector(format!(
            "trusted adapter execution requires explicit allow_adapter_execution authorization: {}",
            adapter_sources.join(", ")
        )))
    }

    pub(in crate::pilot) fn from_manifest(
        manifest: &PilotManifest,
        manifest_dir: &Path,
    ) -> Result<Option<Self>> {
        if !manifest
            .sources
            .iter()
            .any(|source| source.kind == PilotSourceKind::AdapterSample)
        {
            return Ok(None);
        }
        let configured = manifest
            .safety
            .adapter_execution_root
            .as_deref()
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(
                    "pilot manifests with adapters must declare safety.adapter_execution_root"
                        .to_string(),
                )
            })?;
        validate_relative_path("adapter execution root", configured)?;
        let manifest_dir = manifest_dir.canonicalize().with_path(manifest_dir)?;
        let root_path = manifest_dir.join(configured);
        let trusted_root = root_path.canonicalize().with_path(&root_path)?;
        if path_status(&trusted_root)? != PathStatus::Directory {
            return Err(NetdiagError::InvalidTrace(format!(
                "adapter execution root is not a directory: {}",
                trusted_root.display()
            )));
        }
        let interpreter =
            resolve_python_interpreter(manifest.safety.adapter_python_interpreter.as_deref())?;
        let staged_adapters =
            StagedAdapters::prepare(manifest, &manifest_dir, &trusted_root, configured)?;
        Ok(Some(Self {
            interpreter,
            staged_adapters,
        }))
    }

    pub(in crate::pilot) fn staged_adapter(&self, source_name: &str) -> Result<&Path> {
        self.staged_adapters.staged_path(source_name)
    }

    pub(in crate::pilot) fn original_adapter(&self, source_name: &str) -> Result<&Path> {
        self.staged_adapters.original_path(source_name)
    }

    pub(in crate::pilot) fn adapter_identity(&self, source_name: &str) -> Result<&str> {
        self.staged_adapters.identity(source_name)
    }

    pub(in crate::pilot) fn interpreter(&self) -> &Path {
        self.interpreter.path()
    }

    pub(in crate::pilot) fn runtime_path(&self) -> &str {
        self.interpreter.runtime_path()
    }

    pub(in crate::pilot) fn finish<T>(self, operation: Result<T>) -> Result<T> {
        let Self {
            interpreter,
            staged_adapters,
        } = self;
        drop(interpreter);
        staged_adapters.finish(operation)
    }

    /// Runs one adapter process invocation inside a newly-created private directory.
    ///
    /// The directory is never shared with another phase or source, and cleanup
    /// failures remain visible to the caller instead of being left to `Drop`.
    pub(in crate::pilot) fn with_runtime_directory<T>(
        &self,
        operation: impl FnOnce(&Path) -> Result<T>,
    ) -> Result<T> {
        let directory =
            ManagedTempDirectory::create("adapter runtime directory", "netdiag-adapter-runtime-")?;
        let result = operation(directory.path());
        directory.finish(result)
    }
}

fn validate_relative_path(kind: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_ADAPTER_PATH_BYTES {
        return Err(NetdiagError::InvalidTrace(format!(
            "{kind} must contain 1..={MAX_ADAPTER_PATH_BYTES} bytes"
        )));
    }
    let path = Path::new(value);
    if path.is_absolute() {
        return Err(NetdiagError::InvalidTrace(format!(
            "{kind} must be relative to the pilot manifest: {value:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
