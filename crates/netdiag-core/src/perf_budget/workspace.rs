use crate::error::Result;
use crate::storage::{
    ArtifactRootCapability, StagedAtomicDirectory, create_root_bound_staged_directory,
    discard_root_bound_staged_directory, with_artifact_root_capability,
};
use std::ffi::OsString;
use std::path::Path;

pub(super) fn run<T>(
    capability: &ArtifactRootCapability,
    action: impl FnOnce(&mut StagedAtomicDirectory) -> Result<T>,
) -> Result<T> {
    let target_name = OsString::from(format!("perf-run-{}", uuid::Uuid::new_v4().simple()));
    let mut staged = with_artifact_root_capability(capability, |owned| {
        create_root_bound_staged_directory(
            owned,
            Path::new(""),
            target_name,
            "performance workspace staging",
        )
    })?;
    let operation = action(&mut staged);
    discard_root_bound_staged_directory(capability, staged, operation)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;
