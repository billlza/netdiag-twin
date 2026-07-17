use super::errors::trust_error;
use super::key::absolute_target;
use crate::error::{NetdiagError, Result};
use netdiag_platform::{DirectoryTrustError, open_trusted_directory_chain};
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::Path;

#[derive(Clone, Debug)]
pub(crate) struct CoordinationParentScope {
    anchor_identity: [u8; 32],
    missing_components: Vec<OsString>,
}

impl CoordinationParentScope {
    pub(crate) fn for_existing_identity(anchor_identity: [u8; 32]) -> Self {
        Self {
            anchor_identity,
            missing_components: Vec::new(),
        }
    }

    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        self.anchor_identity == other.anchor_identity
            && self.missing_components.len() == other.missing_components.len()
            && self
                .missing_components
                .iter()
                .zip(&other.missing_components)
                .all(|(left, right)| prospective_component_alias(left, right))
    }
}

pub(crate) fn prospective_component_alias(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    if left == right {
        return true;
    }
    let Some((left, right)) = left.to_str().zip(right.to_str()) else {
        return false;
    };
    if left.eq_ignore_ascii_case(right) {
        return true;
    }
    platform_component_alias(left, right)
}

#[cfg(windows)]
fn platform_component_alias(left: &str, right: &str) -> bool {
    let left = left.trim_end_matches([' ', '.']);
    let right = right.trim_end_matches([' ', '.']);
    filesystem_case_key(left) == filesystem_case_key(right)
}

#[cfg(target_os = "macos")]
fn platform_component_alias(left: &str, right: &str) -> bool {
    filesystem_case_key(left) == filesystem_case_key(right)
}

#[cfg(any(windows, target_os = "macos"))]
fn filesystem_case_key(value: &str) -> String {
    value
        .chars()
        .flat_map(char::to_uppercase)
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_component_alias(_left: &str, _right: &str) -> bool {
    false
}

pub(crate) fn inspect(target: &Path) -> Result<CoordinationParentScope> {
    let target = absolute_target(target)?;
    let parent = target.parent().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "coordination lock target has no parent: {}",
            target.display()
        ))
    })?;
    inspect_parent(parent)
}

fn inspect_parent(parent: &Path) -> Result<CoordinationParentScope> {
    let mut candidate = parent.to_path_buf();
    let mut missing_components = Vec::new();
    loop {
        match open_trusted_directory_chain(&candidate) {
            Ok(directory) => {
                directory.validate_identity().map_err(trust_error)?;
                directory.validate_private_security().map_err(trust_error)?;
                missing_components.reverse();
                return Ok(CoordinationParentScope {
                    anchor_identity: directory.coordination_identity().map_err(trust_error)?,
                    missing_components,
                });
            }
            Err(DirectoryTrustError::Inspect { source, .. })
                if source.kind() == ErrorKind::NotFound =>
            {
                let name = candidate
                    .file_name()
                    .ok_or_else(|| trust_error_not_found(&candidate))?;
                missing_components.push(name.to_os_string());
                candidate = candidate
                    .parent()
                    .ok_or_else(|| trust_error_not_found(&candidate))?
                    .to_path_buf();
            }
            Err(source) => return Err(trust_error(source)),
        }
    }
}

fn trust_error_not_found(path: &Path) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "coordination target has no existing trusted ancestor: {}",
        path.display()
    ))
}
