use crate::error::{NetdiagError, Result};
use crate::storage::{
    CoordinationParentScope, coordination_parent_scope, prospective_component_alias,
};
use netdiag_platform::{OpenedFileIdentity, metadata_is_reparse_point};
use std::io::ErrorKind;
use std::path::Path;

mod protected_scopes;
pub(super) use protected_scopes::ProtectedOutputScopes;

pub(super) fn ensure_not_protected(
    resolved: &Path,
    reported: &Path,
    protected_files: &[std::path::PathBuf],
    protected_directories: &[std::path::PathBuf],
    allowed: Option<&Path>,
) -> Result<()> {
    if allowed == Some(resolved) {
        return Ok(());
    }
    if protected_files.iter().any(|target| target == resolved) {
        return Err(overlap_error(reported));
    }
    let output_parent = protected_parent_scope(resolved, reported)?;
    let output_identity = opened_target_identity(resolved, reported)?;
    for protected in protected_files {
        if targets_alias(
            resolved,
            &output_parent,
            output_identity,
            protected,
            reported,
        )? {
            return Err(overlap_error(reported));
        }
    }
    for representative in protected_directories {
        if protected_parent_scope(representative, reported)?.overlaps(&output_parent) {
            return Err(overlap_error(reported));
        }
    }
    Ok(())
}

fn targets_alias(
    output: &Path,
    output_parent: &CoordinationParentScope,
    output_identity: Option<OpenedFileIdentity>,
    protected: &Path,
    reported: &Path,
) -> Result<bool> {
    if output == protected {
        return Ok(true);
    }
    if let Some(output_identity) = output_identity
        && opened_target_identity(protected, reported)? == Some(output_identity)
    {
        return Ok(true);
    }
    if !leaf_names_may_alias(output, protected) {
        return Ok(false);
    }
    Ok(protected_parent_scope(protected, reported)?.overlaps(output_parent))
}

fn opened_target_identity(
    path: &Path,
    reported_output: &Path,
) -> Result<Option<OpenedFileIdentity>> {
    let file = match netdiag_platform::open_file_read_only_no_follow(path) {
        Ok(file) => file,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(validation_error(reported_output, source)),
    };
    let metadata = file
        .metadata()
        .map_err(|source| validation_error(reported_output, source))?;
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(NetdiagError::InvalidTrace(format!(
            "snapshot output could not be proven distinct from a protected run input or transaction directory at {}: target is not a regular non-reparse file: {}",
            reported_output.display(),
            path.display()
        )));
    }
    netdiag_platform::opened_file_identity(&file)
        .map(Some)
        .map_err(|source| validation_error(reported_output, source))
}

fn leaf_names_may_alias(left: &Path, right: &Path) -> bool {
    let Some((left, right)) = left.file_name().zip(right.file_name()) else {
        return false;
    };
    prospective_component_alias(left, right)
}

fn protected_parent_scope(
    target: &Path,
    reported_output: &Path,
) -> Result<CoordinationParentScope> {
    coordination_parent_scope(target).map_err(|source| {
        NetdiagError::InvalidTrace(format!(
            "snapshot output could not be proven distinct from a protected run input or transaction directory at {}: {source}",
            reported_output.display()
        ))
    })
}

fn validation_error(reported: &Path, source: std::io::Error) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "snapshot output could not be proven distinct from a protected run input or transaction directory at {}: {source}",
        reported.display()
    ))
}

fn overlap_error(reported: &Path) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "snapshot output overlaps a protected run input or transaction directory: {}",
        reported.display()
    ))
}

#[cfg(all(test, any(windows, target_os = "macos")))]
mod tests {
    use super::leaf_names_may_alias;
    use std::path::Path;

    #[test]
    fn unicode_case_fold_aliases_are_conservative_before_creation() {
        assert!(leaf_names_may_alias(
            Path::new("ml_re\u{17f}ult.json"),
            Path::new("ml_result.json")
        ));
    }
}
