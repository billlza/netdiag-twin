use super::super::{MAX_ADAPTER_FILE_BYTES, validate_relative_path};
use super::StagedAdapter;
use super::copy::{clean_up_failed_stage, copy_stable_source};
use super::file_security::set_read_only;
use super::trusted_root::TrustedRoot;
use crate::error::{IoContext, NetdiagError, Result};
use std::fs::OpenOptions;
use std::path::Path;

pub(super) fn stage_adapter(
    manifest_dir: &Path,
    trusted_root: &TrustedRoot,
    staging_dir: &Path,
    source_name: &str,
    endpoint: &str,
) -> Result<StagedAdapter> {
    stage_adapter_with_hooks(
        manifest_dir,
        trusted_root,
        staging_dir,
        source_name,
        endpoint,
        (|_| {}, |_| {}, |_| {}),
    )
}

pub(super) fn stage_adapter_with_hooks<BeforeOpen, AfterInspection, AfterCopy>(
    manifest_dir: &Path,
    trusted_root: &TrustedRoot,
    staging_dir: &Path,
    source_name: &str,
    endpoint: &str,
    hooks: (BeforeOpen, AfterInspection, AfterCopy),
) -> Result<StagedAdapter>
where
    BeforeOpen: FnOnce(&Path),
    AfterInspection: FnOnce(&Path),
    AfterCopy: FnOnce(&Path),
{
    let (before_source_open, after_source_inspection, after_source_copy) = hooks;
    validate_relative_path("adapter endpoint", endpoint)?;
    let requested = manifest_dir.join(endpoint);
    before_source_open(&requested);
    let opened = trusted_root.open_source(endpoint)?;
    let mut source_file = opened.file;
    let opened_metadata = opened.metadata;
    let opened_identity = opened.identity;
    let canonical = opened.path;
    if opened_metadata.len() > MAX_ADAPTER_FILE_BYTES {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter endpoint exceeds {MAX_ADAPTER_FILE_BYTES} bytes: {}",
            canonical.display()
        )));
    }
    after_source_inspection(&canonical);

    let staged_path = staging_dir.join(format!("{source_name}.py"));
    let mut staged_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged_path)
        .with_path(&staged_path)?;
    if let Err(error) = copy_stable_source(
        &mut source_file,
        opened_identity,
        &opened_metadata,
        &canonical,
        &mut staged_file,
        &staged_path,
        after_source_copy,
    ) {
        drop(staged_file);
        return Err(clean_up_failed_stage(&staged_path, error));
    }
    if let Err(error) = set_read_only(&staged_path) {
        return Err(clean_up_failed_stage(&staged_path, error));
    }
    let identity = Path::new(endpoint)
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .filter(|identity| !identity.is_empty())
        .unwrap_or(source_name)
        .to_string();
    Ok(StagedAdapter {
        original_path: canonical,
        staged_path,
        identity,
    })
}
