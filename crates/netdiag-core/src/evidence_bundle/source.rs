use crate::error::{IoContext, NetdiagError, Result};
use crate::file_identity::OpenedFileIdentity;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

mod override_source;
pub(super) use override_source::{canonical_logical_path, open_override_source};
mod stable_file;
use stable_file::open_stable_regular_file;
pub(in crate::evidence_bundle) use stable_file::validate_regular_non_reparse;
mod zip_path;
pub(super) use zip_path::normalize_zip_path;

pub(super) struct CanonicalRoots {
    paths: Vec<PathBuf>,
}

impl CanonicalRoots {
    pub(super) fn new(run_dir: &Path, lab_run_dir: Option<&Path>) -> Result<Self> {
        let mut paths = vec![fs::canonicalize(run_dir).with_path(run_dir)?];
        if let Some(lab_run_dir) = lab_run_dir {
            let canonical = fs::canonicalize(lab_run_dir).with_path(lab_run_dir)?;
            if !paths.contains(&canonical) {
                paths.push(canonical);
            }
        }
        Ok(Self { paths })
    }

    fn contains(&self, path: &Path) -> bool {
        self.paths.iter().any(|root| path.starts_with(root))
    }
}

pub(super) struct SourceFile {
    pub(super) canonical_path: PathBuf,
    pub(super) reported_path: PathBuf,
    pub(super) file: File,
    pub(super) opened_metadata: fs::Metadata,
    pub(super) opened_identity: OpenedFileIdentity,
}

pub(super) fn open_required_source(
    path: &Path,
    allowed_roots: Option<&CanonicalRoots>,
) -> Result<SourceFile> {
    open_source(path, allowed_roots)?.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "evidence bundle source does not exist: {}",
            path.display()
        ))
    })
}

fn open_source(path: &Path, allowed_roots: Option<&CanonicalRoots>) -> Result<Option<SourceFile>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(NetdiagError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let stable = open_stable_regular_file(path)?;
    let canonical_path = stable.canonical_path;
    if allowed_roots.is_some_and(|roots| !roots.contains(&canonical_path)) {
        return Err(NetdiagError::InvalidTrace(format!(
            "evidence bundle source resolves outside the allowed run/lab roots: {} -> {}",
            path.display(),
            canonical_path.display()
        )));
    }
    Ok(Some(SourceFile {
        reported_path: canonical_path.clone(),
        canonical_path,
        file: stable.file,
        opened_metadata: stable.opened_metadata,
        opened_identity: stable.opened_identity,
    }))
}
