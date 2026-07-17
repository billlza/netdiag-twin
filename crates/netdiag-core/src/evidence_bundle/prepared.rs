use super::context::EvidenceContext;
use super::export::SourceOverrides;
use super::snapshot::{SnapshotStore, SourceSnapshot};
use super::source::{CanonicalRoots, open_required_source};
use super::{EvidenceBundleExtraFile, MANIFEST_ZIP_PATH, README_ZIP_PATH, reserve_zip_path};
use crate::error::{NetdiagError, Result};
use crate::models::RunArtifactEntry;
use crate::storage::RunLocation;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

mod capture;
mod requested_extras;
pub(in crate::evidence_bundle) use requested_extras::validate as validate_requested_extras;

pub(super) struct PreparedEvidenceSnapshots {
    pub(super) files: Vec<PreparedSnapshotFile>,
    store: SnapshotStore,
}

pub(super) struct PreparedSnapshotFile {
    pub(super) key: String,
    pub(super) source: SourceSnapshot,
    pub(super) zip_path: String,
}

pub(super) struct PrepareRequest<'a> {
    pub(super) location: &'a RunLocation,
    pub(super) run_id: &'a str,
    pub(super) context: EvidenceContext,
    pub(super) requested_extras: &'a [EvidenceBundleExtraFile],
    pub(super) allow_pending_transaction: bool,
    pub(super) source_overrides: &'a SourceOverrides,
}

impl PreparedEvidenceSnapshots {
    pub(super) fn report_mut(&mut self) -> Result<&mut SourceSnapshot> {
        self.files
            .iter_mut()
            .find(|file| file.key == "report")
            .map(|file| &mut file.source)
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(
                    "evidence bundle is missing its manifest-declared report snapshot".to_string(),
                )
            })
    }

    pub(super) fn directory_path(&self) -> &std::path::Path {
        self.store.path()
    }

    pub(super) fn rewrite_reported_root(
        &mut self,
        staged_root: &std::path::Path,
        published_root: &std::path::Path,
    ) -> Result<()> {
        let staged_root = fs::canonicalize(staged_root).map_err(|source| NetdiagError::Io {
            path: staged_root.to_path_buf(),
            source,
        })?;
        for file in &mut self.files {
            if let Ok(relative) = file.source.reported_path.strip_prefix(&staged_root) {
                file.source.reported_path = published_root.join(relative);
            }
        }
        Ok(())
    }

    pub(super) fn finish<T>(self, operation: Result<T>) -> Result<T> {
        let Self { files, store } = self;
        drop(files);
        store.finish(operation)
    }
}

struct SnapshotBuilder {
    files: Vec<PreparedSnapshotFile>,
    used_paths: BTreeSet<String>,
    store: SnapshotStore,
}

impl SnapshotBuilder {
    fn new() -> Result<Self> {
        Ok(Self {
            store: SnapshotStore::new()?,
            files: Vec::new(),
            used_paths: BTreeSet::from([
                README_ZIP_PATH.to_string(),
                MANIFEST_ZIP_PATH.to_string(),
            ]),
        })
    }

    fn capture_artifact(
        &mut self,
        artifact: RunArtifactEntry,
        roots: &CanonicalRoots,
        overrides: &SourceOverrides,
    ) -> Result<()> {
        let path = PathBuf::from(&artifact.path);
        let source = match overrides.open(&path, roots)? {
            Some(source) => source,
            None => open_required_source(&path, Some(roots))?,
        };
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{}.json", artifact.key));
        self.capture_source(artifact.key, source, &file_name)
    }

    fn capture_missing_overrides(
        &mut self,
        included_keys: &BTreeSet<String>,
        roots: &CanonicalRoots,
        overrides: &SourceOverrides,
    ) -> Result<()> {
        for (key, target, staged) in overrides.missing_artifacts(included_keys) {
            let source = super::source::open_override_source(staged, target, roots)?;
            let file_name = target
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    NetdiagError::InvalidTrace(format!(
                        "overridden evidence source has no UTF-8 file name: {}",
                        target.display()
                    ))
                })?;
            self.capture_source(key.to_string(), source, file_name)?;
        }
        Ok(())
    }

    fn capture_context_file(
        &mut self,
        extra: &EvidenceBundleExtraFile,
        roots: &CanonicalRoots,
        overrides: &SourceOverrides,
    ) -> Result<()> {
        let source = match overrides.open(&extra.path, roots)? {
            Some(source) => source,
            None => open_required_source(&extra.path, Some(roots))?,
        };
        self.capture_source(extra.key.clone(), source, &extra.zip_path)
    }

    fn capture_requested_extra(&mut self, extra: &EvidenceBundleExtraFile) -> Result<()> {
        let source = open_required_source(&extra.path, None)?;
        self.capture_source(extra.key.clone(), source, &extra.zip_path)
    }

    fn capture_source(
        &mut self,
        key: String,
        source: super::source::SourceFile,
        raw_zip_path: &str,
    ) -> Result<()> {
        let zip_path = reserve_zip_path(raw_zip_path, &mut self.used_paths)?;
        let source = self.store.capture(source)?;
        self.files.push(PreparedSnapshotFile {
            key,
            source,
            zip_path,
        });
        Ok(())
    }

    fn into_prepared(self) -> PreparedEvidenceSnapshots {
        let Self { store, files, .. } = self;
        PreparedEvidenceSnapshots { files, store }
    }

    fn finish<T>(self, operation: Result<T>) -> Result<T> {
        let Self {
            store,
            files,
            used_paths,
        } = self;
        drop((files, used_paths));
        store.finish(operation)
    }
}
