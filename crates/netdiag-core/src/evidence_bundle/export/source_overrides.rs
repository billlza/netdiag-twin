use super::super::source::{
    CanonicalRoots, SourceFile, canonical_logical_path, open_override_source,
};
use crate::error::Result;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub(crate) struct EvidenceSourceOverride {
    pub key: String,
    pub target_path: PathBuf,
    pub staged_path: PathBuf,
    pub include_if_missing: bool,
}

pub(in crate::evidence_bundle) struct SourceOverrides {
    entries: Vec<NormalizedSourceOverride>,
}

struct NormalizedSourceOverride {
    key: String,
    target_path: PathBuf,
    staged_path: PathBuf,
    include_if_missing: bool,
}

impl SourceOverrides {
    pub(in crate::evidence_bundle) fn new(overrides: &[EvidenceSourceOverride]) -> Result<Self> {
        let entries = overrides
            .iter()
            .map(|source| {
                Ok(NormalizedSourceOverride {
                    key: source.key.clone(),
                    target_path: canonical_logical_path(&source.target_path)?,
                    staged_path: source.staged_path.clone(),
                    include_if_missing: source.include_if_missing,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { entries })
    }

    pub(in crate::evidence_bundle) fn open(
        &self,
        target: &Path,
        allowed_roots: &CanonicalRoots,
    ) -> Result<Option<SourceFile>> {
        let target = canonical_logical_path(target)?;
        self.entries
            .iter()
            .find(|source| source.target_path == target)
            .map(|source| {
                open_override_source(&source.staged_path, &source.target_path, allowed_roots)
            })
            .transpose()
    }

    pub(in crate::evidence_bundle) fn missing_artifacts<'a>(
        &'a self,
        included_keys: &'a BTreeSet<String>,
    ) -> impl Iterator<Item = (&'a str, &'a Path, &'a Path)> {
        self.entries
            .iter()
            .filter(|source| source.include_if_missing && !included_keys.contains(&source.key))
            .map(|source| {
                (
                    source.key.as_str(),
                    source.target_path.as_path(),
                    source.staged_path.as_path(),
                )
            })
    }
}
