use crate::error::{IoContext, NetdiagError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

mod archive_sources;
mod context;
mod export;
mod prepared;
mod snapshot;
mod source;
mod stream;

#[cfg(test)]
mod tests;

pub use context::EvidenceContext;
pub(crate) use export::{
    EvidenceSourceOverride, export_for_transaction as export_evidence_bundle_for_transaction,
    export_staged_directory as export_evidence_bundle_from_staged_directory,
};
use snapshot::SourceSnapshot;
use source::normalize_zip_path;
use stream::{BundleBudget, StreamDigest};

const README_ZIP_PATH: &str = "README-evidence.md";
const MANIFEST_ZIP_PATH: &str = "evidence_bundle_manifest.json";

#[derive(Debug, Clone)]
pub struct EvidenceBundleExtraFile {
    pub key: String,
    pub path: PathBuf,
    pub zip_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundleManifest {
    pub schema: String,
    pub run_id: String,
    pub created_at: DateTime<Utc>,
    pub output: String,
    #[serde(default)]
    pub files: Vec<EvidenceBundleFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundleFile {
    pub key: String,
    pub source_path: String,
    pub zip_path: String,
    pub bytes: u64,
    pub sha256: String,
}

struct BundleArchive {
    zip: ZipWriter<File>,
    options: SimpleFileOptions,
    manifest: EvidenceBundleManifest,
    used_paths: BTreeSet<String>,
    budget: BundleBudget,
}

pub fn export_evidence_bundle(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    output: impl AsRef<Path>,
    extra_files: &[EvidenceBundleExtraFile],
) -> Result<EvidenceBundleManifest> {
    export_evidence_bundle_with_context(
        artifact_root,
        run_id,
        output,
        EvidenceContext::Plain,
        extra_files,
    )
}

pub fn export_evidence_bundle_with_context(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    output: impl AsRef<Path>,
    context: EvidenceContext,
    extra_files: &[EvidenceBundleExtraFile],
) -> Result<EvidenceBundleManifest> {
    export::export_standard(
        artifact_root.as_ref(),
        run_id,
        output.as_ref(),
        context,
        extra_files,
    )
}

fn record_file(
    manifest: &mut EvidenceBundleManifest,
    key: &str,
    source: &SourceSnapshot,
    zip_path: String,
    digest: StreamDigest,
) {
    manifest.files.push(EvidenceBundleFile {
        key: key.to_string(),
        source_path: source.reported_path.display().to_string(),
        zip_path,
        bytes: digest.bytes,
        sha256: digest.sha256,
    });
}

fn reserve_zip_path(raw: &str, used_paths: &mut BTreeSet<String>) -> Result<String> {
    let normalized = normalize_zip_path(raw)?;
    let collision_key = normalized.to_lowercase();
    if !used_paths.insert(collision_key) {
        return Err(NetdiagError::InvalidTrace(format!(
            "duplicate normalized evidence bundle zip path: {normalized}"
        )));
    }
    Ok(normalized)
}

fn zip_error(err: zip::result::ZipError) -> NetdiagError {
    NetdiagError::InvalidTrace(format!("zip export failed: {err}"))
}

impl BundleArchive {
    fn new(file: File, run_id: &str, output: &Path, created_at: DateTime<Utc>) -> Self {
        Self {
            zip: ZipWriter::new(file),
            options: SimpleFileOptions::default().compression_method(CompressionMethod::Deflated),
            manifest: EvidenceBundleManifest {
                schema: "netdiag-evidence-bundle/v1".to_string(),
                run_id: run_id.to_string(),
                created_at,
                output: output.display().to_string(),
                files: Vec::new(),
            },
            used_paths: BTreeSet::from([MANIFEST_ZIP_PATH.to_string()]),
            budget: BundleBudget::new(),
        }
    }

    fn add_readme(&mut self, run_id: &str) -> Result<()> {
        let body = format!(
            "# NetDiag Twin Evidence Bundle\n\nRun ID: `{run_id}`\n\nThis bundle contains the machine-readable artifacts needed to review a diagnosis, connector health, ML inference, recommendations, and what-if evidence. Treat telemetry artifacts as operational data and apply the lab's retention policy before sharing.\n"
        );
        let zip_path = reserve_zip_path(README_ZIP_PATH, &mut self.used_paths)?;
        self.zip
            .start_file(&zip_path, self.options)
            .map_err(zip_error)?;
        self.budget
            .write_bytes(body.as_bytes(), Path::new(README_ZIP_PATH), &mut self.zip)?;
        Ok(())
    }

    fn finish(mut self, tmp_path: &Path) -> Result<EvidenceBundleManifest> {
        let body = serde_json::to_vec_pretty(&self.manifest)?;
        self.zip
            .start_file(MANIFEST_ZIP_PATH, self.options)
            .map_err(zip_error)?;
        self.budget.write_bytes(&body, tmp_path, &mut self.zip)?;
        self.zip
            .finish()
            .map_err(zip_error)?
            .sync_all()
            .with_path(tmp_path)?;
        Ok(self.manifest)
    }
}
