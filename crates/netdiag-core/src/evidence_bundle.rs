use crate::error::{IoContext, NetdiagError, Result};
use crate::models::{RunArtifactEntry, TopologyModel};
use crate::storage::{read_report, resolve_run_location, run_artifacts};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

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

pub fn export_evidence_bundle(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
    output: impl AsRef<Path>,
    extra_files: &[EvidenceBundleExtraFile],
) -> Result<EvidenceBundleManifest> {
    let artifact_root = artifact_root.as_ref();
    let output = output.as_ref();
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).with_path(parent)?;
    }
    let tmp_path = output.with_extension(format!(
        "{}.tmp",
        output
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("zip")
    ));
    let file = File::create(&tmp_path).with_path(&tmp_path)?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut manifest = EvidenceBundleManifest {
        schema: "netdiag-evidence-bundle/v1".to_string(),
        run_id: run_id.to_string(),
        created_at: Utc::now(),
        output: output.display().to_string(),
        files: Vec::new(),
    };
    let mut used_paths = BTreeSet::new();
    let location = resolve_run_location(artifact_root, run_id)?;
    let allowed_run_dir = location.run_dir.clone();

    add_readme(&mut zip, options, run_id, &mut used_paths)?;
    for artifact in run_artifacts(&location.artifact_root, run_id)? {
        if !artifact_path_is_inside_run(&artifact, &allowed_run_dir) {
            continue;
        }
        add_artifact_file(&mut zip, options, artifact, &mut manifest, &mut used_paths)?;
    }
    let default_extra_files = if extra_files.is_empty() {
        location
            .lab_run_dir
            .as_deref()
            .map(default_lab_extra_files)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    for extra in default_extra_files.iter().chain(extra_files.iter()) {
        add_path_file(
            &mut zip,
            options,
            &extra.key,
            &extra.path,
            &extra.zip_path,
            &mut manifest,
            &mut used_paths,
        )?;
    }
    add_topology_snapshots(
        &mut zip,
        options,
        &location.artifact_root,
        run_id,
        &mut manifest,
        &mut used_paths,
    )?;

    let manifest_body = serde_json::to_vec_pretty(&manifest)?;
    zip.start_file("evidence_bundle_manifest.json", options)
        .map_err(zip_error)?;
    zip.write_all(&manifest_body).with_path(&tmp_path)?;
    zip.finish().map_err(zip_error)?;
    std::fs::rename(&tmp_path, output).with_path(output)?;
    Ok(manifest)
}

fn default_lab_extra_files(lab_run_dir: &Path) -> Vec<EvidenceBundleExtraFile> {
    [
        ("scenario", "scenario.yaml", "scenario.yaml"),
        ("acceptance", "acceptance.json", "acceptance.json"),
        ("comparison", "comparison.json", "comparison.json"),
        (
            "multi_source_evidence",
            "multi_source_evidence.json",
            "multi_source_evidence.json",
        ),
        (
            "lab_connector_health",
            "connector_health.json",
            "lab_connector_health.json",
        ),
    ]
    .into_iter()
    .map(|(key, file_name, zip_path)| EvidenceBundleExtraFile {
        key: key.to_string(),
        path: lab_run_dir.join(file_name),
        zip_path: zip_path.to_string(),
    })
    .collect()
}

fn add_readme(
    zip: &mut ZipWriter<File>,
    options: SimpleFileOptions,
    run_id: &str,
    used_paths: &mut BTreeSet<String>,
) -> Result<()> {
    let body = format!(
        "# NetDiag Twin Evidence Bundle\n\nRun ID: `{run_id}`\n\nThis bundle contains the machine-readable artifacts needed to review a diagnosis, connector health, ML inference, recommendations, and what-if evidence. Treat telemetry artifacts as operational data and apply the lab's retention policy before sharing.\n"
    );
    let zip_path = "README-evidence.md".to_string();
    used_paths.insert(zip_path.clone());
    zip.start_file(zip_path, options).map_err(zip_error)?;
    zip.write_all(body.as_bytes())
        .map_err(|source| NetdiagError::Io {
            path: PathBuf::from("README-evidence.md"),
            source,
        })?;
    Ok(())
}

fn add_artifact_file(
    zip: &mut ZipWriter<File>,
    options: SimpleFileOptions,
    artifact: RunArtifactEntry,
    manifest: &mut EvidenceBundleManifest,
    used_paths: &mut BTreeSet<String>,
) -> Result<()> {
    if !artifact.exists {
        return Ok(());
    }
    let path = PathBuf::from(&artifact.path);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}.json", artifact.key));
    add_path_file(
        zip,
        options,
        &artifact.key,
        &path,
        &file_name,
        manifest,
        used_paths,
    )
}

fn artifact_path_is_inside_run(artifact: &RunArtifactEntry, run_dir: &Path) -> bool {
    let path = PathBuf::from(&artifact.path);
    let Ok(path) = path.canonicalize() else {
        return false;
    };
    let Ok(run_dir) = run_dir.canonicalize() else {
        return false;
    };
    path.starts_with(run_dir)
}

fn add_path_file(
    zip: &mut ZipWriter<File>,
    options: SimpleFileOptions,
    key: &str,
    path: &Path,
    zip_path: &str,
    manifest: &mut EvidenceBundleManifest,
    used_paths: &mut BTreeSet<String>,
) -> Result<()> {
    if !path.exists() || !path.is_file() {
        return Ok(());
    }
    let zip_path = unique_zip_path(zip_path, used_paths);
    let bytes = read_file_bytes(path)?;
    zip.start_file(&zip_path, options).map_err(zip_error)?;
    zip.write_all(&bytes).with_path(path)?;
    manifest.files.push(EvidenceBundleFile {
        key: key.to_string(),
        source_path: path.display().to_string(),
        zip_path,
        bytes: bytes.len() as u64,
        sha256: sha256_bytes(&bytes),
    });
    Ok(())
}

fn add_topology_snapshots(
    zip: &mut ZipWriter<File>,
    options: SimpleFileOptions,
    artifact_root: &Path,
    run_id: &str,
    manifest: &mut EvidenceBundleManifest,
    used_paths: &mut BTreeSet<String>,
) -> Result<()> {
    let Ok(report) = read_report(artifact_root, run_id) else {
        return Ok(());
    };
    if let Some(what_if) = report.what_if {
        if let Some(topology) = what_if.topology_snapshot {
            add_virtual_topology(
                zip,
                options,
                "topology",
                "topology.json",
                &topology,
                manifest,
                used_paths,
            )?;
        }
        if let Some(topology) = what_if.modified_topology_snapshot {
            add_virtual_topology(
                zip,
                options,
                "modified_topology",
                "modified_topology.json",
                &topology,
                manifest,
                used_paths,
            )?;
        }
    }
    Ok(())
}

fn add_virtual_topology(
    zip: &mut ZipWriter<File>,
    options: SimpleFileOptions,
    key: &str,
    zip_path: &str,
    topology: &TopologyModel,
    manifest: &mut EvidenceBundleManifest,
    used_paths: &mut BTreeSet<String>,
) -> Result<()> {
    let zip_path = unique_zip_path(zip_path, used_paths);
    let bytes = serde_json::to_vec_pretty(topology)?;
    zip.start_file(&zip_path, options).map_err(zip_error)?;
    zip.write_all(&bytes).map_err(|source| NetdiagError::Io {
        path: PathBuf::from(&zip_path),
        source,
    })?;
    manifest.files.push(EvidenceBundleFile {
        key: key.to_string(),
        source_path: "report.what_if".to_string(),
        zip_path,
        bytes: bytes.len() as u64,
        sha256: sha256_bytes(&bytes),
    });
    Ok(())
}

fn unique_zip_path(path: &str, used_paths: &mut BTreeSet<String>) -> String {
    if used_paths.insert(path.to_string()) {
        return path.to_string();
    }
    let raw = Path::new(path);
    let stem = raw
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    let extension = raw
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    for idx in 2.. {
        let candidate = if extension.is_empty() {
            format!("{stem}-{idx}")
        } else {
            format!("{stem}-{idx}.{extension}")
        };
        if used_paths.insert(candidate.clone()) {
            return candidate;
        }
    }
    unreachable!("unbounded suffix search returns")
}

fn read_file_bytes(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).with_path(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).with_path(path)?;
    Ok(bytes)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn zip_error(err: zip::result::ZipError) -> NetdiagError {
    NetdiagError::InvalidTrace(format!("zip export failed: {err}"))
}
