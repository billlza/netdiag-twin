use super::typed_json::{
    MAX_LAB_RUN_INDEX_BYTES, MAX_LAB_RUN_INDEX_ENTRIES, ensure_collection_limit,
    read_optional_stable_json_bounded,
};
use super::{PathStatus, optional_regular_file, path_status};
use crate::error::{IoContext, NetdiagError, Result};
use crate::identifiers::validate_portable_id;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) const MAX_DISCOVERED_RUN_LOCATIONS: usize = 10_000;

pub fn run_dir(artifact_root: impl AsRef<Path>, run_id: &str) -> Result<PathBuf> {
    validate_portable_id("run id", run_id)?;
    Ok(artifact_root.as_ref().join("runs").join(run_id))
}

pub fn resolve_stored_path(artifact_root: &Path, value: &str) -> Result<PathBuf> {
    if value.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace(
            "stored artifact path is empty".to_string(),
        ));
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return Err(NetdiagError::InvalidTrace(format!(
            "stored artifact path must be relative to the artifact root: {value}"
        )));
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return Err(NetdiagError::InvalidTrace(format!(
            "stored artifact path escapes the artifact root: {value}"
        )));
    }

    let artifact_relative = artifact_root.join(&path);
    if path_status(&artifact_relative)?.exists() {
        return ensure_existing_path_is_confined(artifact_root, artifact_relative);
    }

    if let (Some(parent), Some(root_name), Some(first)) = (
        artifact_root.parent(),
        artifact_root.file_name(),
        path.components().next(),
    ) && first.as_os_str() == root_name
    {
        let legacy_cwd_relative = parent.join(&path);
        if path_status(&legacy_cwd_relative)?.exists() {
            return ensure_existing_path_is_confined(artifact_root, legacy_cwd_relative);
        }
    }

    ensure_nonexistent_path_is_confined(artifact_root, &artifact_relative)?;
    Ok(artifact_relative)
}

fn ensure_existing_path_is_confined(artifact_root: &Path, candidate: PathBuf) -> Result<PathBuf> {
    let canonical_root = fs::canonicalize(artifact_root).with_path(artifact_root)?;
    let canonical_candidate = fs::canonicalize(&candidate).with_path(&candidate)?;
    if canonical_candidate.starts_with(&canonical_root) {
        Ok(candidate)
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "stored artifact path resolves outside the artifact root: {}",
            candidate.display()
        )))
    }
}

fn ensure_nonexistent_path_is_confined(artifact_root: &Path, candidate: &Path) -> Result<()> {
    let canonical_root = fs::canonicalize(artifact_root).with_path(artifact_root)?;
    let mut ancestor = candidate;
    while !path_status(ancestor)?.exists() {
        ancestor = ancestor.parent().ok_or_else(|| {
            NetdiagError::InvalidTrace(format!(
                "stored artifact path has no existing ancestor: {}",
                candidate.display()
            ))
        })?;
    }
    let canonical_ancestor = fs::canonicalize(ancestor).with_path(ancestor)?;
    if canonical_ancestor.starts_with(&canonical_root) {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "stored artifact path has an ancestor outside the artifact root: {}",
            candidate.display()
        )))
    }
}

#[derive(Debug, Clone)]
pub struct RunLocation {
    pub artifact_root: PathBuf,
    pub run_dir: PathBuf,
    pub lab_run_dir: Option<PathBuf>,
    pub lab_index_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
struct LabRunIndexDisk {
    schema: String,
    #[serde(default)]
    runs: Vec<LabRunIndexEntryDisk>,
}

#[derive(Debug, Clone, Deserialize)]
struct LabRunIndexEntryDisk {
    run_id: String,
    lab_run_dir: String,
    pipeline_run_dir: String,
}

pub fn resolve_run_location(artifact_root: impl AsRef<Path>, run_id: &str) -> Result<RunLocation> {
    find_run_location(artifact_root, run_id)?
        .ok_or_else(|| NetdiagError::InvalidTrace(format!("unknown run id: {run_id}")))
}

pub(crate) fn find_run_location(
    artifact_root: impl AsRef<Path>,
    run_id: &str,
) -> Result<Option<RunLocation>> {
    validate_portable_id("run id", run_id)?;
    let artifact_root = artifact_root.as_ref();
    if let Some(location) = top_level_run_location(artifact_root, run_id)? {
        return Ok(Some(location));
    }
    if let Some(location) = lab_index_run_location(artifact_root, run_id)? {
        return Ok(Some(location));
    }
    if let Some(location) = scan_lab_run_location(artifact_root, run_id)? {
        return Ok(Some(location));
    }
    if let Some(location) = scan_pilot_run_location(artifact_root, run_id)? {
        return Ok(Some(location));
    }
    Ok(None)
}

pub fn list_run_locations(artifact_root: impl AsRef<Path>) -> Result<Vec<RunLocation>> {
    let artifact_root = artifact_root.as_ref();
    let mut locations = Vec::new();
    let mut seen = BTreeSet::new();

    for location in scan_top_level_run_locations(artifact_root)? {
        if seen.insert(location.run_dir.display().to_string()) {
            push_discovered_location(&mut locations, location)?;
        }
    }
    for location in lab_index_run_locations(artifact_root)? {
        if seen.insert(location.run_dir.display().to_string()) {
            push_discovered_location(&mut locations, location)?;
        }
    }
    for location in scan_lab_run_locations(artifact_root)? {
        if seen.insert(location.run_dir.display().to_string()) {
            push_discovered_location(&mut locations, location)?;
        }
    }
    for location in scan_pilot_run_locations(artifact_root)? {
        if seen.insert(location.run_dir.display().to_string()) {
            push_discovered_location(&mut locations, location)?;
        }
    }
    locations.sort_by(|left, right| left.run_dir.cmp(&right.run_dir));
    Ok(locations)
}

fn top_level_run_location(artifact_root: &Path, run_id: &str) -> Result<Option<RunLocation>> {
    let run_dir_path = run_dir(artifact_root, run_id)?;
    let manifest_path = run_dir_path.join("manifest.json");
    match fs::symlink_metadata(&manifest_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => {
            return Err(NetdiagError::InvalidTrace(format!(
                "run manifest is not a regular file: {}",
                manifest_path.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(NetdiagError::Io {
                path: manifest_path,
                source,
            });
        }
    }
    ensure_directory_confined(artifact_root, &run_dir_path)?;
    let scenario_path = artifact_root.join("scenario.yaml");
    let pilot_path = artifact_root.join("pilot.yaml");
    let lab_run_dir = (path_status(&scenario_path)?.exists() || path_status(&pilot_path)?.exists())
        .then(|| artifact_root.to_path_buf());
    Ok(Some(RunLocation {
        artifact_root: artifact_root.to_path_buf(),
        run_dir: run_dir_path,
        lab_run_dir,
        lab_index_root: None,
    }))
}

fn scan_top_level_run_locations(artifact_root: &Path) -> Result<Vec<RunLocation>> {
    let runs_dir = artifact_root.join("runs");
    match path_status(&runs_dir)? {
        PathStatus::Missing => return Ok(Vec::new()),
        PathStatus::Directory => {}
        _ => {
            return Err(NetdiagError::InvalidTrace(format!(
                "runs path is not a regular directory: {}",
                runs_dir.display()
            )));
        }
    }
    ensure_directory_confined(artifact_root, &runs_dir)?;
    let mut locations = Vec::new();
    for entry in fs::read_dir(&runs_dir).with_path(&runs_dir)? {
        let entry = entry.with_path(&runs_dir)?;
        let path = entry.path();
        if hidden_path(&path) || !optional_discovered_directory(&path, "run directory")? {
            continue;
        }
        let manifest_path = path.join("manifest.json");
        if !optional_regular_file(&manifest_path, "run manifest")? {
            continue;
        }
        ensure_directory_confined(artifact_root, &path)?;
        validate_directory_id("run directory id", &path)?;
        push_discovered_location(
            &mut locations,
            RunLocation {
                artifact_root: artifact_root.to_path_buf(),
                run_dir: path,
                lab_run_dir: None,
                lab_index_root: None,
            },
        )?;
    }
    Ok(locations)
}

fn read_lab_run_index_disk(artifact_root: &Path) -> Result<Option<LabRunIndexDisk>> {
    let index_path = artifact_root.join("lab_run_index.json");
    let Some(index) = read_optional_stable_json_bounded::<LabRunIndexDisk>(
        &index_path,
        MAX_LAB_RUN_INDEX_BYTES,
        "lab run index",
    )?
    else {
        return Ok(None);
    };
    if index.schema != "netdiag-lab-run-index/v1" {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported lab run index schema: {}",
            index.schema
        )));
    }
    ensure_collection_limit("lab run index", index.runs.len(), MAX_LAB_RUN_INDEX_ENTRIES)?;
    let mut run_ids = BTreeSet::new();
    for entry in &index.runs {
        validate_portable_id("indexed lab run id", &entry.run_id)?;
        if !run_ids.insert(entry.run_id.as_str()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "duplicate lab run id in index: {}",
                entry.run_id
            )));
        }
    }
    Ok(Some(index))
}

fn lab_index_run_location(artifact_root: &Path, run_id: &str) -> Result<Option<RunLocation>> {
    let Some(index) = read_lab_run_index_disk(artifact_root)? else {
        return Ok(None);
    };
    for entry in index.runs {
        if entry.run_id != run_id {
            continue;
        }
        if let Some(location) = lab_entry_location(artifact_root, &entry)? {
            return Ok(Some(location));
        }
    }
    Ok(None)
}

fn lab_index_run_locations(artifact_root: &Path) -> Result<Vec<RunLocation>> {
    let Some(index) = read_lab_run_index_disk(artifact_root)? else {
        return Ok(Vec::new());
    };
    index
        .runs
        .iter()
        .filter_map(|entry| match lab_entry_location(artifact_root, entry) {
            Ok(Some(location)) => Some(Ok(location)),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn lab_entry_location(
    artifact_root: &Path,
    entry: &LabRunIndexEntryDisk,
) -> Result<Option<RunLocation>> {
    validate_portable_id("indexed run id", &entry.run_id)?;
    let lab_run_dir = resolve_stored_path(artifact_root, &entry.lab_run_dir)?;
    let pipeline_run_dir = resolve_stored_path(artifact_root, &entry.pipeline_run_dir)?;
    let lab_manifest = run_dir(&lab_run_dir, &entry.run_id)?.join("manifest.json");
    let pipeline_manifest = pipeline_run_dir.join("manifest.json");
    let artifact_candidate = if optional_regular_file(&lab_manifest, "indexed run manifest")? {
        lab_run_dir.clone()
    } else if optional_regular_file(&pipeline_manifest, "indexed pipeline run manifest")? {
        pipeline_run_dir
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| {
                NetdiagError::InvalidTrace(format!(
                    "indexed pipeline run path has no artifact root: {}",
                    pipeline_run_dir.display()
                ))
            })?
            .to_path_buf()
    } else {
        return Ok(None);
    };
    Ok(Some(RunLocation {
        run_dir: run_dir(&artifact_candidate, &entry.run_id)?,
        artifact_root: artifact_candidate,
        lab_run_dir: Some(lab_run_dir),
        lab_index_root: Some(artifact_root.to_path_buf()),
    }))
}

fn scan_lab_run_location(artifact_root: &Path, run_id: &str) -> Result<Option<RunLocation>> {
    Ok(scan_lab_run_locations(artifact_root)?
        .into_iter()
        .find(|location| {
            location.run_dir.file_name().and_then(|name| name.to_str()) == Some(run_id)
        }))
}

fn scan_lab_run_locations(artifact_root: &Path) -> Result<Vec<RunLocation>> {
    let lab_runs_dir = artifact_root.join("lab-runs");
    match path_status(&lab_runs_dir)? {
        PathStatus::Missing => return Ok(Vec::new()),
        PathStatus::Directory => {}
        _ => {
            return Err(NetdiagError::InvalidTrace(format!(
                "lab runs path is not a regular directory: {}",
                lab_runs_dir.display()
            )));
        }
    }
    ensure_directory_confined(artifact_root, &lab_runs_dir)?;
    let mut locations = Vec::new();
    for scenario in fs::read_dir(&lab_runs_dir).with_path(&lab_runs_dir)? {
        let scenario = scenario.with_path(&lab_runs_dir)?;
        let scenario_path = scenario.path();
        if hidden_path(&scenario_path)
            || !optional_discovered_directory(&scenario_path, "lab scenario directory")?
        {
            continue;
        }
        ensure_directory_confined(artifact_root, &scenario_path)?;
        validate_directory_id("lab scenario directory id", &scenario_path)?;
        for lab_run in fs::read_dir(&scenario_path).with_path(&scenario_path)? {
            let lab_run = lab_run.with_path(&scenario_path)?;
            let lab_run_dir = lab_run.path();
            let runs_dir = lab_run_dir.join("runs");
            if hidden_path(&lab_run_dir)
                || !optional_discovered_directory(&lab_run_dir, "lab run directory")?
            {
                continue;
            }
            ensure_directory_confined(artifact_root, &lab_run_dir)?;
            validate_directory_id("lab run directory id", &lab_run_dir)?;
            if !optional_discovered_directory(&runs_dir, "lab pipeline runs directory")? {
                continue;
            }
            ensure_directory_confined(artifact_root, &runs_dir)?;
            for run in fs::read_dir(&runs_dir).with_path(&runs_dir)? {
                let run = run.with_path(&runs_dir)?;
                let run_dir_path = run.path();
                if hidden_path(&run_dir_path)
                    || !optional_discovered_directory(&run_dir_path, "lab pipeline run directory")?
                {
                    continue;
                }
                let manifest_path = run_dir_path.join("manifest.json");
                if !optional_regular_file(&manifest_path, "lab run manifest")? {
                    continue;
                }
                ensure_directory_confined(artifact_root, &run_dir_path)?;
                validate_directory_id("run directory id", &run_dir_path)?;
                push_discovered_location(
                    &mut locations,
                    RunLocation {
                        artifact_root: lab_run_dir.clone(),
                        run_dir: run_dir_path,
                        lab_run_dir: Some(lab_run_dir.clone()),
                        lab_index_root: Some(artifact_root.to_path_buf()),
                    },
                )?;
            }
        }
    }
    Ok(locations)
}

fn scan_pilot_run_location(artifact_root: &Path, run_id: &str) -> Result<Option<RunLocation>> {
    Ok(scan_pilot_run_locations(artifact_root)?
        .into_iter()
        .find(|location| {
            location.run_dir.file_name().and_then(|name| name.to_str()) == Some(run_id)
        }))
}

fn scan_pilot_run_locations(artifact_root: &Path) -> Result<Vec<RunLocation>> {
    let pilot_runs_dir = artifact_root.join("pilot-runs");
    match path_status(&pilot_runs_dir)? {
        PathStatus::Missing => return Ok(Vec::new()),
        PathStatus::Directory => {}
        _ => {
            return Err(NetdiagError::InvalidTrace(format!(
                "pilot runs path is not a regular directory: {}",
                pilot_runs_dir.display()
            )));
        }
    }
    ensure_directory_confined(artifact_root, &pilot_runs_dir)?;

    let mut locations = Vec::new();
    for pilot in fs::read_dir(&pilot_runs_dir).with_path(&pilot_runs_dir)? {
        let pilot = pilot.with_path(&pilot_runs_dir)?;
        let pilot_dir = pilot.path();
        if hidden_path(&pilot_dir) || !optional_discovered_directory(&pilot_dir, "pilot directory")?
        {
            continue;
        }
        ensure_directory_confined(artifact_root, &pilot_dir)?;
        validate_directory_id("pilot directory id", &pilot_dir)?;
        for run_set in fs::read_dir(&pilot_dir).with_path(&pilot_dir)? {
            let run_set = run_set.with_path(&pilot_dir)?;
            let pilot_run_dir = run_set.path();
            let runs_dir = pilot_run_dir.join("runs");
            if hidden_path(&pilot_run_dir)
                || !optional_discovered_directory(&pilot_run_dir, "pilot run directory")?
            {
                continue;
            }
            ensure_directory_confined(artifact_root, &pilot_run_dir)?;
            validate_directory_id("pilot run directory id", &pilot_run_dir)?;
            if !optional_discovered_directory(&runs_dir, "pilot pipeline runs directory")? {
                continue;
            }
            ensure_directory_confined(artifact_root, &runs_dir)?;
            for run in fs::read_dir(&runs_dir).with_path(&runs_dir)? {
                let run = run.with_path(&runs_dir)?;
                let run_dir_path = run.path();
                if hidden_path(&run_dir_path)
                    || !optional_discovered_directory(
                        &run_dir_path,
                        "pilot pipeline run directory",
                    )?
                {
                    continue;
                }
                let manifest_path = run_dir_path.join("manifest.json");
                if !optional_regular_file(&manifest_path, "pilot run manifest")? {
                    continue;
                }
                ensure_directory_confined(artifact_root, &run_dir_path)?;
                validate_directory_id("run directory id", &run_dir_path)?;
                push_discovered_location(
                    &mut locations,
                    RunLocation {
                        artifact_root: pilot_run_dir.clone(),
                        run_dir: run_dir_path,
                        lab_run_dir: Some(pilot_run_dir.clone()),
                        lab_index_root: Some(artifact_root.to_path_buf()),
                    },
                )?;
            }
        }
    }
    Ok(locations)
}

fn push_discovered_location(locations: &mut Vec<RunLocation>, location: RunLocation) -> Result<()> {
    ensure_discovery_capacity(locations.len())?;
    locations.push(location);
    Ok(())
}

fn ensure_discovery_capacity(discovered: usize) -> Result<()> {
    if discovered >= MAX_DISCOVERED_RUN_LOCATIONS {
        return Err(NetdiagError::InvalidTrace(format!(
            "run discovery exceeds the {MAX_DISCOVERED_RUN_LOCATIONS}-location safety limit"
        )));
    }
    Ok(())
}

fn hidden_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

fn optional_discovered_directory(path: &Path, kind: &str) -> Result<bool> {
    match path_status(path)? {
        PathStatus::Missing | PathStatus::RegularFile => Ok(false),
        PathStatus::Directory => Ok(true),
        PathStatus::Other => Err(NetdiagError::InvalidTrace(format!(
            "{kind} is not a regular directory: {}",
            path.display()
        ))),
    }
}

fn validate_directory_id(kind: &str, path: &Path) -> Result<()> {
    let value = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(format!("{kind} is not valid UTF-8: {}", path.display()))
        })?;
    validate_portable_id(kind, value)
}

fn ensure_directory_confined(artifact_root: &Path, path: &Path) -> Result<()> {
    if fs::symlink_metadata(path)
        .with_path(path)?
        .file_type()
        .is_symlink()
    {
        return Err(NetdiagError::InvalidTrace(format!(
            "artifact directory must not be a symbolic link: {}",
            path.display()
        )));
    }
    let canonical_root = fs::canonicalize(artifact_root).with_path(artifact_root)?;
    let canonical_path = fs::canonicalize(path).with_path(path)?;
    if canonical_path.starts_with(canonical_root) {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "artifact directory resolves outside the artifact root: {}",
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_discovery_limit_rejects_the_first_excess_location() {
        ensure_discovery_capacity(MAX_DISCOVERED_RUN_LOCATIONS - 1).expect("last allowed slot");
        let error = ensure_discovery_capacity(MAX_DISCOVERED_RUN_LOCATIONS)
            .expect_err("first excess location must fail");
        assert!(error.to_string().contains("safety limit"), "{error}");
    }
}
