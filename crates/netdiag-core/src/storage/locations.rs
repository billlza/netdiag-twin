use super::read_json;
use crate::error::{IoContext, NetdiagError, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run_dir(artifact_root: impl AsRef<Path>, run_id: &str) -> PathBuf {
    artifact_root.as_ref().join("runs").join(run_id)
}

pub fn resolve_stored_path(artifact_root: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        return path;
    }

    let artifact_relative = artifact_root.join(&path);
    if artifact_relative.exists() {
        return artifact_relative;
    }

    if let (Some(parent), Some(root_name), Some(first)) = (
        artifact_root.parent(),
        artifact_root.file_name(),
        path.components().next(),
    ) && first.as_os_str() == root_name
    {
        let legacy_cwd_relative = parent.join(&path);
        if legacy_cwd_relative.exists() {
            return legacy_cwd_relative;
        }
    }

    artifact_relative
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
    let artifact_root = artifact_root.as_ref();
    if let Some(location) = top_level_run_location(artifact_root, run_id) {
        return Ok(location);
    }
    if let Some(location) = lab_index_run_location(artifact_root, run_id)? {
        return Ok(location);
    }
    if let Some(location) = scan_lab_run_location(artifact_root, run_id)? {
        return Ok(location);
    }
    if let Some(location) = scan_pilot_run_location(artifact_root, run_id)? {
        return Ok(location);
    }
    Err(NetdiagError::InvalidTrace(format!(
        "unknown run id: {run_id}"
    )))
}

pub fn list_run_locations(artifact_root: impl AsRef<Path>) -> Result<Vec<RunLocation>> {
    let artifact_root = artifact_root.as_ref();
    let mut locations = Vec::new();
    let mut seen = BTreeSet::new();

    for location in scan_top_level_run_locations(artifact_root)? {
        if seen.insert(location.run_dir.display().to_string()) {
            locations.push(location);
        }
    }
    for location in lab_index_run_locations(artifact_root)? {
        if seen.insert(location.run_dir.display().to_string()) {
            locations.push(location);
        }
    }
    for location in scan_lab_run_locations(artifact_root)? {
        if seen.insert(location.run_dir.display().to_string()) {
            locations.push(location);
        }
    }
    for location in scan_pilot_run_locations(artifact_root)? {
        if seen.insert(location.run_dir.display().to_string()) {
            locations.push(location);
        }
    }
    locations.sort_by(|left, right| left.run_dir.cmp(&right.run_dir));
    Ok(locations)
}

fn top_level_run_location(artifact_root: &Path, run_id: &str) -> Option<RunLocation> {
    let run_dir_path = run_dir(artifact_root, run_id);
    run_dir_path.join("manifest.json").exists().then(|| {
        let lab_run_dir = artifact_root
            .join("scenario.yaml")
            .exists()
            .then(|| artifact_root.to_path_buf())
            .or_else(|| {
                artifact_root
                    .join("pilot.yaml")
                    .exists()
                    .then(|| artifact_root.to_path_buf())
            });
        RunLocation {
            artifact_root: artifact_root.to_path_buf(),
            run_dir: run_dir_path,
            lab_run_dir,
            lab_index_root: None,
        }
    })
}

fn scan_top_level_run_locations(artifact_root: &Path) -> Result<Vec<RunLocation>> {
    let runs_dir = artifact_root.join("runs");
    if !runs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut locations = Vec::new();
    for entry in fs::read_dir(&runs_dir).with_path(&runs_dir)? {
        let entry = entry.with_path(&runs_dir)?;
        let path = entry.path();
        if !path.is_dir() || hidden_path(&path) || !path.join("manifest.json").exists() {
            continue;
        }
        locations.push(RunLocation {
            artifact_root: artifact_root.to_path_buf(),
            run_dir: path,
            lab_run_dir: None,
            lab_index_root: None,
        });
    }
    Ok(locations)
}

fn read_lab_run_index_disk(artifact_root: &Path) -> Result<Option<LabRunIndexDisk>> {
    let index_path = artifact_root.join("lab_run_index.json");
    if !index_path.exists() {
        return Ok(None);
    }
    serde_json::from_value(read_json(index_path)?)
        .map(Some)
        .map_err(NetdiagError::from)
}

fn lab_index_run_location(artifact_root: &Path, run_id: &str) -> Result<Option<RunLocation>> {
    let Some(index) = read_lab_run_index_disk(artifact_root)? else {
        return Ok(None);
    };
    for entry in index.runs {
        if entry.run_id != run_id {
            continue;
        }
        if let Some(location) = lab_entry_location(artifact_root, &entry) {
            return Ok(Some(location));
        }
    }
    Ok(None)
}

fn lab_index_run_locations(artifact_root: &Path) -> Result<Vec<RunLocation>> {
    let Some(index) = read_lab_run_index_disk(artifact_root)? else {
        return Ok(Vec::new());
    };
    Ok(index
        .runs
        .iter()
        .filter_map(|entry| lab_entry_location(artifact_root, entry))
        .collect())
}

fn lab_entry_location(artifact_root: &Path, entry: &LabRunIndexEntryDisk) -> Option<RunLocation> {
    let lab_run_dir = resolve_stored_path(artifact_root, &entry.lab_run_dir);
    let pipeline_run_dir = resolve_stored_path(artifact_root, &entry.pipeline_run_dir);
    let artifact_candidate = if run_dir(&lab_run_dir, &entry.run_id)
        .join("manifest.json")
        .exists()
    {
        lab_run_dir.clone()
    } else if pipeline_run_dir.join("manifest.json").exists() {
        pipeline_run_dir
            .parent()
            .and_then(Path::parent)
            .unwrap_or(&lab_run_dir)
            .to_path_buf()
    } else {
        return None;
    };
    Some(RunLocation {
        run_dir: run_dir(&artifact_candidate, &entry.run_id),
        artifact_root: artifact_candidate,
        lab_run_dir: Some(lab_run_dir),
        lab_index_root: Some(artifact_root.to_path_buf()),
    })
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
    if !lab_runs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut locations = Vec::new();
    for scenario in fs::read_dir(&lab_runs_dir).with_path(&lab_runs_dir)? {
        let scenario = scenario.with_path(&lab_runs_dir)?;
        let scenario_path = scenario.path();
        if !scenario_path.is_dir() || hidden_path(&scenario_path) {
            continue;
        }
        for lab_run in fs::read_dir(&scenario_path).with_path(&scenario_path)? {
            let lab_run = lab_run.with_path(&scenario_path)?;
            let lab_run_dir = lab_run.path();
            let runs_dir = lab_run_dir.join("runs");
            if !runs_dir.is_dir() || hidden_path(&lab_run_dir) {
                continue;
            }
            for run in fs::read_dir(&runs_dir).with_path(&runs_dir)? {
                let run = run.with_path(&runs_dir)?;
                let run_dir_path = run.path();
                if !run_dir_path.is_dir()
                    || hidden_path(&run_dir_path)
                    || !run_dir_path.join("manifest.json").exists()
                {
                    continue;
                }
                locations.push(RunLocation {
                    artifact_root: lab_run_dir.clone(),
                    run_dir: run_dir_path,
                    lab_run_dir: Some(lab_run_dir.clone()),
                    lab_index_root: Some(artifact_root.to_path_buf()),
                });
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
    if !pilot_runs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut locations = Vec::new();
    for pilot in fs::read_dir(&pilot_runs_dir).with_path(&pilot_runs_dir)? {
        let pilot = pilot.with_path(&pilot_runs_dir)?;
        let pilot_dir = pilot.path();
        if !pilot_dir.is_dir() || hidden_path(&pilot_dir) {
            continue;
        }
        for run_set in fs::read_dir(&pilot_dir).with_path(&pilot_dir)? {
            let run_set = run_set.with_path(&pilot_dir)?;
            let pilot_run_dir = run_set.path();
            let runs_dir = pilot_run_dir.join("runs");
            if !runs_dir.is_dir() || hidden_path(&pilot_run_dir) {
                continue;
            }
            for run in fs::read_dir(&runs_dir).with_path(&runs_dir)? {
                let run = run.with_path(&runs_dir)?;
                let run_dir_path = run.path();
                if !run_dir_path.is_dir()
                    || hidden_path(&run_dir_path)
                    || !run_dir_path.join("manifest.json").exists()
                {
                    continue;
                }
                locations.push(RunLocation {
                    artifact_root: pilot_run_dir.clone(),
                    run_dir: run_dir_path,
                    lab_run_dir: Some(pilot_run_dir.clone()),
                    lab_index_root: Some(artifact_root.to_path_buf()),
                });
            }
        }
    }
    Ok(locations)
}

fn hidden_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}
