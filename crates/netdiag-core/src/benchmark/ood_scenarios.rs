use crate::error::{IoContext, NetdiagError, Result};
use std::path::{Path, PathBuf};

pub(super) fn ood_scenario_paths(repo_root: &Path) -> Result<Vec<PathBuf>> {
    ood_scenario_paths_in(&repo_root.join("examples/scenarios"))
}

pub(super) fn ood_scenario_paths_in(scenario_root: &Path) -> Result<Vec<PathBuf>> {
    let entries = std::fs::read_dir(scenario_root).with_path(scenario_root)?;
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.with_path(scenario_root)?;
        let path = entry.path();
        if path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with("ood-") && name.ends_with(".yaml"))
        {
            paths.push(path);
        }
    }
    paths.sort();
    if paths.is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "no OOD benchmark scenarios found in {}",
            scenario_root.display()
        )));
    }
    Ok(paths)
}
