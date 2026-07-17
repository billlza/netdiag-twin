use crate::error::Result;
use crate::storage::{PathStatus, path_status};
use std::path::Path;

pub(super) fn validate(root: &Path) -> Result<bool> {
    let has_run_index = path_status(&root.join("run_index.json"))? == PathStatus::RegularFile;
    let has_run_directory = ["runs", "lab-runs", "pilot-runs"]
        .into_iter()
        .map(|name| path_status(&root.join(name)))
        .collect::<Result<Vec<_>>>()?
        .contains(&PathStatus::Directory);
    if !has_run_index && !has_run_directory {
        return Ok(false);
    }

    let entries = crate::storage::list_run_index(root)?;
    if entries.is_empty() {
        return Ok(false);
    }
    for entry in entries {
        crate::storage::run_history_entry(root, entry)?;
    }
    Ok(true)
}
