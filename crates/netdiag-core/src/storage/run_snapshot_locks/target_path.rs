use crate::error::{IoContext, NetdiagError, Result};
use std::path::{Component, Path, PathBuf};

pub(crate) const HIL_REVIEW_JOURNAL_FILE_NAME: &str = "hil_review_transaction.json";
pub(crate) const ACTION_VERIFICATION_JOURNAL_FILE_NAME: &str =
    "action_verification_transaction.json";

pub(super) fn resolve_target_path(path: &Path) -> Result<PathBuf> {
    let absolute = lexical_absolute(path)?;
    absolute.file_name().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!("lock target must name a file: {}", path.display()))
    })?;
    absolute.parent().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "lock target has no parent directory: {}",
            path.display()
        ))
    })?;
    Ok(absolute)
}

fn lexical_absolute(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .with_path(Path::new("."))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(NetdiagError::InvalidTrace(format!(
                        "lock target escapes the filesystem root: {}",
                        path.display()
                    )));
                }
            }
        }
    }
    Ok(normalized)
}
