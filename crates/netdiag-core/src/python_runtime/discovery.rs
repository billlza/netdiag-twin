use super::configured::validate_interpreter;
use super::path_entries::trusted_path_entries;
use super::{ResolvedInterpreter, joined_runtime_path, record_rejection};
use crate::error::{NetdiagError, Result};
use std::env;
use std::ffi::OsStr;

pub(super) fn resolve_platform_default() -> Result<ResolvedInterpreter> {
    let path = env::var_os("PATH");
    resolve_from_path(path.as_deref())
}

fn resolve_from_path(path: Option<&OsStr>) -> Result<ResolvedInterpreter> {
    let path = path.ok_or_else(|| {
        NetdiagError::Connector(
            "cannot resolve a trusted Python interpreter because PATH is not set".to_string(),
        )
    })?;
    let search = trusted_path_entries(path)?;
    let runtime_path = joined_runtime_path(search.entries.iter())?;
    let mut rejections = search.rejections;
    for directory in search.entries {
        let candidate = directory.join("python3");
        let canonical = match candidate.canonicalize() {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                record_rejection(
                    &mut rejections,
                    format!(
                        "interpreter_canonicalize_error(path={}, cause={error})",
                        candidate.display()
                    ),
                );
                continue;
            }
        };
        if let Err(error) = validate_interpreter(&canonical) {
            record_rejection(&mut rejections, error.to_string());
            continue;
        }
        return Ok(ResolvedInterpreter {
            path: canonical,
            runtime_path,
        });
    }
    let details = if rejections.is_empty() {
        "trusted PATH directories contained no python3 candidate".to_string()
    } else {
        rejections.join("; ")
    };
    Err(NetdiagError::Connector(format!(
        "no trusted executable python3 interpreter was found ({details})"
    )))
}

#[cfg(test)]
mod tests;
