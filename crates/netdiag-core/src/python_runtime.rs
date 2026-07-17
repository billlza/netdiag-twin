use crate::error::{NetdiagError, Result};
#[cfg(unix)]
use std::env;
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod configured;
#[cfg(unix)]
use configured::resolve_configured_interpreter;
#[cfg(unix)]
mod discovery;
#[cfg(unix)]
use discovery::resolve_platform_default;
#[cfg(unix)]
mod path_entries;

#[cfg(unix)]
const MAX_REJECTION_DETAILS: usize = 16;
#[cfg(unix)]
const MAX_REJECTION_DETAIL_CHARS: usize = 512;

#[derive(Debug)]
pub(crate) struct ResolvedInterpreter {
    path: PathBuf,
    runtime_path: String,
}

impl ResolvedInterpreter {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn runtime_path(&self) -> &str {
        &self.runtime_path
    }
}

pub(crate) fn resolve_python_interpreter(configured: Option<&str>) -> Result<ResolvedInterpreter> {
    #[cfg(unix)]
    {
        match configured {
            Some(path) => resolve_configured_interpreter(path),
            None => resolve_platform_default(),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = configured;
        resolve_platform_default()
    }
}

#[derive(Debug)]
#[cfg(unix)]
pub(crate) struct TrustedPythonRuntime {
    executable: PathBuf,
    runtime_path: String,
}

#[cfg(unix)]
impl TrustedPythonRuntime {
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(crate) fn runtime_path(&self) -> &str {
        &self.runtime_path
    }
}

#[cfg(unix)]
pub(crate) fn resolve_trusted_python_runtime(
    configured_interpreter: &Path,
) -> Result<TrustedPythonRuntime> {
    let configured_interpreter = configured_interpreter.to_str().ok_or_else(|| {
        NetdiagError::Connector(format!(
            "configured Python interpreter path is not valid Unicode: {}",
            configured_interpreter.display()
        ))
    })?;
    let configured = resolve_python_interpreter(Some(configured_interpreter))?;
    let platform = resolve_python_interpreter(None)?;
    Ok(TrustedPythonRuntime {
        executable: configured.path().to_path_buf(),
        runtime_path: platform.runtime_path().to_string(),
    })
}

#[cfg(not(unix))]
fn resolve_platform_default() -> Result<ResolvedInterpreter> {
    Err(NetdiagError::Connector(
        "Python adapter execution is disabled on this platform because interpreter and ancestor ACL trust cannot yet be proven"
            .to_string(),
    ))
}

#[cfg(unix)]
fn joined_runtime_path<'a>(paths: impl IntoIterator<Item = &'a PathBuf>) -> Result<String> {
    let joined = env::join_paths(paths).map_err(|error| {
        NetdiagError::Connector(format!(
            "failed to construct sanitized adapter PATH: {error}"
        ))
    })?;
    joined.into_string().map_err(|_| {
        NetdiagError::Connector("sanitized adapter PATH is not valid Unicode".to_string())
    })
}

#[cfg(unix)]
fn record_rejection(rejections: &mut Vec<String>, detail: String) {
    if rejections.len() >= MAX_REJECTION_DETAILS {
        return;
    }
    let mut chars = detail.chars();
    let bounded = chars
        .by_ref()
        .take(MAX_REJECTION_DETAIL_CHARS)
        .collect::<String>();
    rejections.push(if chars.next().is_some() {
        format!("{bounded}...")
    } else {
        bounded
    });
}

#[cfg(test)]
mod tests;
