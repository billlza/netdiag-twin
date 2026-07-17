use anyhow::{Context, Result, anyhow};
use std::{
    io::{self, Write},
    path::Path,
};

pub(super) struct OwnedOutput {
    json: String,
}

impl OwnedOutput {
    pub(super) fn prepare(path: &Path) -> Result<Self> {
        let artifact_root = path.to_str().map(str::to_owned).ok_or_else(|| {
            anyhow!(
                "artifact root path must be valid UTF-8 before it can be represented in JSON output"
            )
        })?;
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "artifact_root": artifact_root,
            "status": "artifact_root_owned",
        }))?;
        Ok(Self { json })
    }

    pub(super) fn write(self) -> Result<()> {
        writeln!(io::stdout().lock(), "{}", self.json)
            .context("failed to write artifact root result")
    }
}
