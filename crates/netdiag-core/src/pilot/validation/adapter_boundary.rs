use crate::error::{NetdiagError, Result};
use crate::pilot::{PilotManifest, PilotSourceKind};
use std::path::Path;

mod budget;
use budget::validate_total_execution_budget;

pub(super) fn validate_adapter_boundary_declaration(manifest: &PilotManifest) -> Result<()> {
    let adapters = manifest
        .sources
        .iter()
        .filter(|source| source.kind == PilotSourceKind::AdapterSample)
        .collect::<Vec<_>>();
    if adapters.is_empty() {
        return Ok(());
    }
    let root = manifest
        .safety
        .adapter_execution_root
        .as_deref()
        .ok_or_else(|| {
            NetdiagError::InvalidTrace(
                "pilot manifests with adapters must declare safety.adapter_execution_root"
                    .to_string(),
            )
        })?;
    if root.trim().is_empty() || root.len() > 4 * 1024 || Path::new(root).is_absolute() {
        return Err(NetdiagError::InvalidTrace(
            "safety.adapter_execution_root must be a bounded path relative to the pilot manifest"
                .to_string(),
        ));
    }
    for source in adapters {
        if source.endpoint.trim().is_empty()
            || source.endpoint.len() > 4 * 1024
            || Path::new(&source.endpoint).is_absolute()
        {
            return Err(NetdiagError::InvalidTrace(format!(
                "adapter source {} endpoint must be a bounded path relative to the pilot manifest",
                source.name
            )));
        }
    }
    validate_total_execution_budget(manifest)
}
