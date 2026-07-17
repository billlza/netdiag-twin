use super::adapter_contract::{validate_adapter_options, validated_adapter_contract};
use super::{PILOT_SCHEMA, PilotManifest, PilotSourceKind, PilotSourceRole, bearer};
use crate::error::{NetdiagError, Result};
use crate::identifiers::validate_portable_id;
use crate::resource_limits::MAX_DECLARED_SOURCES as MAX_PILOT_SOURCES;
use std::collections::BTreeSet;

mod adapter_boundary;
use adapter_boundary::validate_adapter_boundary_declaration;

pub fn validate_pilot_manifest(manifest: &PilotManifest) -> Result<()> {
    if manifest.schema.trim() != PILOT_SCHEMA {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported pilot schema: {}",
            manifest.schema
        )));
    }
    validate_portable_id("pilot id", &manifest.id)?;
    if manifest.name.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "pilot {} name is empty",
            manifest.id
        )));
    }
    if manifest.sources.is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "pilot {} has no sources",
            manifest.id
        )));
    }
    if manifest.sources.len() > MAX_PILOT_SOURCES {
        return Err(NetdiagError::InvalidTrace(format!(
            "pilot {} has more than {MAX_PILOT_SOURCES} sources",
            manifest.id
        )));
    }
    validate_sources(manifest)?;
    validate_adapter_boundary_declaration(manifest)?;
    let primary_count = manifest
        .sources
        .iter()
        .filter(|source| source.role == PilotSourceRole::Primary)
        .count();
    if primary_count != 1 {
        return Err(NetdiagError::InvalidTrace(format!(
            "pilot {} must declare exactly one primary source",
            manifest.id
        )));
    }
    Ok(())
}

fn validate_sources(manifest: &PilotManifest) -> Result<()> {
    let mut names = BTreeSet::new();
    for source in &manifest.sources {
        validate_portable_id("pilot source name", &source.name)?;
        source.collection.validate()?;
        if !names.insert(source.name.to_ascii_lowercase()) {
            return Err(NetdiagError::InvalidTrace(format!(
                "pilot {} has duplicate source name {:?}",
                manifest.id, source.name
            )));
        }
        bearer::declaration(source)?;
        if source.kind == PilotSourceKind::AdapterSample {
            validated_adapter_contract(source)?;
            validate_adapter_options(source)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
