use super::pilot_sources::check_source_static_with_boundary;
use super::prepared::PreparedPilot;
use super::redaction::source_inventory;
use super::{PilotManifest, PilotOptions, PilotPreflightReport, bearer};
use crate::connectors::authentication::BearerEnvironmentBindings;
use crate::error::{NetdiagError, Result};
use crate::ml::{ModelBundleSnapshot, load_existing_model_bundle_snapshot};
use crate::models::ConnectorHealthStatus;
use crate::reliability::{ReliabilityCheck, ReliabilityReasonCode};
use crate::storage::{
    ArtifactRootCapability, ensure_artifact_root_owned, with_artifact_root_capability,
};
use chrono::Utc;
use std::path::Path;

const PILOT_PREFLIGHT_SCHEMA: &str = "netdiag-pilot-preflight/v1";

pub(super) struct PreparedPilotPreflight {
    pub(super) report: PilotPreflightReport,
    pub(super) model_snapshot: Option<ModelBundleSnapshot>,
}

pub(super) fn prepare_pilot_preflight(
    prepared: &PreparedPilot,
    options: &PilotOptions,
    bindings: &BearerEnvironmentBindings,
) -> Result<PreparedPilotPreflight> {
    let artifact_check = check_artifact_directory(&options.artifacts);
    let model = check_model_bundle(&options.artifacts);
    build_pilot_preflight(prepared, options, bindings, artifact_check, model)
}

pub(super) fn prepare_pilot_run_preflight(
    prepared: &PreparedPilot,
    options: &PilotOptions,
    bindings: &BearerEnvironmentBindings,
    capability: &ArtifactRootCapability,
) -> Result<PreparedPilotPreflight> {
    let (artifact_check, model) = with_artifact_root_capability(capability, |_| {
        Ok((
            artifact_directory_check(&options.artifacts, Ok(())),
            check_model_bundle(&options.artifacts),
        ))
    })?;
    build_pilot_preflight(prepared, options, bindings, artifact_check, model)
}

fn build_pilot_preflight(
    prepared: &PreparedPilot,
    options: &PilotOptions,
    bindings: &BearerEnvironmentBindings,
    artifact_check: ReliabilityCheck,
    (model_check, model_snapshot): (ReliabilityCheck, Option<ModelBundleSnapshot>),
) -> Result<PreparedPilotPreflight> {
    let manifest = &prepared.manifest;
    let declarations = bearer::declarations(manifest)?;
    bindings.validate_exact_declarations(&declarations)?;
    let mut checks = vec![artifact_check, model_check];
    checks.extend(check_pilot_safety(manifest, options.allow_active));
    checks.extend(manifest.sources.iter().map(|source| {
        check_source_static_with_boundary(
            source,
            &prepared.manifest_dir,
            prepared.adapter_boundary.as_ref(),
        )
    }));
    let passed = checks
        .iter()
        .all(|check| check.status != ConnectorHealthStatus::Error);
    Ok(PreparedPilotPreflight {
        report: PilotPreflightReport {
            schema: PILOT_PREFLIGHT_SCHEMA.to_string(),
            generated_at: Utc::now(),
            pilot_id: manifest.id.clone(),
            passed,
            source_inventory: source_inventory(manifest)?,
            checks,
        },
        model_snapshot,
    })
}

pub(super) fn require_model_snapshot(
    snapshot: Option<ModelBundleSnapshot>,
    context: &str,
) -> Result<ModelBundleSnapshot> {
    snapshot.ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "{context} preflight passed without an immutable model bundle snapshot"
        ))
    })
}

fn check_artifact_directory(path: &Path) -> ReliabilityCheck {
    artifact_directory_check(path, ensure_artifact_root_owned(path))
}

fn artifact_directory_check(path: &Path, result: Result<()>) -> ReliabilityCheck {
    match result {
        Ok(_) => ReliabilityCheck {
            name: "artifact directory writable".to_string(),
            status: ConnectorHealthStatus::Ok,
            run_id: None,
            artifact: Some(path.display().to_string()),
            reason_codes: Vec::new(),
            message: "artifact directory is writable".to_string(),
        },
        Err(err) => ReliabilityCheck {
            name: "artifact directory writable".to_string(),
            status: ConnectorHealthStatus::Error,
            run_id: None,
            artifact: Some(path.display().to_string()),
            reason_codes: vec![ReliabilityReasonCode::PermissionDenied],
            message: err.to_string(),
        },
    }
}

fn check_model_bundle(artifact_root: &Path) -> (ReliabilityCheck, Option<ModelBundleSnapshot>) {
    let model_dir = artifact_root.join("model");
    match load_pilot_model_snapshot(&model_dir) {
        Ok(snapshot) => (
            ReliabilityCheck {
                name: "existing model bundle".to_string(),
                status: ConnectorHealthStatus::Ok,
                run_id: None,
                artifact: Some(model_dir.display().to_string()),
                reason_codes: Vec::new(),
                message: "immutable trained model bundle snapshot captured; pilot will not create synthetic fallback"
                    .to_string(),
            },
            Some(snapshot),
        ),
        Err(err) => (
            ReliabilityCheck {
                name: "existing model bundle".to_string(),
                status: ConnectorHealthStatus::Error,
                run_id: None,
                artifact: Some(model_dir.display().to_string()),
                reason_codes: vec![ReliabilityReasonCode::ArtifactMissing],
                message: format!(
                    "pilot requires an existing model bundle and will not create synthetic fallback: {err}"
                ),
            },
            None,
        ),
    }
}

fn load_pilot_model_snapshot(model_dir: &Path) -> Result<ModelBundleSnapshot> {
    let snapshot = load_existing_model_bundle_snapshot(model_dir)?;
    validate_pilot_model_bundle(&snapshot)?;
    Ok(snapshot)
}

fn validate_pilot_model_bundle(snapshot: &ModelBundleSnapshot) -> Result<()> {
    let manifest = &snapshot.manifest;
    if manifest.synthetic_fallback {
        return Err(NetdiagError::InvalidTrace(
            "pilot requires a trained model bundle; synthetic fallback models are not accepted"
                .to_string(),
        ));
    }
    if manifest.dataset_hash_sha256.is_none() {
        return Err(NetdiagError::InvalidTrace(
            "pilot model manifest must include dataset_hash_sha256".to_string(),
        ));
    }
    if !manifest
        .training_gate
        .as_ref()
        .is_some_and(|gate| gate.passed)
    {
        return Err(NetdiagError::InvalidTrace(
            "pilot model manifest must include a passing training_gate".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn check_pilot_safety(
    manifest: &PilotManifest,
    cli_allow_active: bool,
) -> Vec<ReliabilityCheck> {
    let active_sources = manifest
        .sources
        .iter()
        .filter(|source| source.active)
        .map(|source| source.name.clone())
        .collect::<Vec<_>>();
    if active_sources.is_empty() {
        return vec![ReliabilityCheck {
            name: "pilot safety".to_string(),
            status: ConnectorHealthStatus::Ok,
            run_id: None,
            artifact: None,
            reason_codes: Vec::new(),
            message: "pilot is read-only".to_string(),
        }];
    }
    let active_allowed = manifest.safety.allow_active && cli_allow_active;
    vec![ReliabilityCheck {
        name: "active probe double opt-in".to_string(),
        status: if active_allowed {
            ConnectorHealthStatus::Ok
        } else {
            ConnectorHealthStatus::Error
        },
        run_id: None,
        artifact: None,
        reason_codes: if active_allowed {
            Vec::new()
        } else {
            vec![ReliabilityReasonCode::PermissionDenied]
        },
        message: if active_allowed {
            format!("active sources allowed: {}", active_sources.join(", "))
        } else {
            format!(
                "active sources require manifest safety.allow_active=true and CLI --allow-active: {}",
                active_sources.join(", ")
            )
        },
    }]
}
