use super::*;
use crate::connectors::authentication::ResolvedBearerTokens;
use crate::pilot::{PilotGates, PilotManifest, PilotSafety};

pub(super) fn load_pilot_source(
    source: &PilotSource,
    base_dir: &Path,
) -> Result<LoadedPilotSource> {
    let boundary = test_adapter_boundary(source, base_dir)?;
    let operation = load_pilot_source_with_boundary(
        source,
        base_dir,
        boundary.as_ref(),
        true,
        &ResolvedBearerTokens::default(),
    );
    match boundary {
        Some(boundary) => boundary.finish(operation),
        None => operation,
    }
}

pub(super) fn check_source_static(source: &PilotSource, base_dir: &Path) -> ReliabilityCheck {
    let boundary = test_adapter_boundary(source, base_dir);
    match boundary {
        Ok(boundary) => {
            let check = check_source_static_with_boundary(source, base_dir, boundary.as_ref());
            let cleanup = match boundary {
                Some(boundary) => boundary.finish(Ok(check)),
                None => Ok(check),
            };
            cleanup.unwrap_or_else(|err| ReliabilityCheck {
                name: format!("source {} valid", source.name),
                status: ConnectorHealthStatus::Error,
                run_id: None,
                artifact: Some(redacted_endpoint(source)),
                reason_codes: vec![source_static_failure_reason(source.kind)],
                message: err.to_string(),
            })
        }
        Err(err) => ReliabilityCheck {
            name: format!("source {} valid", source.name),
            status: ConnectorHealthStatus::Error,
            run_id: None,
            artifact: Some(redacted_endpoint(source)),
            reason_codes: vec![source_static_failure_reason(source.kind)],
            message: err.to_string(),
        },
    }
}

fn test_adapter_boundary(
    source: &PilotSource,
    base_dir: &Path,
) -> Result<Option<AdapterExecutionBoundary>> {
    if source.kind != PilotSourceKind::AdapterSample {
        return Ok(None);
    }
    let manifest = PilotManifest {
        schema: "netdiag-pilot/v1".to_string(),
        id: "source-test".to_string(),
        name: "Source test".to_string(),
        operator: None,
        safety: PilotSafety {
            allow_active: false,
            adapter_execution_root: Some(".".to_string()),
            adapter_python_interpreter: None,
            retention_days: None,
        },
        sources: vec![source.clone()],
        gates: PilotGates::default(),
    };
    AdapterExecutionBoundary::from_manifest(&manifest, base_dir)
}
