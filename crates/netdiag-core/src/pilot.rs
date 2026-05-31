use self::pilot_sources::{LoadedPilotSource, check_source_static, load_pilot_source};
use crate::error::{IoContext, NetdiagError, Result};
use crate::evidence_bundle::export_evidence_bundle;
use crate::ml::{MODEL_MANIFEST_FILE_NAME, load_existing_model};
use crate::models::{ConnectorHealthSnapshot, ConnectorHealthStatus, ModelManifest};
use crate::pipeline::diagnose_ingest_with_whatif_and_existing_model_dir;
use crate::reliability::{
    ReliabilityCheck, ReliabilityReasonCode, check_reliability, redact_json_value, redact_string,
    write_text_atomic,
};
use crate::storage::{run_dir, save_json_atomic, write_connector_health};
use chrono::Utc;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use uuid::Uuid;

mod adapter_contract;
mod pilot_sources;
mod promotion;
mod types;
mod workflow;

pub use promotion::*;
pub use types::*;
pub use workflow::*;

const PILOT_SCHEMA: &str = "netdiag-pilot/v1";
const PILOT_PREFLIGHT_SCHEMA: &str = "netdiag-pilot-preflight/v1";
const PILOT_REPORT_SCHEMA: &str = "netdiag-pilot-report/v1";

pub fn load_pilot_manifest(path: impl AsRef<Path>) -> Result<PilotManifest> {
    let path = path.as_ref();
    let body = fs::read_to_string(path).with_path(path)?;
    let manifest: PilotManifest = serde_yaml::from_str(&body)
        .map_err(|err| NetdiagError::InvalidTrace(format!("invalid pilot YAML: {err}")))?;
    validate_pilot_manifest(&manifest)?;
    Ok(manifest)
}

pub fn validate_pilot_manifest(manifest: &PilotManifest) -> Result<()> {
    if manifest.schema.trim() != PILOT_SCHEMA {
        return Err(NetdiagError::InvalidTrace(format!(
            "unsupported pilot schema: {}",
            manifest.schema
        )));
    }
    if manifest.id.trim().is_empty() {
        return Err(NetdiagError::InvalidTrace("pilot id is empty".to_string()));
    }
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

pub fn preflight_pilot(
    path: impl AsRef<Path>,
    options: PilotOptions,
) -> Result<PilotPreflightReport> {
    let path = path.as_ref();
    let manifest = load_pilot_manifest(path)?;
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut checks = Vec::new();
    checks.push(check_artifact_directory(&options.artifacts));
    checks.push(check_model_bundle(&options.artifacts));
    checks.extend(check_pilot_safety(&manifest, options.allow_active));
    checks.extend(
        manifest
            .sources
            .iter()
            .map(|source| check_source_static(source, base_dir)),
    );
    let passed = checks
        .iter()
        .all(|check| check.status != ConnectorHealthStatus::Error);
    Ok(PilotPreflightReport {
        schema: PILOT_PREFLIGHT_SCHEMA.to_string(),
        generated_at: Utc::now(),
        pilot_id: manifest.id.clone(),
        passed,
        source_inventory: source_inventory(&manifest),
        checks,
    })
}

pub fn run_pilot(path: impl AsRef<Path>, options: PilotOptions) -> Result<PilotReport> {
    let path = path.as_ref();
    let manifest = load_pilot_manifest(path)?;
    let preflight = preflight_pilot(path, options.clone())?;
    if !preflight.passed {
        return Err(NetdiagError::InvalidTrace(format!(
            "pilot preflight failed for {}",
            manifest.id
        )));
    }
    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let created_at = Utc::now();
    let pilot_run_dir = options
        .artifacts
        .join("pilot-runs")
        .join(&manifest.id)
        .join(created_at.format("%Y%m%dT%H%M%SZ").to_string());
    fs::create_dir_all(&pilot_run_dir).with_path(&pilot_run_dir)?;
    persist_redacted_pilot_manifest(&manifest, &pilot_run_dir.join("pilot.yaml"))?;

    let loaded = manifest
        .sources
        .iter()
        .map(|source| load_pilot_source(source, base_dir))
        .collect::<Result<Vec<_>>>()?;
    let primary = loaded
        .iter()
        .find(|item| item.source.role == PilotSourceRole::Primary)
        .ok_or_else(|| NetdiagError::InvalidTrace("pilot primary source missing".to_string()))?;
    let model_dir = options.artifacts.join("model");
    validate_pilot_model_bundle(&model_dir)?;
    let pipeline = diagnose_ingest_with_whatif_and_existing_model_dir(
        primary.ingest.clone(),
        &pilot_run_dir,
        &model_dir,
        None,
    )?;
    write_connector_health(&pilot_run_dir, &pipeline.run_id, &primary.health)?;
    let connector_health = loaded
        .iter()
        .map(|item| item.health.clone())
        .collect::<Vec<_>>();
    save_json_atomic(
        pilot_run_dir.join("connector_health.json"),
        &connector_health,
    )?;

    let evidence_bundle = export_evidence_bundle(
        &pilot_run_dir,
        &pipeline.run_id,
        pilot_run_dir.join(format!("netdiag-evidence-{}.zip", pipeline.run_id)),
        &[],
    )?;
    save_json_atomic(
        run_dir(&pilot_run_dir, &pipeline.run_id).join("evidence_bundle.json"),
        &evidence_bundle,
    )?;
    let gate_status = aggregate_connector_status(&connector_health);
    let mut report = PilotReport {
        schema: PILOT_REPORT_SCHEMA.to_string(),
        generated_at: Utc::now(),
        pilot_id: manifest.id.clone(),
        pilot_name: manifest.name.clone(),
        read_only: !manifest.sources.iter().any(|source| source.active),
        passed: false,
        run_id: pipeline.run_id.clone(),
        pilot_run_dir: pilot_run_dir.display().to_string(),
        source_inventory: source_inventory(&manifest),
        connector_health,
        diagnosis_summary: PilotDiagnosisSummary {
            diagnosis_status: pipeline.report.diagnosis_status.as_str().to_string(),
            primary_label: pipeline
                .report
                .diagnosis_decision
                .primary_label
                .map(|label| label.as_str().to_string()),
            root_causes: pipeline
                .report
                .root_causes
                .iter()
                .map(|root| root.symptom.clone())
                .collect(),
            recommendation_count: pipeline.report.recommendations.len(),
        },
        evidence_bundle: Some(evidence_bundle),
        checks: Vec::new(),
    };
    persist_redacted_source_payloads(&loaded, &pilot_run_dir)?;
    save_json_atomic(pilot_run_dir.join("pilot_report.json"), &report)?;
    write_text_atomic(
        pilot_run_dir.join("pilot_summary.md"),
        &render_pilot_markdown(&report),
    )?;
    let reliability = check_reliability(crate::reliability::ReliabilityCheckOptions {
        artifact_root: pilot_run_dir.clone(),
        run_id: Some(pipeline.run_id.clone()),
    })?;
    report.passed = manifest
        .gates
        .allowed_connector_status
        .contains(&gate_status)
        && reliability.status != ConnectorHealthStatus::Error;
    report.checks = reliability.checks;
    save_json_atomic(pilot_run_dir.join("pilot_report.json"), &report)?;
    write_text_atomic(
        pilot_run_dir.join("pilot_summary.md"),
        &render_pilot_markdown(&report),
    )?;
    Ok(report)
}

fn persist_redacted_source_payloads(
    loaded: &[LoadedPilotSource],
    pilot_run_dir: &Path,
) -> Result<()> {
    for item in loaded {
        if let Some(payload) = &item.redacted_payload {
            save_json_atomic(
                pilot_run_dir.join(format!(
                    "source_{}_redacted.json",
                    safe_name(&item.source.name)
                )),
                payload,
            )?;
        }
    }
    Ok(())
}

fn check_artifact_directory(path: &Path) -> ReliabilityCheck {
    match fs::create_dir_all(path).with_path(path) {
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

fn check_model_bundle(artifact_root: &Path) -> ReliabilityCheck {
    let model_dir = artifact_root.join("model");
    match validate_pilot_model_bundle(&model_dir) {
        Ok(_) => ReliabilityCheck {
            name: "existing model bundle".to_string(),
            status: ConnectorHealthStatus::Ok,
            run_id: None,
            artifact: Some(model_dir.display().to_string()),
            reason_codes: Vec::new(),
            message: "model bundle is present; pilot will not create synthetic fallback"
                .to_string(),
        },
        Err(err) => ReliabilityCheck {
            name: "existing model bundle".to_string(),
            status: ConnectorHealthStatus::Error,
            run_id: None,
            artifact: Some(model_dir.display().to_string()),
            reason_codes: vec![ReliabilityReasonCode::ArtifactMissing],
            message: format!(
                "pilot requires an existing model bundle and will not create synthetic fallback: {err}"
            ),
        },
    }
}

fn validate_pilot_model_bundle(model_dir: &Path) -> Result<()> {
    load_existing_model(model_dir)?;
    let manifest_path = model_dir.join(MODEL_MANIFEST_FILE_NAME);
    let manifest: ModelManifest =
        serde_json::from_value(crate::storage::read_json(&manifest_path)?)?;
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

fn check_pilot_safety(manifest: &PilotManifest, cli_allow_active: bool) -> Vec<ReliabilityCheck> {
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

fn source_inventory(manifest: &PilotManifest) -> Vec<PilotSourceInventory> {
    manifest
        .sources
        .iter()
        .map(|source| PilotSourceInventory {
            name: source.name.clone(),
            kind: source.kind,
            role: source.role,
            endpoint: redacted_endpoint(source),
            active: source.active,
            metadata: redacted_metadata(&source.metadata),
        })
        .collect()
}

fn redacted_endpoint(source: &PilotSource) -> String {
    let endpoint = redact_string(&source.endpoint);
    if source.bearer_token_env.is_some() {
        return if endpoint == "[redacted]" {
            endpoint
        } else {
            format!("{endpoint}?auth=[redacted-env]")
        };
    }
    endpoint
}

fn redacted_metadata(metadata: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut value = serde_json::to_value(metadata).unwrap_or_else(|_| json!({}));
    redact_json_value(&mut value);
    serde_json::from_value(value).unwrap_or_default()
}

fn persist_redacted_pilot_manifest(manifest: &PilotManifest, path: &Path) -> Result<()> {
    let mut value = serde_json::to_value(manifest)?;
    redact_json_value(&mut value);
    let manifest: PilotManifest = serde_json::from_value(value)?;
    let body = serde_yaml::to_string(&manifest).map_err(|err| {
        NetdiagError::InvalidTrace(format!("failed to render redacted pilot manifest: {err}"))
    })?;
    write_text_atomic(path, &body)?;
    Ok(())
}

fn aggregate_connector_status(health: &[ConnectorHealthSnapshot]) -> ConnectorHealthStatus {
    health
        .iter()
        .map(|item| item.status)
        .max()
        .unwrap_or(ConnectorHealthStatus::Error)
}

fn render_pilot_markdown(report: &PilotReport) -> String {
    let mut body = String::new();
    body.push_str("# NetDiag Twin Pilot Report\n\n");
    body.push_str(&format!(
        "- Pilot: `{}`\n- Status: `{}`\n- Run ID: `{}`\n- Read-only: `{}`\n\n",
        report.pilot_id,
        if report.passed { "passed" } else { "failed" },
        report.run_id,
        report.read_only
    ));
    body.push_str("## Diagnosis\n\n");
    body.push_str(&format!(
        "- Status: `{}`\n- Primary label: `{}`\n- Recommendations: `{}`\n\n",
        report.diagnosis_summary.diagnosis_status,
        report
            .diagnosis_summary
            .primary_label
            .as_deref()
            .unwrap_or("n/a"),
        report.diagnosis_summary.recommendation_count,
    ));
    body.push_str("## Sources\n\n| Name | Kind | Role | Active | Endpoint |\n| --- | --- | --- | --- | --- |\n");
    for source in &report.source_inventory {
        body.push_str(&format!(
            "| {} | {:?} | {:?} | {} | {} |\n",
            source.name, source.kind, source.role, source.active, source.endpoint
        ));
    }
    body
}

fn safe_name(value: &str) -> String {
    let safe = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        Uuid::new_v4().simple().to_string()
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml::{TrainingOptions, train_model_from_jsonl_with_options};
    use tempfile::tempdir;

    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("repo root")
            .to_path_buf()
    }

    fn sample(name: &str) -> std::path::PathBuf {
        repo_root().join("data/samples").join(format!("{name}.csv"))
    }

    fn provision_test_model(artifacts: &Path) {
        train_model_from_jsonl_with_options(
            repo_root().join("examples/datasets/pilot-smoke-training.jsonl"),
            artifacts.join("model"),
            TrainingOptions {
                min_rows_per_label: 1,
                ..TrainingOptions::default()
            },
        )
        .expect("trained smoke model");
    }

    #[test]
    fn active_pilot_requires_double_opt_in() {
        let manifest = PilotManifest {
            schema: PILOT_SCHEMA.to_string(),
            id: "pilot".to_string(),
            name: "Pilot".to_string(),
            operator: None,
            safety: PilotSafety {
                allow_active: true,
                retention_days: None,
            },
            sources: vec![PilotSource {
                name: "probe".to_string(),
                kind: PilotSourceKind::TraceFile,
                endpoint: "data/samples/normal.csv".to_string(),
                role: PilotSourceRole::Primary,
                active: true,
                bearer_token_env: None,
                mapping: None,
                collection: PilotCollection::default(),
                metadata: BTreeMap::new(),
            }],
            gates: PilotGates::default(),
        };
        let denied = check_pilot_safety(&manifest, false);
        assert_eq!(denied[0].status, ConnectorHealthStatus::Error);
        let allowed = check_pilot_safety(&manifest, true);
        assert_eq!(allowed[0].status, ConnectorHealthStatus::Ok);
    }

    #[test]
    fn validates_pilot_manifest_requires_one_primary() {
        let mut manifest = PilotManifest {
            schema: PILOT_SCHEMA.to_string(),
            id: "pilot".to_string(),
            name: "Pilot".to_string(),
            operator: None,
            safety: PilotSafety::default(),
            sources: Vec::new(),
            gates: PilotGates::default(),
        };
        assert!(validate_pilot_manifest(&manifest).is_err());
        manifest.sources.push(PilotSource {
            name: "trace".to_string(),
            kind: PilotSourceKind::TraceFile,
            endpoint: "normal.csv".to_string(),
            role: PilotSourceRole::Primary,
            active: false,
            bearer_token_env: None,
            mapping: None,
            collection: PilotCollection::default(),
            metadata: BTreeMap::new(),
        });
        assert!(validate_pilot_manifest(&manifest).is_ok());
    }

    #[test]
    fn preflight_redacts_token_env_inventory() {
        let temp = tempdir().expect("tempdir");
        let manifest_path = temp.path().join("pilot.yaml");
        fs::write(
            &manifest_path,
            r#"
schema: netdiag-pilot/v1
id: http-pilot
name: HTTP pilot
sources:
  - name: gateway
    kind: http_json
    endpoint: https://example.invalid/adapter
    role: primary
    bearer_token_env: NETDIAG_TEST_TOKEN
"#,
        )
        .expect("manifest");
        let report = preflight_pilot(
            &manifest_path,
            PilotOptions {
                artifacts: temp.path().join("artifacts"),
                allow_active: false,
            },
        )
        .expect("preflight");
        assert!(
            report.source_inventory[0]
                .endpoint
                .contains("[redacted-env]")
        );
    }

    #[test]
    fn manifest_accepts_connector_family_aliases() {
        let temp = tempdir().expect("tempdir");
        let mapping_path = temp.path().join("mapping.json");
        fs::write(
            &mapping_path,
            serde_json::to_string(&crate::connectors::default_prometheus_mapping())
                .expect("mapping json"),
        )
        .expect("mapping");
        let manifest_path = temp.path().join("pilot.yaml");
        fs::write(
            &manifest_path,
            format!(
                r#"
schema: netdiag-pilot/v1
id: connector-pilot
name: Connector pilot
sources:
  - name: prometheus
    kind: prometheus-query
    endpoint: http://127.0.0.1:9090
    mapping: {}
    role: primary
  - name: otlp
    kind: otlp-grpc
    endpoint: 127.0.0.1:4317
    mapping: {}
    role: corroborating
  - name: counters
    kind: system-counters
    endpoint: all
    role: corroborating
"#,
                mapping_path.display(),
                mapping_path.display()
            ),
        )
        .expect("manifest");

        let manifest = load_pilot_manifest(&manifest_path).expect("manifest");
        assert_eq!(manifest.sources[0].kind, PilotSourceKind::PrometheusQuery);
        assert_eq!(manifest.sources[1].kind, PilotSourceKind::OtlpGrpc);
        assert_eq!(manifest.sources[2].kind, PilotSourceKind::SystemCounters);
    }

    #[test]
    fn connector_family_manifest_preflights_without_live_collection() {
        let temp = tempdir().expect("tempdir");
        let artifacts = temp.path().join("artifacts");
        provision_test_model(&artifacts);

        let report = preflight_pilot(
            repo_root().join("examples/pilots/connector-family-readonly.yaml"),
            PilotOptions {
                artifacts,
                allow_active: false,
            },
        )
        .expect("preflight");

        assert!(report.passed);
        assert_eq!(report.source_inventory.len(), 5);
        assert!(
            report
                .source_inventory
                .iter()
                .any(|source| source.kind == PilotSourceKind::OtlpGrpc)
        );
    }

    #[test]
    fn pilot_workflow_runs_generic_lab_kit_adapter_contracts() {
        let temp = tempdir().expect("tempdir");
        let artifacts = temp.path().join("artifacts");
        provision_test_model(&artifacts);
        let after = crate::diagnose_file(
            sample("normal"),
            &artifacts,
            Some(("line", "reroute_path_b")),
        )
        .expect("after run");

        let report = run_pilot_workflow(
            repo_root().join("examples/pilots/generic-lab-kit.yaml"),
            PilotWorkflowOptions {
                artifacts,
                allow_active: false,
                verification: Some(PilotWorkflowVerificationOptions {
                    after_run_id: after.run_id,
                    recommendation_id: None,
                    policy_path: None,
                    objective_path: None,
                }),
            },
        )
        .expect("workflow");

        assert!(report.passed);
        assert_eq!(report.pilot_id, "generic-lab-kit");
        assert!(report.verification.is_some());
        assert!(
            report
                .phases
                .iter()
                .any(|phase| phase.name == "evidence_bundle"
                    && phase.status == PilotWorkflowPhaseStatus::Passed)
        );
        assert!(
            report
                .pilot_run
                .as_ref()
                .and_then(|run| run.evidence_bundle.as_ref())
                .is_some()
        );
    }
}
