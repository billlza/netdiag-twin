use crate::connectors::{HttpJsonConfig, load_http_json};
use crate::error::{IoContext, NetdiagError, Result};
use crate::evidence_bundle::{EvidenceBundleManifest, export_evidence_bundle};
use crate::ingest::{ingest_json_value, ingest_trace};
use crate::ml::{MODEL_MANIFEST_FILE_NAME, load_existing_model};
use crate::models::{ConnectorHealthSnapshot, ConnectorHealthStatus, ModelManifest};
use crate::pipeline::diagnose_ingest_with_whatif_and_existing_model_dir;
use crate::reliability::{
    ReliabilityCheck, ReliabilityReasonCode, check_reliability, redact_json_value, redact_string,
    write_text_atomic,
};
use crate::storage::{
    connector_health_from_ingest, run_dir, save_json_atomic, write_connector_health,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use uuid::Uuid;

const PILOT_SCHEMA: &str = "netdiag-pilot/v1";
const PILOT_PREFLIGHT_SCHEMA: &str = "netdiag-pilot-preflight/v1";
const PILOT_REPORT_SCHEMA: &str = "netdiag-pilot-report/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotManifest {
    pub schema: String,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub safety: PilotSafety,
    #[serde(default)]
    pub sources: Vec<PilotSource>,
    #[serde(default)]
    pub gates: PilotGates,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PilotSafety {
    #[serde(default)]
    pub allow_active: bool,
    #[serde(default)]
    pub retention_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotGates {
    #[serde(default = "default_allowed_connector_status")]
    pub allowed_connector_status: Vec<ConnectorHealthStatus>,
}

impl Default for PilotGates {
    fn default() -> Self {
        Self {
            allowed_connector_status: default_allowed_connector_status(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotSource {
    pub name: String,
    pub kind: PilotSourceKind,
    pub endpoint: String,
    #[serde(default)]
    pub role: PilotSourceRole,
    #[serde(default)]
    pub active: bool,
    #[serde(default)]
    pub bearer_token_env: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotSourceKind {
    TraceFile,
    AdapterSample,
    HttpJson,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PilotSourceRole {
    #[default]
    Primary,
    Corroborating,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotOptions {
    pub artifacts: PathBuf,
    #[serde(default)]
    pub allow_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotPreflightReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub pilot_id: String,
    pub passed: bool,
    #[serde(default)]
    pub source_inventory: Vec<PilotSourceInventory>,
    #[serde(default)]
    pub checks: Vec<ReliabilityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotReport {
    pub schema: String,
    pub generated_at: DateTime<Utc>,
    pub pilot_id: String,
    pub pilot_name: String,
    pub read_only: bool,
    pub passed: bool,
    pub run_id: String,
    pub pilot_run_dir: String,
    #[serde(default)]
    pub source_inventory: Vec<PilotSourceInventory>,
    #[serde(default)]
    pub connector_health: Vec<ConnectorHealthSnapshot>,
    pub diagnosis_summary: PilotDiagnosisSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_bundle: Option<EvidenceBundleManifest>,
    #[serde(default)]
    pub checks: Vec<ReliabilityCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotSourceInventory {
    pub name: String,
    pub kind: PilotSourceKind,
    pub role: PilotSourceRole,
    pub endpoint: String,
    pub active: bool,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PilotDiagnosisSummary {
    pub diagnosis_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_label: Option<String>,
    pub root_causes: Vec<String>,
    pub recommendation_count: usize,
}

struct LoadedPilotSource {
    source: PilotSource,
    ingest: crate::models::IngestResult,
    health: ConnectorHealthSnapshot,
    redacted_payload: Option<Value>,
}

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
        read_only: !options.allow_active,
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

fn load_pilot_source(source: &PilotSource, base_dir: &Path) -> Result<LoadedPilotSource> {
    match source.kind {
        PilotSourceKind::TraceFile => {
            let path = resolve_path(base_dir, &source.endpoint);
            let ingest = ingest_trace(&path)?;
            let health =
                connector_health_from_ingest("trace-file", &source.name, &source.name, &ingest);
            Ok(LoadedPilotSource {
                source: source.clone(),
                ingest,
                health,
                redacted_payload: None,
            })
        }
        PilotSourceKind::AdapterSample => {
            let adapter = resolve_path(base_dir, &source.endpoint);
            let adapter = adapter.canonicalize().with_path(&adapter)?;
            let output = Command::new("python3")
                .arg(&adapter)
                .arg("--emit-sample")
                .current_dir(adapter.parent().unwrap_or(base_dir))
                .output()
                .map_err(|err| {
                    NetdiagError::Connector(format!("failed to run adapter sample: {err}"))
                })?;
            if !output.status.success() {
                return Err(NetdiagError::Connector(format!(
                    "adapter sample {} exited {}: {}",
                    adapter.display(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
            let payload: Value = serde_json::from_slice(&output.stdout)?;
            let ingest = ingest_json_value(payload.clone(), safe_name(&source.name))?;
            let mut payload = payload;
            redact_json_value(&mut payload);
            let health =
                connector_health_from_ingest("adapter-sample", &source.name, &source.name, &ingest);
            Ok(LoadedPilotSource {
                source: source.clone(),
                ingest,
                health,
                redacted_payload: Some(payload),
            })
        }
        PilotSourceKind::HttpJson => {
            let bearer_token = source
                .bearer_token_env
                .as_ref()
                .and_then(|name| std::env::var(name).ok());
            let loaded = load_http_json(&HttpJsonConfig {
                endpoint: source.endpoint.clone(),
                bearer_token,
                timeout: Duration::from_secs(10),
            })?;
            let mut payload = loaded.payload.clone().unwrap_or_else(|| json!({}));
            redact_json_value(&mut payload);
            Ok(LoadedPilotSource {
                source: source.clone(),
                ingest: loaded.ingest.clone(),
                health: connector_health_from_ingest(
                    "http-json",
                    &source.name,
                    &loaded.sample,
                    &loaded.ingest,
                ),
                redacted_payload: Some(payload),
            })
        }
    }
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

fn check_source_static(source: &PilotSource, base_dir: &Path) -> ReliabilityCheck {
    let path = resolve_path(base_dir, &source.endpoint);
    let status = match source.kind {
        PilotSourceKind::TraceFile | PilotSourceKind::AdapterSample => path.is_file(),
        PilotSourceKind::HttpJson => {
            source.endpoint.starts_with("http://") || source.endpoint.starts_with("https://")
        }
    };
    ReliabilityCheck {
        name: format!("source {} valid", source.name),
        status: if status {
            ConnectorHealthStatus::Ok
        } else {
            ConnectorHealthStatus::Error
        },
        run_id: None,
        artifact: Some(redacted_endpoint(source)),
        reason_codes: if status {
            Vec::new()
        } else {
            vec![ReliabilityReasonCode::ArtifactMissing]
        },
        message: if status {
            "source is statically valid".to_string()
        } else {
            "source endpoint is missing or invalid".to_string()
        },
    }
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

fn resolve_path(base_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    }
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

fn default_allowed_connector_status() -> Vec<ConnectorHealthStatus> {
    vec![ConnectorHealthStatus::Ok, ConnectorHealthStatus::Degraded]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
}
