use super::preflight::check_pilot_safety;
use super::*;
use crate::connectors::authentication::{
    BearerEnvironmentBinding, BearerEnvironmentBindings, BearerSourceKind,
};
use crate::ml::{TrainingOptions, train_model_from_jsonl_with_options};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use tempfile::tempdir;
use zip::ZipArchive;

mod manifest;
mod preflight;

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
    crate::storage::ensure_artifact_root_owned(artifacts).expect("owned artifacts dir");
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

#[cfg(unix)]
const PRIVATE_RUNTIME_ADAPTER: &str = r#"import json
import os
import stat
import sys
from pathlib import Path

runtime_directory = Path.cwd()
if any(os.environ.get(name) != str(runtime_directory) for name in ("TMPDIR", "TMP", "TEMP")):
    print("private runtime temp environment mismatch", file=sys.stderr)
    raise SystemExit(41)
if stat.S_IMODE(runtime_directory.stat().st_mode) != 0o700:
    print("private runtime directory mode mismatch", file=sys.stderr)
    raise SystemExit(42)
if Path("replacement-parent-marker").exists():
    print("adapter executed in replaced original parent", file=sys.stderr)
    raise SystemExit(43)

if "--preflight" in sys.argv:
    print(json.dumps({
    "schema": "netdiag-adapter-preflight/v1",
    "adapter": "test-adapter",
    "collection_mode": "sample",
    "passed": True,
    "checks": [{"name": "snapshot", "status": "ok"}],
    "health": {"status": "ok"},
    "redaction": {"fields": [], "secrets": []}
    }))
else:
    print(json.dumps({
    "schema": "netdiag-adapter-payload/v1",
    "collection_mode": "sample",
    "sample": "snapshot",
    "protocol": "test",
    "flow_count": 1,
    "records": [{
        "timestamp": "2026-01-01T00:00:00Z",
        "latency_ms": 10.0,
        "jitter_ms": 1.0,
        "packet_loss_rate": 0.0,
        "retransmission_rate": 0.0,
        "timeout_events": 0.0,
        "retry_events": 0.0,
        "throughput_mbps": 100.0,
        "dns_failure_events": 0.0,
        "tls_failure_events": 0.0,
        "quic_blocked_ratio": 0.0
    }],
    "experiment": {
        "scenario_id": "snapshot",
        "fault_start": "2026-01-01T00:00:00Z",
        "fault_end": "2026-01-01T00:00:01Z",
        "ground_truth": "normal"
    }
    }))
"#;

#[cfg(unix)]
const ADAPTER_SNAPSHOT_MANIFEST: &str = r#"schema: netdiag-pilot/v1
id: adapter-snapshot
name: Adapter snapshot
safety:
  adapter_execution_root: trusted
sources:
  - name: adapter
    kind: adapter_sample
    endpoint: trusted/test-adapter/adapter.py
    role: primary
    adapter:
      mode: sample
    metadata:
      adapter_contract: netdiag-adapter/v1
"#;

#[cfg(unix)]
fn replace_original_adapter_parent(
    root: &Path,
    adapter_dir: &Path,
    adapter_path: &Path,
) -> std::path::PathBuf {
    let marker = root.join("replacement-executed");
    let original_adapter_dir = root.join("trusted/test-adapter-original");
    fs::rename(adapter_dir, original_adapter_dir).expect("replace original adapter parent");
    fs::create_dir(adapter_dir).expect("replacement adapter parent");
    fs::write(adapter_dir.join("replacement-parent-marker"), "replacement")
        .expect("replacement parent marker");
    fs::write(
        adapter_path,
        format!(
            "from pathlib import Path\nPath({:?}).write_text('executed')\n",
            marker.display().to_string()
        ),
    )
    .expect("replace original adapter");
    marker
}

#[test]
fn pilot_internal_invariants_fail_closed_for_missing_model_and_health() {
    let error = require_model_snapshot(None, "unit pilot")
        .expect_err("a passed preflight must carry an immutable model snapshot");
    assert!(error.to_string().contains("unit pilot preflight passed"));
    assert_eq!(
        evidence::aggregate_connector_status(&[]),
        ConnectorHealthStatus::Error
    );
}

#[test]
fn pilot_manifest_fails_fast_for_unknown_adapter_contract_and_reserved_args() {
    let mut source = PilotSource {
        name: "adapter".to_string(),
        kind: PilotSourceKind::AdapterSample,
        endpoint: "adapter.py".to_string(),
        role: PilotSourceRole::Primary,
        active: false,
        bearer_token_env: None,
        mapping: None,
        collection: PilotCollection::default(),
        adapter: PilotAdapterOptions::default(),
        metadata: BTreeMap::from([(
            "adapter_contract".to_string(),
            "netdiag-adapter/v2".to_string(),
        )]),
    };
    let mut manifest = PilotManifest {
        schema: PILOT_SCHEMA.to_string(),
        id: "adapter-pilot".to_string(),
        name: "Adapter pilot".to_string(),
        operator: None,
        safety: PilotSafety::default(),
        sources: vec![source.clone()],
        gates: PilotGates::default(),
    };

    assert!(validate_pilot_manifest(&manifest).is_err());

    source.metadata.insert(
        "adapter_contract".to_string(),
        "netdiag-adapter/v1".to_string(),
    );
    source.adapter.mode = Some(PilotAdapterMode::Live);
    source.adapter.args = vec!["--password=secret".to_string()];
    manifest.sources = vec![source];
    assert!(validate_pilot_manifest(&manifest).is_err());
}

#[test]
fn persisted_adapter_arguments_do_not_expose_values() {
    assert_eq!(
        redaction::redacted_adapter_argument("--verbose"),
        "--verbose"
    );
    assert_eq!(
        redaction::redacted_adapter_argument("--input=private.json"),
        "--input=[redacted]"
    );
    assert_eq!(
        redaction::redacted_adapter_argument("private.json"),
        "[redacted]"
    );
    assert_eq!(
        redaction::redacted_adapter_argument("-pSECRET"),
        "-p[redacted]"
    );
    assert_eq!(
        redaction::redacted_adapter_argument("--API-KEY=SECRET"),
        "--API-KEY=[redacted]"
    );
}

#[test]
fn endpoint_inventory_removes_url_userinfo_and_sensitive_query_values() {
    let source = PilotSource {
        name: "http".to_string(),
        kind: PilotSourceKind::HttpJson,
        endpoint:
            "https://operator:opaque-password@example.test/data?ACCESS_TOKEN=opaque-token&region=lab"
                .to_string(),
        role: PilotSourceRole::Primary,
        active: false,
        bearer_token_env: None,
        mapping: None,
        collection: PilotCollection::default(),
        adapter: PilotAdapterOptions::default(),
        metadata: BTreeMap::new(),
    };

    let endpoint = redaction::redacted_endpoint(&source);
    let url = reqwest::Url::parse(&endpoint).expect("redacted endpoint URL");
    assert!(url.username().is_empty());
    assert!(url.password().is_none());
    assert!(!endpoint.contains("opaque-password"));
    assert!(!endpoint.contains("opaque-token"));
    assert!(
        url.query_pairs()
            .any(|(key, value)| key == "ACCESS_TOKEN" && value == "[redacted]")
    );
    assert!(
        url.query_pairs()
            .any(|(key, value)| key == "region" && value == "lab")
    );

    let secret_endpoint = source.endpoint.clone();
    let manifest = PilotManifest {
        schema: PILOT_SCHEMA.to_string(),
        id: "redaction-test".to_string(),
        name: "Redaction test".to_string(),
        operator: None,
        safety: PilotSafety::default(),
        sources: vec![source],
        gates: PilotGates::default(),
    };
    let temp = tempdir().expect("tempdir");
    let persisted = temp.path().join("pilot.yaml");
    redaction::persist_redacted_pilot_manifest(&manifest, &persisted)
        .expect("persist redacted manifest");
    let body = std::fs::read_to_string(persisted).expect("redacted manifest");
    assert!(!body.contains("opaque-password"));
    assert!(!body.contains("opaque-token"));
    assert!(!body.contains(&secret_endpoint));
}

#[test]
fn pilot_manifest_rejects_non_portable_ids_before_path_creation() {
    let source = PilotSource {
        name: "trace".to_string(),
        kind: PilotSourceKind::TraceFile,
        endpoint: "normal.csv".to_string(),
        role: PilotSourceRole::Primary,
        active: false,
        bearer_token_env: None,
        mapping: None,
        collection: PilotCollection::default(),
        adapter: PilotAdapterOptions::default(),
        metadata: BTreeMap::new(),
    };
    for id in [
        "../outside",
        "nested/path",
        r"nested\path",
        ".hidden",
        "tail.",
    ] {
        let manifest = PilotManifest {
            schema: PILOT_SCHEMA.to_string(),
            id: id.to_string(),
            name: "Pilot".to_string(),
            operator: None,
            safety: PilotSafety::default(),
            sources: vec![source.clone()],
            gates: PilotGates::default(),
        };
        let error = validate_pilot_manifest(&manifest).expect_err("unsafe id must fail");
        assert!(error.to_string().contains("pilot id"), "{id:?}: {error}");
    }
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
    let bindings = BearerEnvironmentBindings::new([BearerEnvironmentBinding::new(
        "gateway",
        BearerSourceKind::HttpJson,
        "https://example.invalid/adapter",
        "NETDIAG_TEST_TOKEN",
    )
    .expect("binding")])
    .expect("bindings");
    let report = preflight_pilot_with_bearer_bindings(
        &manifest_path,
        PilotOptions {
            artifacts: temp.path().join("artifacts"),
            allow_active: false,
            allow_adapter_execution: false,
        },
        &bindings,
    )
    .expect("preflight");
    let endpoint = reqwest::Url::parse(&report.source_inventory[0].endpoint)
        .expect("redacted inventory endpoint");
    assert!(
        endpoint
            .query_pairs()
            .any(|(key, value)| key == "auth" && value == "[redacted-env]")
    );
}

#[test]
fn manifest_bearer_declaration_cannot_authorize_environment_access() {
    let temp = tempdir().expect("tempdir");
    let manifest_path = temp.path().join("pilot.yaml");
    fs::write(
        &manifest_path,
        r#"
schema: netdiag-pilot/v1
id: unauthorized-http
name: Unauthorized HTTP
sources:
  - name: gateway
    kind: http_json
    endpoint: http://127.0.0.1:1/adapter
    role: primary
    bearer_token_env: AWS_SECRET_ACCESS_KEY
"#,
    )
    .expect("manifest");
    let error = preflight_pilot(
        &manifest_path,
        PilotOptions {
            artifacts: temp.path().join("artifacts"),
            allow_active: false,
            allow_adapter_execution: false,
        },
    )
    .expect_err("manifest declaration alone must not authorize environment access");
    let message = error.to_string();
    assert!(message.contains("not externally authorized"));
    assert!(!message.contains("must-not-load"));
}

#[test]
fn pilot_run_resolves_authorized_environment_before_network_or_staging() {
    const ENVIRONMENT: &str = "NETDIAG_TEST_MISSING_PILOT_BEARER_05_3";
    assert!(
        std::env::var_os(ENVIRONMENT).is_none(),
        "test requires an absent environment variable"
    );
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let manifest_path = temp.path().join("pilot.yaml");
    fs::write(
        &manifest_path,
        format!(
            r#"schema: netdiag-pilot/v1
id: missing-authorized-token
name: Missing authorized token
sources:
  - name: gateway
    kind: http_json
    endpoint: http://127.0.0.1:1/adapter
    role: primary
    bearer_token_env: {ENVIRONMENT}
"#
        ),
    )
    .expect("manifest");
    let bindings = BearerEnvironmentBindings::new([BearerEnvironmentBinding::new(
        "gateway",
        BearerSourceKind::HttpJson,
        "http://127.0.0.1:1/different-path",
        ENVIRONMENT,
    )
    .expect("binding")])
    .expect("bindings");

    let error = run_pilot_with_bearer_bindings(
        &manifest_path,
        PilotOptions {
            artifacts: artifacts.clone(),
            allow_active: false,
            allow_adapter_execution: false,
        },
        &bindings,
    )
    .expect_err("missing authorized environment must fail before collection");

    assert!(error.to_string().contains("is not set"));
    assert!(
        !artifacts.join("pilot-runs").exists(),
        "token resolution must precede pilot staging"
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
            allow_adapter_execution: false,
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
fn adapter_static_preflight_never_executes_python_and_run_requires_separate_opt_in() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let adapters = temp.path().join("adapters");
    fs::create_dir(&adapters).expect("adapters root");
    let marker = temp.path().join("adapter-executed");
    fs::write(
        adapters.join("adapter.py"),
        format!(
            "from pathlib import Path\nPath({:?}).write_text('executed')\n",
            marker.display().to_string()
        ),
    )
    .expect("adapter script");
    let manifest_path = temp.path().join("pilot.yaml");
    fs::write(
        &manifest_path,
        r#"schema: netdiag-pilot/v1
id: adapter-static
name: Adapter static preflight
safety:
  adapter_execution_root: adapters
sources:
  - name: adapter
    kind: adapter_sample
    endpoint: adapters/adapter.py
    role: primary
    adapter:
      mode: sample
    metadata:
      adapter_contract: netdiag-adapter/v1
"#,
    )
    .expect("manifest");

    let report = preflight_pilot(
        &manifest_path,
        PilotOptions {
            artifacts: artifacts.clone(),
            allow_active: false,
            allow_adapter_execution: false,
        },
    )
    .expect("static preflight");
    assert!(report.passed);
    assert!(!marker.exists(), "static preflight executed adapter code");

    let error = run_pilot(
        &manifest_path,
        PilotOptions {
            artifacts: artifacts.clone(),
            allow_active: false,
            allow_adapter_execution: false,
        },
    )
    .expect_err("adapter execution must require an independent opt-in");
    assert!(error.to_string().contains("allow_adapter_execution"));
    assert!(!marker.exists(), "denied run executed adapter code");
}

#[cfg(unix)]
#[test]
fn prepared_pilot_executes_adapter_snapshot_when_original_is_replaced() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    let adapter_dir = temp.path().join("trusted/test-adapter");
    fs::create_dir_all(&adapter_dir).expect("adapter directory");
    let adapter_path = adapter_dir.join("adapter.py");
    fs::write(&adapter_path, PRIVATE_RUNTIME_ADAPTER).expect("trusted adapter");
    let manifest_path = temp.path().join("pilot.yaml");
    fs::write(&manifest_path, ADAPTER_SNAPSHOT_MANIFEST).expect("manifest");
    let prepared = PreparedPilot::load(&manifest_path).expect("prepared pilot");
    let marker = replace_original_adapter_parent(temp.path(), &adapter_dir, &adapter_path);
    fs::write(&manifest_path, "schema: replaced-after-prepare\n")
        .expect("replace original manifest");
    let options = PilotOptions {
        artifacts,
        allow_active: false,
        allow_adapter_execution: true,
    };

    let bindings = crate::connectors::authentication::BearerEnvironmentBindings::default();
    let capability =
        crate::storage::prepare_artifact_root(&options.artifacts).expect("artifact root");
    let preflight = prepare_pilot_run_preflight(&prepared, &options, &bindings, &capability)
        .expect("preflight snapshot");
    assert!(preflight.report.passed);
    let model_snapshot = preflight.model_snapshot.expect("model snapshot");
    let expected_model_hash = model_snapshot.model_file_hash_sha256.clone();
    crate::ml::rebuild_synthetic_model_bundle(&options.artifacts.join("model"))
        .expect("replace model bundle after preflight");
    let current_model_hash =
        crate::ml::load_existing_model_bundle_snapshot(&options.artifacts.join("model"))
            .expect("current model snapshot")
            .model_file_hash_sha256;
    assert_ne!(expected_model_hash, current_model_hash);
    let report = run_prepared_pilot(&prepared, options, &model_snapshot, &bindings, &capability)
        .expect("run prepared snapshot");
    assert!(report.passed);
    assert!(!marker.exists(), "replaced adapter path was executed");
    let persisted = crate::storage::read_report(Path::new(&report.pilot_run_dir), &report.run_id)
        .expect("persisted pilot report");
    assert_eq!(
        persisted.model_file_hash.as_deref(),
        Some(expected_model_hash.as_str())
    );
    prepared.finish(Ok(())).expect("finish prepared pilot");
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
            allow_adapter_execution: true,
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

#[test]
fn pilot_bundle_binds_redacted_manifest_health_and_final_result() {
    let temp = tempdir().expect("tempdir");
    let artifacts = temp.path().join("artifacts");
    provision_test_model(&artifacts);
    fs::copy(sample("normal"), temp.path().join("trace.csv")).expect("trace fixture");
    let manifest_path = temp.path().join("pilot.yaml");
    fs::write(
        &manifest_path,
        r#"schema: netdiag-pilot/v1
id: evidence-context
name: Evidence context
sources:
  - name: trace
    kind: trace_file
    endpoint: trace.csv
    role: primary
    metadata:
      api_token: raw-secret-value
"#,
    )
    .expect("pilot manifest");

    let report = run_pilot(
        &manifest_path,
        PilotOptions {
            artifacts: artifacts.clone(),
            allow_active: false,
            allow_adapter_execution: false,
        },
    )
    .expect("pilot run");
    assert!(report.passed);
    assert!(!report.pilot_run_dir.contains(".staged-"));
    assert!(report.checks.iter().all(|check| {
        check
            .artifact
            .as_deref()
            .is_none_or(|path| !path.contains(".staged-"))
    }));
    let bundle = report.evidence_bundle.as_ref().expect("evidence manifest");
    assert!(!bundle.output.contains(".staged-"));
    assert!(
        bundle
            .files
            .iter()
            .all(|file| !file.source_path.contains(".staged-"))
    );
    let bundle_file = File::open(&bundle.output).expect("bundle file");
    let mut archive = ZipArchive::new(bundle_file).expect("bundle archive");

    let archived_manifest = read_archive_text(&mut archive, "evidence_bundle_manifest.json");
    assert!(!archived_manifest.contains(".staged-"));

    let pilot_manifest = read_archive_text(&mut archive, "pilot.yaml");
    assert!(!pilot_manifest.contains("raw-secret-value"));
    assert!(!pilot_manifest.contains("NETDIAG_RAW_SECRET_NAME"));
    assert!(pilot_manifest.contains("[redacted]"));

    let pilot_report = read_archive_bytes(&mut archive, "pilot_report.json");
    let evidence_payload =
        fs::read(Path::new(&report.pilot_run_dir).join("pilot_evidence_report.json"))
            .expect("persisted evidence payload");
    assert_eq!(pilot_report, evidence_payload);
    let archived_result: serde_json::Value =
        serde_json::from_slice(&pilot_report).expect("pilot result json");
    assert_eq!(archived_result["passed"], true);
    assert!(archived_result.get("evidence_bundle").is_none());

    let persisted_final: serde_json::Value = serde_json::from_slice(
        &fs::read(Path::new(&report.pilot_run_dir).join("pilot_report.json"))
            .expect("persisted final pilot report"),
    )
    .expect("final pilot report json");
    assert_eq!(persisted_final["passed"], true);
    assert_eq!(
        persisted_final["evidence_bundle"],
        serde_json::to_value(bundle).expect("evidence manifest value")
    );

    let archived_health = read_archive_bytes(&mut archive, "pilot_connector_health.json");
    let persisted_health = fs::read(Path::new(&report.pilot_run_dir).join("connector_health.json"))
        .expect("persisted connector health");
    assert_eq!(archived_health, persisted_health);

    let manifest_entry = bundle
        .files
        .iter()
        .find(|entry| entry.key == "pilot_report")
        .expect("pilot report manifest entry");
    assert_eq!(manifest_entry.bytes, pilot_report.len() as u64);
    assert_eq!(manifest_entry.sha256, sha256_hex(&pilot_report));
    let pilot_parent = Path::new(&report.pilot_run_dir)
        .parent()
        .expect("pilot parent");
    assert!(
        fs::read_dir(pilot_parent)
            .expect("pilot entries")
            .all(|entry| !entry
                .expect("pilot entry")
                .file_name()
                .to_string_lossy()
                .starts_with('.')),
        "successful pilot run leaked a hidden stage"
    );
    let standard = crate::diagnose_file(sample("normal"), &artifacts, None)
        .expect("standard diagnosis after pilot run");
    let canonical_runs = fs::canonicalize(&artifacts)
        .expect("canonical artifact root")
        .join("runs");
    assert_eq!(standard.run_dir.parent(), Some(canonical_runs.as_path()));
}

fn read_archive_bytes(archive: &mut ZipArchive<File>, name: &str) -> Vec<u8> {
    let mut entry = archive.by_name(name).expect("archive entry");
    let mut body = Vec::new();
    entry.read_to_end(&mut body).expect("archive entry body");
    body
}

fn read_archive_text(archive: &mut ZipArchive<File>, name: &str) -> String {
    String::from_utf8(read_archive_bytes(archive, name)).expect("UTF-8 archive entry")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
