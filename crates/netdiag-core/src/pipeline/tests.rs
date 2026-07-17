use super::diagnose_ingest_with_whatif_and_connector_health;
use crate::ingest::ingest_trace;
use crate::models::{ConnectorHealthSnapshot, IngestResult};
use crate::storage::typed_json::MAX_CONNECTOR_HEALTH_BYTES;
use std::path::{Path, PathBuf};

fn sample_ingest() -> IngestResult {
    ingest_trace(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/samples/normal.csv"))
        .expect("sample ingest")
}

fn published_runs(root: &Path) -> Vec<PathBuf> {
    let runs = root.join("runs");
    match std::fs::read_dir(runs) {
        Ok(entries) => entries
            .map(|entry| entry.expect("run entry").path())
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read runs: {error}"),
    }
}

#[test]
fn source_health_is_part_of_the_first_published_snapshot() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ingest = sample_ingest();
    let health =
        ConnectorHealthSnapshot::from_ingest("http-json", "lab-router", "router-sample", &ingest);

    let result =
        diagnose_ingest_with_whatif_and_connector_health(ingest, temp.path(), None, health.clone())
            .expect("diagnosed run");
    let stored: ConnectorHealthSnapshot = serde_json::from_slice(
        &std::fs::read(result.run_dir.join("connector_health.json")).expect("health artifact"),
    )
    .expect("stored health");

    assert_eq!(result.connector_health, health);
    assert_eq!(stored, health);
}

#[test]
fn mismatched_health_fails_before_a_run_is_created() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ingest = sample_ingest();
    let mut health = ConnectorHealthSnapshot::from_ingest("pcap", "en0", "capture", &ingest);
    health.warning_count += 1;

    let error = diagnose_ingest_with_whatif_and_connector_health(ingest, temp.path(), None, health)
        .expect_err("mismatched health must fail");

    assert!(error.to_string().contains("does not match"), "{error}");
    assert!(published_runs(temp.path()).is_empty());
}

#[test]
fn oversized_health_aborts_staging_without_a_visible_run() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ingest = sample_ingest();
    let mut health = ConnectorHealthSnapshot::from_ingest("pcap", "en0", "capture", &ingest);
    health.sample = "x".repeat(
        usize::try_from(MAX_CONNECTOR_HEALTH_BYTES).expect("connector health limit fits usize"),
    );

    let error = diagnose_ingest_with_whatif_and_connector_health(ingest, temp.path(), None, health)
        .expect_err("oversized health must abort staging");

    assert!(error.to_string().contains("connector health"), "{error}");
    assert!(published_runs(temp.path()).is_empty());
}

#[test]
fn nested_pipeline_indexes_only_inside_the_retained_outer_stage() {
    let temp = tempfile::tempdir().expect("tempdir");
    let artifact_root = temp.path().join("artifacts");
    let model_dir = temp.path().join("model");
    crate::ml::rebuild_synthetic_model_bundle(&model_dir).expect("model bundle");
    let model_snapshot =
        crate::ml::load_existing_model_bundle_snapshot(&model_dir).expect("model snapshot");
    let capability =
        crate::storage::prepare_artifact_root(&artifact_root).expect("artifact root capability");
    let staged = crate::storage::with_artifact_root_capability(&capability, |owned| {
        crate::storage::create_root_bound_staged_directory(
            owned,
            Path::new("pilot-runs"),
            std::ffi::OsString::from("outer-run"),
            "nested pipeline test",
        )
    })
    .expect("outer stage");
    let ingest = sample_ingest();
    let health = ConnectorHealthSnapshot::from_ingest("test", "local", "sample", &ingest);

    let result =
        super::diagnose_ingest_with_nested_artifact_root_and_model_snapshot_and_connector_health(
            ingest,
            &staged,
            &model_snapshot,
            None,
            health,
        )
        .expect("nested pipeline");

    assert_eq!(
        result.run_dir,
        staged.staging_path().join("runs").join(&result.run_id)
    );
    assert!(staged.staging_path().join("run_index.json").is_file());
    assert!(!artifact_root.join("run_index.json").exists());
    assert!(!artifact_root.join(".netdiag-run-publication.json").exists());
    let (_, published) = crate::storage::finish_root_bound_staged_directory(
        &capability,
        staged,
        Ok(()),
        |_, &(), _| Ok(()),
    )
    .expect("publish outer stage");
    assert!(published.join("runs").join(&result.run_id).is_dir());
    assert!(published.join("run_index.json").is_file());
}
