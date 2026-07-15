use super::{LabRunOptions, run_lab_batch};

#[test]
fn lab_batch_claims_artifact_root_only_after_input_preparation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let scenario_path = temp.path().join("scenario.yaml");
    let artifacts = temp.path().join("artifacts");
    std::fs::write(
        &scenario_path,
        r#"schema: netdiag-lab-scenario/v1
id: missing-source-batch-check
name: Missing source batch check
expected_label: normal
data_sources:
  - role: primary
    kind: trace-file
    endpoint: missing.csv
"#,
    )
    .expect("scenario");

    let batch = run_lab_batch(
        &[scenario_path],
        LabRunOptions {
            artifacts: artifacts.clone(),
        },
    )
    .expect("source failure must be recorded in the batch report");

    assert_eq!((batch.total_scenarios, batch.failed), (1, 1));
    assert!(
        batch.results[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("missing.csv")),
        "{:?}",
        batch.results
    );
    assert!(
        !artifacts.exists(),
        "failed input preparation must not claim the batch artifact root"
    );
}
