use super::validation::{MAX_LAB_COLLECTION_ITEMS, MAX_LAB_NAME_BYTES, MAX_LAB_SOURCES};
use super::*;
use crate::lab::{
    LabAcceptance, LabCollection, LabDataSource, LabDataSourceKind, LabDataSourceRole,
    LabRunOptions, LabScenario, LabVerification,
};
use std::collections::BTreeMap;
use std::fs;

fn source(index: usize, role: LabDataSourceRole) -> LabDataSource {
    LabDataSource {
        name: Some(format!("source-{index}")),
        role,
        kind: LabDataSourceKind::TraceFile,
        endpoint: "trace.csv".to_string(),
        bearer_token_env: None,
        mapping: None,
    }
}

fn scenario_with_sources(count: usize) -> LabScenario {
    LabScenario {
        schema: "netdiag-lab-scenario/v1".to_string(),
        id: "bounded-scenario".to_string(),
        name: "Bounded scenario".to_string(),
        expected_label: None,
        topology: None,
        data_sources: (0..count)
            .map(|index| {
                source(
                    index,
                    if index == 0 {
                        LabDataSourceRole::Primary
                    } else {
                        LabDataSourceRole::Corroborating
                    },
                )
            })
            .collect(),
        collection: LabCollection {
            timeout_secs: 1,
            ..LabCollection::default()
        },
        what_if: None,
        acceptance: LabAcceptance::default(),
        verification: LabVerification::default(),
    }
}

#[test]
fn bearer_authentication_requires_named_http_sources() {
    let mut non_http = scenario_with_sources(1);
    non_http.data_sources[0].bearer_token_env = Some("SOURCE_TOKEN".to_string());
    let error =
        validate_lab_scenario(&non_http).expect_err("non-HTTP bearer declaration must fail closed");
    assert!(error.to_string().contains("non-HTTP kind trace-file"));

    let mut unnamed = scenario_with_sources(1);
    unnamed.data_sources[0].kind = LabDataSourceKind::HttpJson;
    unnamed.data_sources[0].endpoint = "http://127.0.0.1:8080/source".to_string();
    unnamed.data_sources[0].name = None;
    unnamed.data_sources[0].bearer_token_env = Some("SOURCE_TOKEN".to_string());
    let error = validate_lab_scenario(&unnamed)
        .expect_err("authenticated source without an explicit name must fail closed");
    assert!(error.to_string().contains("must declare an explicit name"));
}

#[test]
fn authenticated_source_names_are_unique() {
    let mut scenario = scenario_with_sources(2);
    for source in &mut scenario.data_sources {
        source.name = Some("gateway".to_string());
        source.kind = LabDataSourceKind::HttpJson;
        source.endpoint = "http://127.0.0.1:8080/source".to_string();
        source.bearer_token_env = Some("SOURCE_TOKEN".to_string());
    }
    let error = validate_lab_scenario(&scenario)
        .expect_err("duplicate authenticated source identity must fail closed");
    assert!(
        error
            .to_string()
            .contains("duplicate authenticated data source name")
    );
}

#[test]
fn exact_scenario_byte_limit_is_accepted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("scenario.yaml");
    let mut yaml = serde_yaml::to_string(&scenario_with_sources(1))
        .expect("serialize scenario")
        .into_bytes();
    assert!(yaml.len() < MAX_LAB_SCENARIO_BYTES as usize);
    yaml.resize(MAX_LAB_SCENARIO_BYTES as usize, b' ');
    fs::write(&path, &yaml).expect("exact-size scenario");

    let loaded = load_lab_scenario(&path).expect("exact-size scenario must load");

    assert_eq!(loaded.id, "bounded-scenario");
}

#[test]
fn oversized_scenario_is_rejected_before_yaml_parsing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("scenario.yaml");
    let artifacts = temp.path().join("artifacts");
    let file = fs::File::create(&path).expect("scenario fixture");
    file.set_len(MAX_LAB_SCENARIO_BYTES + 1)
        .expect("oversized fixture");

    let error = crate::lab::run_lab_scenario(
        &path,
        LabRunOptions {
            artifacts: artifacts.clone(),
        },
    )
    .expect_err("oversized YAML must fail closed");

    assert!(error.to_string().contains("1048576-byte read limit"));
    assert!(!artifacts.join("lab-runs").exists());
}

#[cfg(unix)]
#[test]
fn scenario_symlink_is_rejected_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target.yaml");
    let link = temp.path().join("scenario.yaml");
    fs::write(
        &target,
        serde_yaml::to_string(&scenario_with_sources(1)).expect("serialize scenario"),
    )
    .expect("target scenario");
    symlink(&target, &link).expect("scenario symlink");

    let error = load_lab_scenario(&link).expect_err("scenario symlink must fail closed");

    assert!(error.to_string().contains("regular, non-symlink"));
}

#[test]
fn source_count_and_total_collection_budget_are_bounded() {
    let exact_source_count = scenario_with_sources(MAX_LAB_SOURCES);
    validate_lab_scenario(&exact_source_count).expect("exact source limit");

    let too_many = scenario_with_sources(MAX_LAB_SOURCES + 1);
    let error = validate_lab_scenario(&too_many).expect_err("source count must be bounded");
    assert!(error.to_string().contains("more than 64"));

    let mut exact_budget = scenario_with_sources(2);
    exact_budget.collection.timeout_secs = 300;
    validate_lab_scenario(&exact_budget).expect("exact aggregate timeout budget");

    let mut excessive_budget = scenario_with_sources(3);
    excessive_budget.collection.timeout_secs = 201;
    let error =
        validate_lab_scenario(&excessive_budget).expect_err("aggregate budget must be bounded");
    assert!(error.to_string().contains("603s exceeds 600s"));

    let mut overflow = scenario_with_sources(2);
    overflow.collection.timeout_secs = u64::MAX;
    let error = validate_lab_scenario(&overflow).expect_err("budget overflow must fail closed");
    assert!(error.to_string().contains("budget overflowed"));
}

#[test]
fn oversized_name_and_collections_are_rejected_before_run_publication() {
    let temp = tempfile::tempdir().expect("tempdir");
    let scenario_path = temp.path().join("scenario.yaml");
    let artifacts = temp.path().join("artifacts");
    let mut scenario = scenario_with_sources(1);
    scenario.name = "n".repeat(MAX_LAB_NAME_BYTES + 1);
    fs::write(
        &scenario_path,
        serde_yaml::to_string(&scenario).expect("serialize invalid scenario"),
    )
    .expect("invalid scenario");

    let error = crate::lab::run_lab_scenario(
        &scenario_path,
        LabRunOptions {
            artifacts: artifacts.clone(),
        },
    )
    .expect_err("oversized name must fail before execution");

    assert!(error.to_string().contains("name exceeds 256 bytes"));
    assert!(!artifacts.join("lab-runs").exists());

    let mut excessive_collection = scenario_with_sources(1);
    excessive_collection.verification.objective = (0..=MAX_LAB_COLLECTION_ITEMS)
        .map(|index| (format!("metric-{index}"), ">= 0".to_string()))
        .collect::<BTreeMap<_, _>>();
    let error = validate_lab_scenario(&excessive_collection)
        .expect_err("verification collection must be bounded");
    assert!(error.to_string().contains("maximum is 128"));

    let mut invalid_probability = scenario_with_sources(1);
    invalid_probability.acceptance.min_ml_probability = f64::NAN;
    let error = validate_lab_scenario(&invalid_probability)
        .expect_err("non-finite acceptance threshold must fail closed");
    assert!(error.to_string().contains("finite and between 0 and 1"));
}

#[test]
fn published_snapshot_is_the_exact_generation_that_was_validated() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_path = temp.path().join("scenario.yaml");
    let archived_path = temp.path().join("run").join("scenario.yaml");
    let scenario_a = scenario_with_sources(1);
    let mut scenario_b = scenario_with_sources(1);
    scenario_b.id = "replacement-scenario".to_string();
    let bytes_a = serde_yaml::to_string(&scenario_a)
        .expect("serialize generation A")
        .into_bytes();
    let bytes_b = serde_yaml::to_string(&scenario_b)
        .expect("serialize generation B")
        .into_bytes();
    fs::write(&source_path, &bytes_a).expect("generation A");
    let snapshot = load_lab_scenario_snapshot(&source_path).expect("snapshot generation A");
    fs::write(&source_path, &bytes_b).expect("replace source with generation B");

    snapshot
        .publish_to(&archived_path)
        .expect("publish immutable snapshot");

    assert_eq!(snapshot.scenario().id, "bounded-scenario");
    assert_eq!(fs::read(&source_path).expect("source B"), bytes_b);
    assert_eq!(fs::read(&archived_path).expect("archived A"), bytes_a);
}
