use super::*;
use crate::models::RunManifest;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Fixture {
    value: String,
}

#[test]
fn optional_and_required_reads_distinguish_missing_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("missing.json");

    assert!(
        read_optional_stable_json_bounded::<Fixture>(&path, 128, "fixture")
            .expect("optional read")
            .is_none()
    );
    let error = read_required_stable_json_bounded::<Fixture>(&path, 128, "fixture")
        .expect_err("required read must fail");
    assert!(error.to_string().contains("fixture is missing"), "{error}");
}

#[test]
fn typed_read_is_bounded_and_reports_schema_context() {
    let temp = tempfile::tempdir().expect("tempdir");
    let oversized = temp.path().join("oversized.json");
    std::fs::write(&oversized, br#"{"value":"large"}"#).expect("oversized fixture");
    let error = read_required_stable_json_bounded::<Fixture>(&oversized, 4, "fixture")
        .expect_err("oversized JSON must fail");
    assert!(error.to_string().contains("4-byte read limit"), "{error}");

    let malformed = temp.path().join("malformed.json");
    std::fs::write(&malformed, b"not json").expect("malformed fixture");
    let error = read_required_stable_json_bounded::<Fixture>(&malformed, 128, "fixture")
        .expect_err("malformed JSON must fail");
    assert!(error.to_string().contains("invalid fixture"), "{error}");
    assert!(error.to_string().contains("malformed.json"), "{error}");
}

#[test]
fn bounded_writer_accepts_exact_output_and_rejects_larger_output_before_publication() {
    let temp = tempfile::tempdir().expect("tempdir");
    let value = Fixture {
        value: "bounded".to_string(),
    };
    let exact_bytes = prepare_json_bounded(&value, u64::MAX, "fixture")
        .expect("fixture serialization")
        .as_bytes()
        .to_vec();
    let exact = temp.path().join("exact.json");
    save_json_atomic_bounded(&exact, &value, exact_bytes.len() as u64, "fixture")
        .expect("exact bounded write");
    assert_eq!(std::fs::read(&exact).expect("exact output"), exact_bytes);

    let rejected = temp.path().join("rejected.json");
    let error =
        save_json_atomic_bounded(&rejected, &value, exact_bytes.len() as u64 - 1, "fixture")
            .expect_err("oversized serialization must fail");
    assert!(error.to_string().contains("serialized fixture"), "{error}");
    assert!(!rejected.exists(), "rejected target must not be published");
}

#[cfg(unix)]
#[test]
fn typed_read_rejects_symbolic_links() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target.json");
    let link = temp.path().join("link.json");
    std::fs::write(&target, br#"{"value":"safe"}"#).expect("target fixture");
    symlink(&target, &link).expect("symlink fixture");

    let error = read_required_stable_json_bounded::<Fixture>(&link, 128, "fixture")
        .expect_err("symlink must fail closed");
    assert!(
        error.to_string().contains("regular, non-symlink"),
        "{error}"
    );
}

#[test]
fn collection_limit_rejects_only_values_above_the_contract() {
    ensure_collection_limit("fixture index", 2, 2).expect("exact count");
    let error = ensure_collection_limit("fixture index", 3, 2)
        .expect_err("over-limit collection must fail");
    assert!(error.to_string().contains("3 entries"), "{error}");
}

#[test]
fn run_manifest_artifact_limit_is_inclusive_and_fail_closed() {
    let manifest = |count| RunManifest {
        run_id: "run".to_string(),
        sample: "sample".to_string(),
        created_at: Utc::now(),
        trace_rows: 1,
        artifact_paths: (0..count)
            .map(|index| (format!("key-{index}"), format!("artifact-{index}.json")))
            .collect::<BTreeMap<_, _>>(),
    };

    ensure_manifest_artifact_limit(&manifest(MAX_RUN_MANIFEST_ARTIFACTS))
        .expect("the exact manifest artifact limit is valid");
    let error = ensure_manifest_artifact_limit(&manifest(MAX_RUN_MANIFEST_ARTIFACTS + 1))
        .expect_err("one artifact above the manifest limit must fail");
    assert!(error.to_string().contains("4097 entries"), "{error}");
}
