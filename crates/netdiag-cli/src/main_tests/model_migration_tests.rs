#![cfg(test)]

use super::*;
use netdiag_core::ml::{
    MODEL_CURRENT_FILE_NAME, MODEL_MANIFEST_FILE_NAME, load_existing_model_bundle_identity,
};

#[test]
fn model_migrate_preserves_a_legacy_bundle_and_supports_normal_diagnosis() {
    let root = tempfile::tempdir().expect("private root");
    provision_test_model(root.path());
    let model_dir = root.path().join("model");
    let before = load_existing_model_bundle_identity(&model_dir).expect("model identity");
    let generation = model_dir
        .join("generations")
        .join(before.generation.expect("generation"));
    let model_bytes = fs::read(generation.join("rust_logistic_model.json")).expect("model bytes");
    let mut manifest = before.manifest;
    manifest.schema_version = "netdiag-model-manifest/v1".to_string();
    manifest.model_file_hash_sha256.clear();
    fs::write(model_dir.join("rust_logistic_model.json"), &model_bytes).expect("legacy model");
    fs::write(
        model_dir.join(MODEL_MANIFEST_FILE_NAME),
        serde_json::to_vec(&manifest).expect("manifest JSON"),
    )
    .expect("legacy manifest");
    fs::remove_file(model_dir.join(MODEL_CURRENT_FILE_NAME)).expect("legacy layout");
    fs::remove_dir_all(model_dir.join("generations")).expect("private fixture generations");
    load_existing_model_bundle_identity(&model_dir).expect_err("runtime rejects legacy schema");

    run(Args::parse_from([
        "netdiag",
        "model",
        "migrate",
        "--model-dir",
        path_str(&model_dir),
    ]))
    .expect("explicit CLI migration");
    let after = load_existing_model_bundle_identity(&model_dir).expect("current identity");
    assert_eq!(after.model_file_hash_sha256, before.model_file_hash_sha256);
    assert_eq!(after.manifest.training_source, manifest.training_source);
    netdiag_core::diagnose_file(sample("normal"), root.path(), None)
        .expect("diagnosis after migration");
}

#[cfg(unix)]
#[test]
fn model_migrate_rejects_non_utf8_output_paths_before_mutation() {
    let root = tempfile::tempdir().expect("private root");
    let model_dir = root.path().join(OsString::from_vec(b"model-\xff".to_vec()));
    let error = run(Args::parse_from([
        OsString::from("netdiag"),
        OsString::from("model"),
        OsString::from("migrate"),
        OsString::from("--model-dir"),
        model_dir.as_os_str().to_owned(),
    ]))
    .expect_err("non-UTF-8 output must fail before writes");
    assert!(error.to_string().contains("must be valid UTF-8"));
    assert!(!model_dir.exists());
    assert_eq!(fs::read_dir(root.path()).expect("private root").count(), 0);
}
