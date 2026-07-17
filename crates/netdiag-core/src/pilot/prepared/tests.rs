use super::*;
use std::fs;

#[cfg(unix)]
fn load_adapter_prepared() -> (tempfile::TempDir, PreparedPilot, PathBuf) {
    let temp = tempfile::Builder::new()
        .prefix("netdiag-prepared-cleanup-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("trusted tempdir");
    let trusted = temp.path().join("trusted");
    fs::create_dir(&trusted).expect("trusted adapter root");
    fs::write(trusted.join("adapter.py"), "print('fixture')\n").expect("adapter fixture");
    let manifest = temp.path().join("pilot.yaml");
    fs::write(
        &manifest,
        r#"schema: netdiag-pilot/v1
id: prepared-cleanup
name: Prepared cleanup
safety:
  adapter_execution_root: trusted
sources:
  - name: adapter
    kind: adapter_sample
    endpoint: trusted/adapter.py
    role: primary
    adapter:
      mode: sample
    metadata:
      adapter_contract: netdiag-adapter/v1
"#,
    )
    .expect("manifest fixture");
    let prepared = PreparedPilot::load(&manifest).expect("prepared adapter pilot");
    let staging_path = prepared
        .adapter_boundary
        .as_ref()
        .expect("adapter boundary")
        .staged_adapter("adapter")
        .expect("staged adapter")
        .parent()
        .expect("staging parent")
        .to_path_buf();
    (temp, prepared, staging_path)
}

#[test]
fn manifest_parent_rejects_a_path_without_a_parent() {
    let error = manifest_parent(Path::new("")).expect_err("empty path has no parent");
    assert!(error.to_string().contains("has no parent"));
}

#[test]
fn load_builds_a_stable_manifest_context_for_a_valid_trace_pilot() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("pilot.yaml");
    fs::write(
        &path,
        r#"schema: netdiag-pilot/v1
id: prepared-trace
name: Prepared trace
sources:
  - name: trace
    kind: trace_file
    endpoint: trace.csv
    role: primary
"#,
    )
    .expect("manifest");

    let prepared = PreparedPilot::load(&path).expect("valid prepared pilot");

    assert_eq!(prepared.manifest.id, "prepared-trace");
    assert_eq!(
        prepared.manifest_dir,
        temp.path().canonicalize().expect("canonical tempdir")
    );
    assert!(prepared.adapter_boundary.is_none());
}

#[test]
fn load_propagates_a_missing_manifest_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing.yaml");

    let error = PreparedPilot::load(&missing).expect_err("missing manifest must fail");

    assert!(error.to_string().contains("missing.yaml"));
}

#[test]
fn load_rejects_an_adapter_manifest_without_a_trusted_execution_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("pilot.yaml");
    fs::write(
        &path,
        r#"schema: netdiag-pilot/v1
id: missing-root
name: Missing root
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

    let error = PreparedPilot::load(&path).expect_err("missing execution root must fail");

    assert!(error.to_string().contains("must declare"), "{error}");
}

#[cfg(unix)]
#[test]
fn finish_explicitly_removes_staging_after_success_and_operation_failure() {
    let (_temp, prepared, staging_path) = load_adapter_prepared();
    assert_eq!(prepared.finish(Ok(7_u8)).expect("successful finish"), 7);
    assert!(!staging_path.exists());

    let (_temp, prepared, staging_path) = load_adapter_prepared();
    let error = prepared
        .finish::<()>(Err(NetdiagError::InvalidTrace(
            "prepared operation failed".to_string(),
        )))
        .expect_err("operation error must be preserved");
    assert!(
        matches!(error, NetdiagError::InvalidTrace(ref message) if message == "prepared operation failed"),
        "{error}"
    );
    assert!(!staging_path.exists());
}

#[cfg(unix)]
#[test]
fn finish_preserves_prepared_operation_and_cleanup_failures() {
    use std::os::unix::fs::PermissionsExt;

    let (_temp, prepared, staging_path) = load_adapter_prepared();
    let displaced = staging_path.with_extension("displaced");
    fs::rename(&staging_path, &displaced).expect("displace staging directory");
    fs::create_dir(&staging_path).expect("replacement staging directory");
    fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o700))
        .expect("replacement mode");
    let error = prepared
        .finish::<()>(Err(NetdiagError::InvalidTrace(
            "prepared operation failed".to_string(),
        )))
        .expect_err("operation and cleanup failures must both remain observable");
    fs::remove_dir_all(&staging_path).expect("remove replacement fixture");
    fs::remove_dir_all(&displaced).expect("remove displaced fixture");

    let (operation, cleanup_source) = match &error {
        NetdiagError::TrustedTemporaryDirectoryOperationAndCleanup {
            operation, cleanup, ..
        } => (operation, cleanup),
        other => panic!("expected structured operation and cleanup failure: {other}"),
    };
    assert!(
        operation.to_string().contains("prepared operation failed"),
        "{operation}"
    );
    assert!(!cleanup_source.to_string().is_empty());
    assert_eq!(
        std::error::Error::source(&error)
            .expect("operation source")
            .to_string(),
        operation.to_string()
    );
}
