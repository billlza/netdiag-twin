use super::*;
use crate::pilot::{
    PilotAdapterMode, PilotAdapterOptions, PilotCollection, PilotGates, PilotSafety, PilotSource,
    PilotSourceRole,
};
use std::collections::BTreeMap;
use std::fs;

fn trusted_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("netdiag-adapter-boundary-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("trusted tempdir")
}

fn manifest(endpoint: String) -> PilotManifest {
    PilotManifest {
        schema: "netdiag-pilot/v1".to_string(),
        id: "adapter-test".to_string(),
        name: "Adapter test".to_string(),
        operator: None,
        safety: PilotSafety {
            allow_active: false,
            adapter_execution_root: Some("trusted".to_string()),
            adapter_python_interpreter: None,
            retention_days: None,
        },
        sources: vec![PilotSource {
            name: "adapter".to_string(),
            kind: PilotSourceKind::AdapterSample,
            endpoint,
            role: PilotSourceRole::Primary,
            active: false,
            bearer_token_env: None,
            mapping: None,
            collection: PilotCollection::default(),
            adapter: PilotAdapterOptions {
                mode: Some(PilotAdapterMode::Sample),
                args: Vec::new(),
                env_allowlist: Vec::new(),
            },
            metadata: BTreeMap::new(),
        }],
        gates: PilotGates::default(),
    }
}

#[test]
fn adapter_boundary_rejects_absolute_and_parent_escape_paths() {
    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    fs::create_dir(&trusted).expect("trusted root");
    fs::write(trusted.join("adapter.py"), "print('ok')\n").expect("adapter");
    fs::write(temp.path().join("outside.py"), "print('outside')\n").expect("outside");
    let boundary = AdapterExecutionBoundary::from_manifest(
        &manifest("trusted/adapter.py".to_string()),
        temp.path(),
    )
    .expect("boundary")
    .expect("adapter boundary");
    assert_eq!(
        fs::read_to_string(boundary.staged_adapter("adapter").expect("staged adapter"))
            .expect("staged contents"),
        "print('ok')\n"
    );
    let staging_path = boundary
        .staged_adapter("adapter")
        .expect("staged adapter")
        .parent()
        .expect("staging parent")
        .to_path_buf();
    boundary.finish(Ok(())).expect("finish adapter boundary");
    assert!(!staging_path.exists());
    let absolute = AdapterExecutionBoundary::from_manifest(
        &manifest(trusted.join("adapter.py").display().to_string()),
        temp.path(),
    )
    .expect_err("absolute adapter paths must fail");
    assert!(absolute.to_string().contains("relative"));
    let escape =
        AdapterExecutionBoundary::from_manifest(&manifest("outside.py".to_string()), temp.path())
            .expect_err("parent escape must fail after canonicalization");
    assert!(escape.to_string().contains("escapes"));
}

#[cfg(unix)]
#[test]
fn adapter_boundary_rejects_symlink_that_resolves_outside_root() {
    use std::os::unix::fs::symlink;

    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    fs::create_dir(&trusted).expect("trusted root");
    let outside = temp.path().join("outside.py");
    fs::write(&outside, "print('outside')\n").expect("outside");
    symlink(&outside, trusted.join("adapter.py")).expect("symlink");
    let error = AdapterExecutionBoundary::from_manifest(
        &manifest("trusted/adapter.py".to_string()),
        temp.path(),
    )
    .expect_err("symlink escape must fail");
    assert!(error.to_string().contains("symbolic link"));
}

#[cfg(unix)]
#[test]
fn adapter_boundary_rejects_oversized_source_files() {
    let temp = trusted_tempdir();
    let trusted = temp.path().join("trusted");
    fs::create_dir(&trusted).expect("trusted root");
    let adapter = trusted.join("adapter.py");
    let file = fs::File::create(&adapter).expect("adapter");
    file.set_len(MAX_ADAPTER_FILE_BYTES + 1)
        .expect("oversized adapter");
    let error = AdapterExecutionBoundary::from_manifest(
        &manifest("trusted/adapter.py".to_string()),
        temp.path(),
    )
    .expect_err("oversized adapter must fail before execution");
    assert!(error.to_string().contains("exceeds"));
}

#[test]
fn adapter_boundary_rejects_missing_non_directory_and_unbounded_roots() {
    let temp = trusted_tempdir();

    let mut missing = manifest("trusted/adapter.py".to_string());
    missing.safety.adapter_execution_root = None;
    let error = AdapterExecutionBoundary::from_manifest(&missing, temp.path())
        .expect_err("adapter root declaration is mandatory");
    assert!(error.to_string().contains("must declare"), "{error}");

    fs::write(temp.path().join("trusted"), "not a directory").expect("root-shaped file");
    let error = AdapterExecutionBoundary::from_manifest(
        &manifest("trusted/adapter.py".to_string()),
        temp.path(),
    )
    .expect_err("adapter execution root must be a directory");
    assert!(error.to_string().contains("not a directory"), "{error}");

    for configured in [String::new(), "x".repeat(MAX_ADAPTER_PATH_BYTES + 1)] {
        let mut invalid = manifest("trusted/adapter.py".to_string());
        invalid.safety.adapter_execution_root = Some(configured);
        let error = AdapterExecutionBoundary::from_manifest(&invalid, temp.path())
            .expect_err("empty and oversized adapter roots must fail");
        assert!(error.to_string().contains("must contain"), "{error}");
    }
}
