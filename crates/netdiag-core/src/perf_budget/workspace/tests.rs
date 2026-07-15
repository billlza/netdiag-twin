use super::*;
use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::storage::prepare_artifact_root;

fn assert_only_ownership_marker(root: &Path) {
    let entries = std::fs::read_dir(root)
        .expect("artifact root entries")
        .map(|entry| entry.expect("artifact root entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        entries,
        [std::ffi::OsString::from(".netdiag-artifact-root.json")]
    );
}

#[test]
fn managed_workspace_is_removed_after_success() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let capability = prepare_artifact_root(root.path()).expect("artifact root capability");

    let staging_path = run(&capability, |workspace| {
        workspace.save_json("measurement.json", &serde_json::json!({"elapsed": 1}))?;
        Ok(workspace.staging_path().to_path_buf())
    })
    .expect("managed performance workspace");

    assert!(!staging_path.exists());
    assert_only_ownership_marker(root.path());
}

#[test]
fn managed_workspace_is_removed_after_operation_error() {
    let root = tempfile::tempdir().expect("temporary artifact root");
    let capability = prepare_artifact_root(root.path()).expect("artifact root capability");
    let mut workspace_paths = None;

    let error = run(&capability, |workspace| -> Result<()> {
        workspace.save_json("measurement.json", &serde_json::json!({"elapsed": 1}))?;
        workspace_paths = Some((
            workspace.staging_path().to_path_buf(),
            workspace.target_path().to_path_buf(),
        ));
        Err(NetdiagError::InvalidTrace(
            "expected benchmark failure".to_string(),
        ))
    })
    .expect_err("performance operation must fail");

    let (staging_path, target_path) = workspace_paths.expect("captured workspace paths");
    let NetdiagError::AtomicPublish {
        path,
        phase,
        source,
    } = &error
    else {
        panic!("unexpected operation error: {error:?}");
    };
    assert_eq!(path, &target_path);
    assert_eq!(*phase, AtomicPublishPhase::NotPublished);
    assert!(matches!(
        source.as_ref(),
        NetdiagError::InvalidTrace(message) if message == "expected benchmark failure"
    ));
    assert!(!staging_path.exists());
    assert!(!target_path.exists());
    assert_only_ownership_marker(root.path());
}
