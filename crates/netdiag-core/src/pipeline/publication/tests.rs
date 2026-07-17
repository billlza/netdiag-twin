#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::*;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::error::IoContext;
use crate::error::{AtomicPublishPhase, NetdiagError};

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn parent_replacement_cannot_redirect_run_publication() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary root");
    let canonical_root = std::fs::canonicalize(root.path()).expect("canonical root");
    let capability = crate::storage::prepare_artifact_root(root.path()).expect("artifact root");
    let pending = PendingRunPublication::prepare();
    let run_id = pending.run_id().to_string();
    let mut staged = crate::storage::with_artifact_root_capability(&capability, |owned| {
        pending.stage(RunPublicationRoot::Owned(owned))
    })
    .expect("staged run");
    staged
        .save_json("artifact.json", &serde_json::json!({"safe": true}))
        .expect("staged artifact");
    let runs_path = root.path().join("runs");
    let displaced = root.path().join("displaced-runs");
    let replacement = root.path().join("replacement-runs");
    std::fs::create_dir(&replacement).expect("replacement runs");

    let published = staged
        .publish_after(|| {
            std::fs::rename(&runs_path, &displaced).with_path(&runs_path)?;
            symlink(&replacement, &runs_path).with_path(&runs_path)
        })
        .expect("bound publication");

    assert_eq!(published, canonical_root.join("runs").join(&run_id));
    assert!(displaced.join(&run_id).join("artifact.json").is_file());
    assert!(!replacement.join(&run_id).exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn target_collision_is_not_published_and_preserves_existing_run() {
    let root = tempfile::tempdir().expect("temporary root");
    let capability = crate::storage::prepare_artifact_root(root.path()).expect("artifact root");
    let pending = PendingRunPublication::prepare();
    let run_id = pending.run_id().to_string();
    let mut staged = crate::storage::with_artifact_root_capability(&capability, |owned| {
        pending.stage(RunPublicationRoot::Owned(owned))
    })
    .expect("staged run");
    staged
        .save_json("artifact.json", &serde_json::json!({"staged": true}))
        .expect("staged artifact");
    let target = root.path().join("runs").join(&run_id);
    std::fs::create_dir(&target).expect("existing target");
    std::fs::write(target.join("sentinel"), b"existing").expect("existing sentinel");

    let error = staged.publish().expect_err("collision must fail closed");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::NotPublished)
    );
    assert_eq!(
        std::fs::read(target.join("sentinel")).expect("preserved sentinel"),
        b"existing"
    );
    let staged_entries = std::fs::read_dir(root.path().join("runs"))
        .expect("runs entries")
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with('.'))
        .count();
    assert_eq!(staged_entries, 0, "failed collision leaked a stage");
}

#[test]
fn post_publication_failure_keeps_the_run_as_the_outer_phase() {
    let root = tempfile::tempdir().expect("temporary root");
    let run_path = root.path().join("runs/run-id");
    let error = crate::storage::preserve_published_directory::<()>(
        &run_path,
        Err(NetdiagError::InvalidTrace(
            "injected run index failure".to_string(),
        )),
    )
    .expect_err("index failure");

    let NetdiagError::AtomicPublish {
        path,
        phase,
        source,
    } = error
    else {
        panic!("expected atomic publication error");
    };
    assert_eq!(path, run_path);
    assert_eq!(phase, AtomicPublishPhase::Published);
    assert!(matches!(
        source.as_ref(),
        NetdiagError::InvalidTrace(message) if message == "injected run index failure"
    ));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn real_index_failure_is_reconciled_on_the_next_owned_root_entry() {
    let root = tempfile::tempdir().expect("temporary root");
    let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("data/samples/congestion.csv");
    super::super::fail_next_run_index_update();

    let error = super::super::diagnose_file(sample, root.path(), None)
        .expect_err("injected index update must fail after run publication");

    let NetdiagError::AtomicPublish {
        path,
        phase,
        source,
    } = &error
    else {
        panic!("expected typed run publication failure: {error}");
    };
    assert_eq!(*phase, AtomicPublishPhase::Published);
    assert!(path.join("manifest.json").is_file());
    assert!(matches!(
        source.as_ref(),
        NetdiagError::InvalidTrace(message) if message == "injected run index update failure"
    ));
    assert!(!root.path().join("run_index.json").exists());

    crate::storage::ensure_artifact_root_owned(root.path())
        .expect("recover published run and reconcile its index");

    let run_id = path
        .file_name()
        .and_then(|name| name.to_str())
        .expect("published run id");
    let entries = crate::storage::list_run_index(root.path()).expect("reconciled run index");
    assert!(entries.iter().any(|entry| entry.run_id == run_id));
    assert!(!root.path().join(".netdiag-run-publication.json").exists());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn staged_run_is_published_and_indexed_after_a_journaled_crash() {
    let root = tempfile::tempdir().expect("temporary root");
    let sample = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("data/samples/normal.csv");
    super::super::fail_after_run_publication_journal();

    let error = super::super::diagnose_file(sample, root.path(), None)
        .expect_err("injected crash must stop before the staged run rename");
    assert!(
        error
            .to_string()
            .contains("injected crash after run publication journal")
    );
    assert!(root.path().join(".netdiag-run-publication.json").is_file());

    crate::storage::ensure_artifact_root_owned(root.path())
        .expect("recover staged run publication");

    let entries = crate::storage::list_run_index(root.path()).expect("recovered run index");
    assert_eq!(entries.len(), 1);
    assert!(root.path().join("runs").join(&entries[0].run_id).is_dir());
    assert!(
        std::fs::read_dir(root.path().join("runs"))
            .expect("runs entries")
            .all(|entry| !entry
                .expect("run entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".staged-"))
    );
    assert!(!root.path().join(".netdiag-run-publication.json").exists());
}
