use super::*;
use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::storage::{NoClobberDisposition, StagedAtomicFile};
use std::ffi::OsStr;
use std::io::Write;

#[test]
fn durability_confirmation_failure_preserves_published_phase() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = TrustedDatasetRoot::open(temp.path()).expect("trusted dataset root");
    let target = root
        .target("dataset_manifest.json")
        .expect("bound manifest target");
    let error = root
        .confirm_publication_durability_with(
            &target,
            |_| {
                Err(NetdiagError::Io {
                    path: root.path().to_path_buf(),
                    source: std::io::Error::other("injected directory sync failure"),
                })
            },
            || Ok(()),
        )
        .expect_err("sync failure must remain publication uncertainty");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::PublishedButDurabilityUncertain)
    );
}

#[test]
fn final_identity_failure_does_not_erase_publication_phase() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = TrustedDatasetRoot::open(temp.path()).expect("trusted dataset root");
    let target = root
        .target("dataset_manifest.json")
        .expect("bound manifest target");
    let primary = root
        .confirm_publication_durability_with(
            &target,
            |_| Ok(()),
            || {
                Err(NetdiagError::InvalidTrace(
                    "injected post-sync identity failure".to_string(),
                ))
            },
        )
        .expect_err("post-sync identity failure must report an already durable publication");
    let combined = root
        .finish_with::<()>(Err(primary), || {
            Err(NetdiagError::InvalidTrace(
                "injected final identity failure".to_string(),
            ))
        })
        .expect_err("both failures must be reported");

    assert_eq!(
        combined.atomic_publish_phase(),
        Some(AtomicPublishPhase::Published)
    );
    let NetdiagError::AtomicPublish { source, .. } = combined else {
        panic!("expected atomic publication state");
    };
    assert!(matches!(
        source.as_ref(),
        NetdiagError::CombinedFailure {
            primary,
            secondary,
            ..
        } if matches!(primary.as_ref(), NetdiagError::InvalidTrace(message) if message == "injected post-sync identity failure")
            && matches!(secondary.as_ref(), NetdiagError::InvalidTrace(message) if message == "injected final identity failure")
    ));
}

#[test]
fn committed_manifest_wraps_an_inner_partition_phase_with_exact_published_target() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = TrustedDatasetRoot::open(temp.path()).expect("trusted dataset root");
    let manifest = root
        .target("dataset_manifest.json")
        .expect("bound manifest target");
    let partition_path = root.path().join("train.jsonl");
    let partition_failure = NetdiagError::atomic_publish(
        partition_path.clone(),
        AtomicPublishPhase::NotPublished,
        NetdiagError::InvalidTrace("injected partition failure".to_string()),
    );

    let error = root
        .finish_published::<()>(&manifest, Err(partition_failure))
        .expect_err("committed manifest must remain the outer publication state");

    let NetdiagError::AtomicPublish {
        path,
        phase,
        source,
    } = error
    else {
        panic!("expected manifest publication state");
    };
    assert_eq!(path, manifest.resolved_path());
    assert_eq!(phase, AtomicPublishPhase::Published);
    assert!(matches!(
        source.as_ref(),
        NetdiagError::AtomicPublish {
            path,
            phase: AtomicPublishPhase::NotPublished,
            ..
        } if path == &partition_path
    ));
}

#[test]
fn dataset_trust_error_preserves_platform_path_and_io_source() {
    use std::error::Error;

    let path = Path::new("/trusted/dataset").to_path_buf();
    let error = errors::trust_error(netdiag_platform::DirectoryTrustError::Inspect {
        path: path.clone(),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "inspect denied"),
    });

    let NetdiagError::FilesystemTrust { context, source } = &error else {
        panic!("expected structured filesystem trust error: {error}");
    };
    assert_eq!(*context, "dataset directory");
    assert!(matches!(
        source,
        netdiag_platform::DirectoryTrustError::Inspect {
            path: source_path,
            source,
        } if source_path == &path
            && source.kind() == std::io::ErrorKind::PermissionDenied
            && source.to_string() == "inspect denied"
    ));
    assert!(error.source().is_some());
}

#[test]
fn held_directory_controls_staging_publication_and_rollback_after_path_replacement() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root_path = temp.path().join("dataset-root");
    let displaced_path = temp.path().join("dataset-root-displaced");
    let root = TrustedDatasetRoot::open(&root_path).expect("trusted dataset root");
    let target = root
        .target("artifact.jsonl")
        .expect("bound artifact target");

    std::fs::rename(&root_path, &displaced_path).expect("displace opened directory");
    std::fs::create_dir(&root_path).expect("replacement directory");
    std::fs::set_permissions(&root_path, std::fs::Permissions::from_mode(0o700))
        .expect("private replacement directory");
    let replacement_artifact = root_path.join("artifact.jsonl");
    std::fs::write(&replacement_artifact, b"replacement sentinel").expect("replacement sentinel");

    let mut staged =
        StagedAtomicFile::reserve_in(root.directory_arc(), OsStr::new("artifact.jsonl"), "tmp")
            .expect("stage through retained directory handle");
    staged
        .file_mut()
        .write_all(b"held directory data")
        .expect("stage bytes");
    assert_eq!(
        staged
            .publish_noclobber(&target)
            .expect("bound publication"),
        NoClobberDisposition::Created
    );

    let displaced_artifact = displaced_path.join("artifact.jsonl");
    assert_eq!(
        std::fs::read(&displaced_artifact).expect("held-directory publication"),
        b"held directory data"
    );
    assert_eq!(
        std::fs::read(&replacement_artifact).expect("replacement sentinel after publish"),
        b"replacement sentinel"
    );

    let original = NetdiagError::InvalidTrace("injected registration failure".to_string());
    let rolled_back = root.rollback_created_files(&[target], original);

    assert!(matches!(
        rolled_back,
        NetdiagError::InvalidTrace(message) if message == "injected registration failure"
    ));
    assert!(
        !displaced_artifact.exists(),
        "rollback did not remove the held-directory artifact"
    );
    assert_eq!(
        std::fs::read(&replacement_artifact).expect("replacement sentinel after rollback"),
        b"replacement sentinel"
    );
}

#[test]
fn rollback_preserves_original_failure_and_every_cleanup_failure() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = TrustedDatasetRoot::open(temp.path()).expect("trusted dataset root");
    let first = root.target("first.jsonl").expect("first target");
    let second = root.target("second.jsonl").expect("second target");
    std::fs::create_dir(first.resolved_path()).expect("unremovable first target");
    std::fs::create_dir(second.resolved_path()).expect("unremovable second target");

    let error = root.rollback_created_files(
        &[first.clone(), second.clone()],
        NetdiagError::InvalidTrace("original registration failure".to_string()),
    );

    let NetdiagError::CombinedFailure {
        primary_context,
        primary,
        secondary_context,
        secondary: first_cleanup,
    } = error
    else {
        panic!("expected the first rollback failure to be retained");
    };
    assert_eq!(primary_context, "dataset registration failed");
    assert_eq!(
        secondary_context,
        "rollback of an immutable dependency also failed"
    );
    assert_cleanup_failure(&first_cleanup, &first);

    let NetdiagError::CombinedFailure {
        primary_context,
        primary: original,
        secondary_context,
        secondary: second_cleanup,
    } = primary.as_ref()
    else {
        panic!("expected the second rollback failure and original error");
    };
    assert_eq!(*primary_context, "dataset registration failed");
    assert_eq!(
        *secondary_context,
        "rollback of an immutable dependency also failed"
    );
    assert!(matches!(
        original.as_ref(),
        NetdiagError::InvalidTrace(message) if message == "original registration failure"
    ));
    assert_cleanup_failure(second_cleanup, &second);
    assert!(first.resolved_path().is_dir());
    assert!(second.resolved_path().is_dir());
}

fn assert_cleanup_failure(error: &NetdiagError, target: &crate::storage::BoundAtomicFileTarget) {
    assert!(matches!(
        error,
        NetdiagError::AtomicPublish {
            path,
            phase: AtomicPublishPhase::Published,
            source,
        } if path == target.resolved_path()
            && matches!(source.as_ref(), NetdiagError::PlatformAtomicPublication {
                path: platform_path,
                ..
            } if platform_path == target.resolved_path())
    ));
}
