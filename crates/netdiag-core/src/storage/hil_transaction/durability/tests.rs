use super::publish_staged_file_with;
use crate::error::{AtomicPublishPhase, NetdiagError};
use crate::storage::atomic_file::publish::{publish_temporary_file, published_uncertain};
use std::path::Path;

fn staged_hash(path: &Path) -> String {
    crate::storage::sha256_stable_regular_file_bounded(path, 1024)
        .expect("staged hash")
        .expect("staged file")
}

#[test]
fn post_rename_failure_preserves_durability_uncertainty() {
    let root = tempfile::tempdir().expect("temporary directory");
    let target = root.path().join("report.json");
    let staged = root.path().join(".report.json.hil-test.stage");
    std::fs::write(&staged, b"published report").expect("staged report");
    let expected_sha256 = staged_hash(&staged);

    let error = publish_staged_file_with(
        &staged,
        &target,
        1024,
        &expected_sha256,
        |bound, staged_name| {
            publish_temporary_file(bound, staged_name)?;
            Err(published_uncertain(NetdiagError::Io {
                path: bound.directory().resolved_path().to_path_buf(),
                source: std::io::Error::other("injected parent sync failure"),
            }))
        },
    )
    .expect_err("post-rename failure must remain uncertain");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::PublishedButDurabilityUncertain)
    );
    assert_eq!(
        std::fs::read(&target).expect("published report"),
        b"published report"
    );
    assert!(!staged.exists());
    assert!(error.to_string().contains("injected parent sync failure"));
}

#[cfg(unix)]
#[test]
fn publication_stays_on_retained_parent_after_path_replacement() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().expect("temporary directory");
    let parent = root.path().join("run");
    let displaced = root.path().join("run-displaced");
    std::fs::create_dir(&parent).expect("run directory");
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
        .expect("private run directory");
    let target = parent.join("report.json");
    let staged = parent.join(".report.json.hil-test.stage");
    std::fs::write(&staged, b"retained report").expect("staged report");
    let expected_sha256 = staged_hash(&staged);

    publish_staged_file_with(
        &staged,
        &target,
        1024,
        &expected_sha256,
        |bound, staged_name| {
            std::fs::rename(&parent, &displaced).expect("displace retained parent");
            std::fs::create_dir(&parent).expect("replacement parent");
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
                .expect("private replacement parent");
            std::fs::write(parent.join("report.json"), b"replacement sentinel")
                .expect("replacement sentinel");
            publish_temporary_file(bound, staged_name)
        },
    )
    .expect("publish through retained directory handle");

    assert_eq!(
        std::fs::read(displaced.join("report.json")).expect("retained report"),
        b"retained report"
    );
    assert_eq!(
        std::fs::read(parent.join("report.json")).expect("replacement sentinel"),
        b"replacement sentinel"
    );
    assert!(!displaced.join(".report.json.hil-test.stage").exists());
}
