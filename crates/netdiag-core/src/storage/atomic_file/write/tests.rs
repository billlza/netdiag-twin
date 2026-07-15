#[cfg(unix)]
use crate::error::AtomicPublishPhase;
use crate::error::IoContext;
use crate::error::NetdiagError;
use crate::storage::NoClobberDisposition;
use crate::storage::atomic_file::durability::cleanup_failed_write;
#[cfg(unix)]
use crate::storage::atomic_file::publish::{
    PublishResult, platform_failure, publish_temporary_file, published_uncertain,
};
use crate::storage::atomic_file::target::BoundAtomicFileTarget;
use crate::storage::atomic_file::write::write_file_atomically_noclobber_or_existing_to_bound;
#[cfg(unix)]
use crate::storage::atomic_file::write::write_file_atomically_with;
#[cfg(unix)]
use std::error::Error;
use std::ffi::OsStr;
use std::io::Write;
use std::sync::{Arc, Barrier};

#[test]
fn no_clobber_publish_preserves_an_existing_target() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = bound_target(root.path(), "state.json");
    std::fs::write(target.resolved_path(), b"existing").expect("existing target");

    let (disposition, ()) =
        write_file_atomically_noclobber_or_existing_to_bound(&target, "json", |file| {
            file.write_all(b"replacement")
                .with_path(target.resolved_path())
        })
        .expect("existing target is an explicit no-clobber outcome");

    assert_eq!(disposition, NoClobberDisposition::Existing);
    assert_eq!(
        std::fs::read(target.resolved_path()).expect("target bytes"),
        b"existing"
    );
}

#[test]
fn concurrent_no_clobber_publish_has_one_creator_and_one_existing_result() {
    let root = tempfile::tempdir().expect("tempdir");
    let target = bound_target(root.path(), "state.json");
    let barrier = Arc::new(Barrier::new(2));
    let handles = [b'a', b'b'].map(|byte| {
        let target = target.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            write_file_atomically_noclobber_or_existing_to_bound(&target, "json", |file| {
                file.write_all(&[byte]).with_path(target.resolved_path())
            })
            .map(|(disposition, ())| disposition)
        })
    });

    let results = handles.map(|handle| handle.join().expect("writer thread"));
    let dispositions = results
        .into_iter()
        .collect::<crate::error::Result<Vec<_>>>()
        .expect("both no-clobber outcomes");
    assert_eq!(
        dispositions
            .iter()
            .filter(|value| **value == NoClobberDisposition::Created)
            .count(),
        1
    );
    assert_eq!(
        dispositions
            .iter()
            .filter(|value| **value == NoClobberDisposition::Existing)
            .count(),
        1
    );
    assert!(matches!(
        std::fs::read(target.resolved_path())
            .expect("winner bytes")
            .as_slice(),
        b"a" | b"b"
    ));
}

fn bound_target(root: &std::path::Path, name: &str) -> BoundAtomicFileTarget {
    let directory = netdiag_platform::open_or_create_trusted_directory_chain(root)
        .expect("trusted target directory");
    BoundAtomicFileTarget::from_directory(Arc::new(directory), OsStr::new(name))
        .expect("bound target")
}

#[cfg(unix)]
#[test]
fn replace_publish_stays_bound_when_parent_path_is_replaced() {
    parent_swap_case(publish_temporary_file, b"replace");
}

#[cfg(unix)]
#[test]
fn no_clobber_publish_stays_bound_when_parent_path_is_replaced() {
    parent_swap_case(publish_temporary_file_noclobber, b"no-clobber");
}

#[cfg(unix)]
fn publish_temporary_file_noclobber(
    target: &BoundAtomicFileTarget,
    temporary: &OsStr,
) -> PublishResult {
    netdiag_platform::publish_file_noclobber_at(target.directory(), temporary, target.target_name())
        .map_err(|source| platform_failure(target, source))
}

#[cfg(unix)]
fn parent_swap_case(
    publish: impl FnOnce(&BoundAtomicFileTarget, &OsStr) -> PublishResult,
    bytes: &'static [u8],
) {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("temporary root");
    let parent = root.path().join("output");
    let protected = root.path().join("protected");
    std::fs::create_dir(&parent).expect("output parent");
    std::fs::create_dir(&protected).expect("protected parent");
    let target = parent.join("state.json");
    let protected_target = protected.join("state.json");
    std::fs::write(&protected_target, b"protected").expect("protected target");
    let displaced = root.path().join("displaced");

    write_file_atomically_with(
        &target,
        "json",
        |file| file.write_all(bytes).with_path(&target),
        publish,
        || {
            std::fs::rename(&parent, &displaced).with_path(&parent)?;
            symlink(&protected, &parent).with_path(&parent)
        },
    )
    .expect("handle-bound publication");

    assert_eq!(
        std::fs::read(displaced.join("state.json")).expect("bound output"),
        bytes
    );
    assert_eq!(
        std::fs::read(protected_target).expect("protected bytes"),
        b"protected"
    );
    assert_eq!(
        std::fs::read_dir(displaced)
            .expect("displaced entries")
            .count(),
        1,
        "temporary file leaked"
    );
}

#[cfg(unix)]
#[test]
fn post_publication_failure_is_classified_as_durability_uncertain() {
    let root = tempfile::tempdir().expect("temporary root");
    let target = root.path().join("state.json");
    let error = write_file_atomically_with(
        &target,
        "json",
        |file| file.write_all(b"published").with_path(&target),
        |bound, temporary| {
            publish_temporary_file(bound, temporary)?;
            Err(published_uncertain(NetdiagError::Io {
                path: bound.resolved_path().to_path_buf(),
                source: std::io::Error::other("injected post-publication failure"),
            }))
        },
        || Ok(()),
    )
    .expect_err("post-publication failure");

    assert_eq!(
        error.atomic_publish_phase(),
        Some(AtomicPublishPhase::PublishedButDurabilityUncertain)
    );
    assert_eq!(
        std::fs::read(&target).expect("published bytes"),
        b"published"
    );
    assert!(error.to_string().contains("post-publication failure"));
    let NetdiagError::AtomicPublish { path, source, .. } = &error else {
        panic!("expected structured atomic publication error: {error}");
    };
    assert_eq!(path, &target);
    let NetdiagError::Io {
        path: source_path,
        source: io_source,
    } = source.as_ref()
    else {
        panic!("expected structured I/O source: {source}");
    };
    assert_eq!(
        source_path,
        &target.canonicalize().expect("resolved published target")
    );
    assert_eq!(io_source.to_string(), "injected post-publication failure");
    let atomic_source = error.source().expect("atomic publication source");
    assert_eq!(atomic_source.to_string(), source.to_string());
    assert_eq!(
        atomic_source
            .source()
            .expect("underlying I/O source")
            .to_string(),
        "injected post-publication failure"
    );
}

#[test]
fn failed_temporary_cleanup_keeps_operation_and_io_causes() {
    let root = tempfile::tempdir().expect("temporary root");
    let target_path = root.path().join("state.json");
    let target = BoundAtomicFileTarget::bind(&target_path).expect("bound target");
    let temporary_name = OsStr::new("state.cleanup.tmp");
    let temporary_path = target.directory().resolved_path().join(temporary_name);
    std::fs::create_dir(&temporary_path).expect("directory cleanup fixture");

    let error = cleanup_failed_write(
        &target,
        temporary_name,
        &temporary_path,
        NetdiagError::InvalidTrace("injected write failure".to_string()),
    );

    let NetdiagError::CombinedFailure {
        primary, secondary, ..
    } = error
    else {
        panic!("expected combined cleanup failure");
    };
    assert!(matches!(
        primary.as_ref(),
        NetdiagError::InvalidTrace(message) if message == "injected write failure"
    ));
    let NetdiagError::Io { path, source } = secondary.as_ref() else {
        panic!("expected typed cleanup I/O failure");
    };
    assert_eq!(path, &temporary_path);
    let expected_kind = if cfg!(target_os = "linux") {
        std::io::ErrorKind::IsADirectory
    } else {
        std::io::ErrorKind::PermissionDenied
    };
    assert_eq!(source.kind(), expected_kind);
}
