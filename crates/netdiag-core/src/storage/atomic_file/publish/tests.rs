use super::*;
use crate::storage::atomic_file::BoundAtomicFileTarget;
use std::ffi::OsStr;
use std::io;

#[test]
fn platform_failure_keeps_the_complete_platform_error() {
    let root = tempfile::tempdir().expect("temporary root");
    let target_path = root.path().join("state.json");
    let target = BoundAtomicFileTarget::bind(&target_path).expect("bound target");
    let platform_error = netdiag_platform::publish_file_replace_at(
        target.directory(),
        OsStr::new("../invalid"),
        OsStr::new("state.json"),
    )
    .expect_err("invalid leaf must fail");

    let failure = platform_failure(&target, platform_error);

    assert_eq!(failure.phase, AtomicPublishPhase::NotPublished);
    let NetdiagError::PlatformAtomicPublication { path, source } = failure.source.as_ref() else {
        panic!("expected complete platform publication error");
    };
    assert_eq!(path, target.resolved_path());
    assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
    assert!(source.classification().is_none());
}
