use super::super::finish_preparation;
use std::ffi::OsStr;

#[test]
fn successful_preparation_returns_the_same_trusted_directory() {
    let root = tempfile::tempdir().expect("tempdir");
    let directory = crate::open_trusted_directory_chain(root.path()).expect("trusted directory");
    let expected_path = directory.resolved_path().to_path_buf();
    let expected_identity = directory
        .coordination_identity()
        .expect("prepared directory identity");
    let parent = std::fs::File::open(root.path()).expect("opened parent");

    let finished = finish_preparation(
        &parent,
        OsStr::new("unused"),
        root.path().join("unused"),
        Ok(directory),
    )
    .expect("successful preparation");

    assert_eq!(finished.resolved_path(), expected_path);
    assert_eq!(
        finished.coordination_identity().expect("finished identity"),
        expected_identity
    );
}
