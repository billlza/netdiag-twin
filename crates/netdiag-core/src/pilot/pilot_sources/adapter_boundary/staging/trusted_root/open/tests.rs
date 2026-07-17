use super::*;
use std::fs;

fn trusted_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("netdiag-relative-open-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("trusted tempdir")
}

#[test]
fn relative_open_rejects_empty_and_parent_component_paths() {
    let temp = trusted_tempdir();
    let root = fs::File::open(temp.path()).expect("opened root");

    let empty = open_relative_regular_file(
        &root,
        temp.path(),
        Path::new(""),
        &temp.path().join("empty"),
    )
    .expect_err("empty relative endpoint must fail");
    assert!(
        empty.to_string().contains("does not name a file"),
        "{empty}"
    );

    let parent = open_relative_regular_file(
        &root,
        temp.path(),
        Path::new("../adapter.py"),
        &temp.path().join("../adapter.py"),
    )
    .expect_err("parent endpoint component must fail");
    assert!(
        parent
            .to_string()
            .contains("escapes safety.adapter_execution_root"),
        "{parent}"
    );
}
