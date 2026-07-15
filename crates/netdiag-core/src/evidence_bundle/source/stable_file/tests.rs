use super::*;

#[cfg(unix)]
#[test]
fn rejects_source_replaced_by_symlink_between_validation_and_open() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("source.json");
    let outside = temp.path().join("outside.json");
    fs::write(&source, "inside").expect("inside source");
    fs::write(&outside, "outside").expect("outside source");

    let error = open_stable_regular_file_with_hook(&source, || {
        fs::remove_file(&source).expect("remove source");
        symlink(&outside, &source).expect("replace with symlink");
    })
    .expect_err("identity-changing replacement must fail closed");

    assert!(error.to_string().contains("source.json"), "{error}");
}

#[cfg(unix)]
#[test]
fn rejects_direct_symlink_sources_even_when_the_target_is_inside_the_root() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target.json");
    let source = temp.path().join("source.json");
    fs::write(&target, "inside").expect("target");
    symlink(&target, &source).expect("source symlink");

    let error = open_stable_regular_file(&source).expect_err("symlink must fail closed");
    assert!(error.to_string().contains("non-reparse regular file"));
}

#[cfg(windows)]
#[test]
fn windows_regular_files_are_not_classified_as_reparse_points() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("source.json");
    fs::write(&source, "inside").expect("source");
    let metadata = fs::symlink_metadata(&source).expect("metadata");

    validate_regular_non_reparse(&source, &metadata).expect("regular file");
}
