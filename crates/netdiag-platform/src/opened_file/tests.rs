use super::*;
use std::fs;

#[test]
fn identity_is_bound_to_the_open_handle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let first_path = temp.path().join("first");
    let second_path = temp.path().join("second");
    fs::write(&first_path, b"first").expect("first fixture");
    fs::write(&second_path, b"second").expect("second fixture");

    let first = open_file_read_only_no_follow(&first_path).expect("first handle");
    let first_again = open_file_read_only_no_follow(&first_path).expect("second first handle");
    let second = open_file_read_only_no_follow(&second_path).expect("second handle");

    assert!(same_open_file(&first, &first_again).expect("same identity"));
    assert!(!same_open_file(&first, &second).expect("different identity"));
}

#[cfg(unix)]
#[test]
fn no_follow_open_rejects_a_symbolic_link() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target");
    let link = temp.path().join("link");
    fs::write(&target, b"target").expect("target fixture");
    symlink(&target, &link).expect("link fixture");

    open_file_read_only_no_follow(&link).expect_err("symlink must not be followed");
}
