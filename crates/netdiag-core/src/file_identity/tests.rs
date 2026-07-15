use super::*;
use std::fs;

#[test]
#[cfg(any(unix, windows))]
fn identity_requires_the_same_opened_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::write(&first, b"first").expect("first file");
    fs::write(&second, b"second").expect("second file");
    let first_file = open_file(&first).expect("first file");
    let first_again = open_file(&first).expect("first file again");
    let second_file = open_file(&second).expect("second file");

    assert!(same_file(&first_file, &first_again, &first).expect("same identity"));
    assert!(!same_file(&first_file, &second_file, &first).expect("different identity"));
    assert_eq!(
        identity(&first_file, &first).expect("first identity"),
        identity(&first_again, &first).expect("same first identity")
    );
}
