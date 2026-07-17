use super::*;
use crate::python_runtime::tests::trusted_tempdir;
use std::fs;

#[test]
fn trusted_path_entries_preserve_precedence_and_deduplicate() {
    let temp = trusted_tempdir();
    let first = temp.path().join("z-first");
    let second = temp.path().join("a-second");
    fs::create_dir(&first).expect("first directory");
    fs::create_dir(&second).expect("second directory");
    let joined = env::join_paths([&first, &second, &first]).expect("PATH");

    let search = trusted_path_entries(&joined).expect("trusted PATH entries");

    assert_eq!(
        search.entries,
        vec![
            first.canonicalize().expect("first canonical path"),
            second.canonicalize().expect("second canonical path"),
        ]
    );
}

#[test]
fn trusted_path_entries_reject_writable_components_with_explicit_reason() {
    use std::os::unix::fs::PermissionsExt;

    let temp = trusted_tempdir();
    let writable = temp.path().join("writable");
    fs::create_dir(&writable).expect("writable directory");
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
        .expect("writable permissions");
    let joined = env::join_paths([&writable]).expect("PATH");

    let search = trusted_path_entries(&joined).expect("bounded PATH inspection");

    assert!(search.entries.is_empty());
    assert!(
        search
            .rejections
            .iter()
            .any(|reason| reason.contains("group/world-writable"))
    );
}

#[test]
fn trusted_path_entries_bound_input_and_report_relative_or_missing_entries() {
    let oversized = std::ffi::OsString::from("x".repeat(MAX_PATH_BYTES + 1));
    let error = trusted_path_entries(&oversized)
        .err()
        .expect("PATH size must be bounded");
    assert!(error.to_string().contains("PATH exceeds"));

    let temp = trusted_tempdir();
    let missing = temp.path().join("missing");
    let joined =
        env::join_paths([PathBuf::from("relative"), missing]).expect("syntactically valid PATH");
    let search = trusted_path_entries(&joined).expect("bounded rejected entries");
    assert!(search.entries.is_empty());
    assert!(
        search
            .rejections
            .iter()
            .any(|reason| reason.contains("path_entry_not_absolute"))
    );
    assert!(
        search
            .rejections
            .iter()
            .any(|reason| reason.contains("path_canonicalize_error"))
    );
}
