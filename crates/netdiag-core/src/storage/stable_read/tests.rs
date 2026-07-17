use super::*;

#[test]
fn exact_limit_is_accepted_and_larger_file_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let exact = temp.path().join("exact.json");
    let oversized = temp.path().join("oversized.json");
    fs::write(&exact, b"1234").expect("exact fixture");
    fs::write(&oversized, b"12345").expect("oversized fixture");

    assert_eq!(
        read_stable_regular_file_bounded(&exact, 4)
            .expect("exact bounded read")
            .expect("exact file"),
        b"1234"
    );
    assert!(read_stable_regular_file_bounded(&oversized, 4).is_err());
}

#[test]
fn same_length_in_place_change_between_reads_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("settings.json");
    fs::write(&path, b"first").expect("initial fixture");

    let error = read_with_hook(&path, 16, || {
        fs::write(&path, b"other").expect("same-length replacement");
    })
    .expect_err("mixed generations must fail closed");

    assert!(
        error
            .to_string()
            .contains("changed while it was being read")
    );
}

#[test]
fn a_short_read_relative_to_the_opened_metadata_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("settings.json");
    fs::write(&path, b"data").expect("fixture");
    let mut file = File::open(&path).expect("fixture handle");

    let error = read_pass(&mut file, &path, 16, 17, 5)
        .expect_err("an early EOF must be treated as a concurrent change");

    assert!(
        error
            .to_string()
            .contains("changed while it was being read")
    );
}

#[cfg(unix)]
#[test]
fn atomic_path_replacement_between_reads_is_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("settings.json");
    let replacement = temp.path().join("replacement.json");
    fs::write(&path, b"same").expect("initial fixture");
    fs::write(&replacement, b"same").expect("replacement fixture");

    let error = read_with_hook(&path, 16, || {
        fs::rename(&replacement, &path).expect("atomic replacement");
    })
    .expect_err("a different file generation must fail closed");

    assert!(
        error
            .to_string()
            .contains("changed while it was being read")
    );
}

#[cfg(unix)]
#[test]
fn stable_hash_rejects_atomic_path_replacement_between_passes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("artifact.json");
    let replacement = temp.path().join("replacement.json");
    fs::write(&path, b"first").expect("initial fixture");
    fs::write(&replacement, b"other").expect("replacement fixture");

    let error = super::digest::hash_with_hook(&path, 16, || {
        fs::rename(&replacement, &path).expect("atomic replacement");
    })
    .expect_err("a hash must be bound to one visible file generation");

    assert!(
        error
            .to_string()
            .contains("changed while it was being read")
    );
}

#[test]
fn stable_hash_rejects_same_length_in_place_change_between_passes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("artifact.json");
    fs::write(&path, b"first").expect("initial fixture");

    let error = super::digest::hash_with_hook(&path, 16, || {
        fs::write(&path, b"other").expect("same-length mutation");
    })
    .expect_err("a hash must not combine mutable file generations");

    assert!(
        error
            .to_string()
            .contains("changed while it was being read")
    );
}

#[test]
fn stable_hash_is_bounded_and_distinguishes_missing_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("artifact.json");
    let missing = temp.path().join("missing.json");
    fs::write(&path, b"abc").expect("hash fixture");

    assert_eq!(
        super::digest::sha256_stable_regular_file_bounded(&path, 3)
            .expect("stable hash")
            .as_deref(),
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert!(
        super::digest::sha256_stable_regular_file_bounded(&missing, 3)
            .expect("missing stable hash")
            .is_none()
    );
    assert!(
        super::digest::sha256_stable_regular_file_bounded(&path, 2)
            .expect_err("oversized stable hash must fail")
            .to_string()
            .contains("exceeds the 2-byte")
    );
}

#[test]
fn an_unrepresentable_limit_is_rejected_before_opening_the_path() {
    let error = read_stable_regular_file_bounded(Path::new("not-inspected"), u64::MAX)
        .expect_err("u64::MAX cannot be extended by the sentinel byte");

    assert!(error.to_string().contains("less than u64::MAX"));
}

#[cfg(unix)]
#[test]
fn symbolic_link_is_rejected_without_following_it() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target.json");
    let link = temp.path().join("settings.json");
    fs::write(&target, b"{}").expect("target fixture");
    symlink(&target, &link).expect("symlink fixture");

    let error =
        read_stable_regular_file_bounded(&link, 16).expect_err("settings symlink must fail closed");
    assert!(error.to_string().contains("regular, non-symlink"));
}

#[test]
fn missing_file_is_distinct_from_an_empty_file() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing.json");
    let empty = temp.path().join("empty.json");
    fs::write(&empty, b"").expect("empty fixture");

    assert!(
        read_stable_regular_file_bounded(&missing, 16)
            .expect("missing lookup")
            .is_none()
    );
    assert_eq!(
        read_stable_regular_file_bounded(&empty, 16).expect("empty lookup"),
        Some(Vec::new())
    );
}
