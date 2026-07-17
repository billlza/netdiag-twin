use super::*;

#[test]
fn objective_loader_preserves_direct_and_nested_forms() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let direct = temp.path().join("direct.yaml");
    let nested = temp.path().join("nested.yaml");
    std::fs::write(&direct, "objective:\n  latency_p95_delta_pct: '<= -5'\n")
        .expect("direct objective");
    std::fs::write(
        &nested,
        "verification:\n  fail_if:\n    packet_loss_delta_pct: '> 1'\n",
    )
    .expect("nested objective");

    let direct = read(&direct).expect("direct objective form");
    let nested = read(&nested).expect("nested objective form");

    assert_eq!(direct.objective["latency_p95_delta_pct"], "<= -5");
    assert_eq!(nested.fail_if["packet_loss_delta_pct"], "> 1");
}

#[test]
fn objective_loader_distinguishes_missing_from_invalid_content() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let missing = temp.path().join("missing.yaml");
    let invalid = temp.path().join("invalid.yaml");
    std::fs::write(&invalid, b"objective: [").expect("invalid objective");

    let missing_error = read(&missing).expect_err("missing objective must fail");
    let invalid_error = read(&invalid).expect_err("invalid objective must fail");

    assert!(matches!(
        missing_error,
        NetdiagError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound
    ));
    assert!(invalid_error.to_string().contains("invalid objective YAML"));
}

#[test]
fn objective_loader_rejects_oversized_and_non_utf8_input() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let oversized = temp.path().join("oversized.yaml");
    let invalid_utf8 = temp.path().join("invalid-utf8.yaml");
    let file = std::fs::File::create(&oversized).expect("oversized fixture");
    file.set_len(MAX_VERIFICATION_OBJECTIVE_BYTES + 1)
        .expect("extend oversized fixture");
    std::fs::write(&invalid_utf8, [0xff]).expect("invalid UTF-8 fixture");

    let oversized_error = read(&oversized).expect_err("oversized objective must fail");
    let utf8_error = read(&invalid_utf8).expect_err("invalid UTF-8 must fail");

    assert!(
        oversized_error
            .to_string()
            .contains("exceeds the 262144-byte read limit"),
        "{oversized_error}"
    );
    assert!(utf8_error.to_string().contains("not valid UTF-8"));
}

#[cfg(unix)]
#[test]
fn objective_loader_rejects_symbolic_links_without_following_them() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temporary directory");
    let target = temp.path().join("target.yaml");
    let link = temp.path().join("objective.yaml");
    std::fs::write(&target, "objective:\n  latency_p95_delta_pct: '<= -5'\n")
        .expect("target fixture");
    symlink(&target, &link).expect("objective symlink");

    let error = read(&link).expect_err("objective symlink must fail");

    assert!(
        error.to_string().contains("regular, non-symlink"),
        "{error}"
    );
}
