use super::*;

#[test]
fn topology_loader_error_keeps_cli_context_and_root_cause() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing-topology.json");

    let error = read_topology(&missing).expect_err("missing topology must fail");
    let chain = format!("{error:#}");

    assert!(chain.contains("failed to load topology"), "{chain}");
    assert!(chain.contains("topology file is missing"), "{chain}");
    assert!(chain.contains(&missing.display().to_string()), "{chain}");
}

#[cfg(unix)]
#[test]
fn policy_loader_exposes_symbolic_link_rejection() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target.json");
    let link = temp.path().join("policy.json");
    std::fs::write(&target, "{}").expect("target");
    symlink(&target, &link).expect("policy link");

    let error = read_policy(&link).expect_err("policy link must fail");
    let chain = format!("{error:#}");

    assert!(chain.contains("failed to load policy"), "{chain}");
    assert!(chain.contains("non-symlink"), "{chain}");
}
