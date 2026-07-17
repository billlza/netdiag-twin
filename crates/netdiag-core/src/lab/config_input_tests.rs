use super::*;

#[test]
fn missing_what_if_paths_preserve_named_preset_fallbacks() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let request = LabWhatIf {
        topology: "mesh".to_string(),
        policy: "reroute_path_b".to_string(),
    };

    let topology = load_lab_topology(&request, temp.path()).expect("named topology preset");
    let policy = load_lab_policy(&request, temp.path()).expect("named policy preset");

    assert_eq!(topology.key, "mesh");
    assert_eq!(policy.id, "reroute_path_b");
}

#[test]
fn oversized_what_if_files_are_rejected_before_parsing() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let topology = temp.path().join("topology.json");
    let policy = temp.path().join("policy.json");
    let topology_file = std::fs::File::create(&topology).expect("topology fixture");
    let policy_file = std::fs::File::create(&policy).expect("policy fixture");
    topology_file
        .set_len(8 * 1024 * 1024)
        .expect("extend topology fixture");
    policy_file
        .set_len(8 * 1024 * 1024)
        .expect("extend policy fixture");
    let request = LabWhatIf {
        topology: topology.display().to_string(),
        policy: policy.display().to_string(),
    };

    let topology_error =
        load_lab_topology(&request, temp.path()).expect_err("oversized topology must fail");
    let policy_error =
        load_lab_policy(&request, temp.path()).expect_err("oversized policy must fail");

    assert!(
        topology_error.to_string().contains("exceeds"),
        "{topology_error}"
    );
    assert!(
        policy_error.to_string().contains("exceeds"),
        "{policy_error}"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_what_if_paths_are_rejected_instead_of_falling_back() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temporary directory");
    let topology_target = temp.path().join("topology-target.json");
    let policy_target = temp.path().join("policy-target.json");
    std::fs::write(&topology_target, b"{}").expect("topology target");
    std::fs::write(&policy_target, b"{}").expect("policy target");
    symlink(&topology_target, temp.path().join("mesh")).expect("topology symlink");
    symlink(&policy_target, temp.path().join("reroute_path_b")).expect("policy symlink");
    let request = LabWhatIf {
        topology: "mesh".to_string(),
        policy: "reroute_path_b".to_string(),
    };

    let topology_error =
        load_lab_topology(&request, temp.path()).expect_err("topology symlink must fail");
    let policy_error =
        load_lab_policy(&request, temp.path()).expect_err("policy symlink must fail");

    assert!(
        topology_error.to_string().contains("regular, non-symlink"),
        "{topology_error}"
    );
    assert!(
        policy_error.to_string().contains("regular, non-symlink"),
        "{policy_error}"
    );
}
