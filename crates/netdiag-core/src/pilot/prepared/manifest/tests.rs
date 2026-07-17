use super::*;
use std::fs::File;
use std::io::Write;

#[test]
fn pilot_manifest_size_is_bounded_before_yaml_parsing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("oversized.yaml");
    let mut file = File::create(&path).expect("manifest");
    file.write_all(&vec![b'x'; MAX_PILOT_MANIFEST_BYTES as usize + 1])
        .expect("oversized manifest");

    let error = read_manifest(&path).expect_err("oversized manifest must fail");
    assert!(error.to_string().contains("exceeds"));
}

#[cfg(unix)]
#[test]
fn pilot_manifest_symbolic_link_is_rejected() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target.yaml");
    let path = temp.path().join("pilot.yaml");
    std::fs::write(&target, "schema: netdiag-pilot/v1\n").expect("target manifest");
    symlink(&target, &path).expect("manifest symlink");

    let error = read_manifest(&path).expect_err("manifest symlink must fail closed");
    assert!(
        error.to_string().contains("regular, non-symlink"),
        "{error}"
    );
}

#[test]
fn pilot_manifest_missing_and_directory_sources_propagate_io_errors() {
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("missing.yaml");
    let missing_error = read_manifest(&missing).expect_err("missing manifest must fail");
    assert!(missing_error.to_string().contains("missing.yaml"));

    let directory_error = read_manifest(temp.path()).expect_err("directory read must fail");
    assert!(
        directory_error
            .to_string()
            .contains(&temp.path().display().to_string())
    );
}

#[test]
fn pilot_manifest_distinguishes_yaml_and_domain_validation_errors() {
    let temp = tempfile::tempdir().expect("tempdir");
    let malformed = temp.path().join("malformed.yaml");
    std::fs::write(&malformed, "sources: [").expect("malformed manifest");
    let yaml_error = read_manifest(&malformed).expect_err("malformed YAML must fail");
    assert!(yaml_error.to_string().contains("invalid pilot YAML"));

    let unsupported = temp.path().join("unsupported.yaml");
    std::fs::write(
        &unsupported,
        r#"schema: netdiag-pilot/v2
id: unsupported
name: Unsupported
sources:
  - name: trace
    kind: trace_file
    endpoint: trace.csv
    role: primary
"#,
    )
    .expect("unsupported manifest");
    let validation_error = read_manifest(&unsupported).expect_err("unsupported schema must fail");
    assert!(
        validation_error
            .to_string()
            .contains("unsupported pilot schema")
    );
}
