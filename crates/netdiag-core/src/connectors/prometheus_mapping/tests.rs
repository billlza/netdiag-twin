use super::*;

#[test]
fn mapping_loader_accepts_a_bounded_utf8_object() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("mapping.json");
    std::fs::write(&path, br#"{"latency_ms":"latency_seconds"}"#).expect("mapping fixture");

    let mapping = load_prometheus_mapping_file(&path).expect("valid mapping");

    assert_eq!(mapping["latency_ms"], "latency_seconds");
}

#[test]
fn mapping_loader_distinguishes_missing_from_other_failures() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("missing.json");

    let error = load_prometheus_mapping_file(&path).expect_err("missing mapping must fail");

    assert!(matches!(
        error,
        NetdiagError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound
    ));
}

#[test]
fn mapping_loader_rejects_oversized_input_before_parsing() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("oversized.json");
    let file = std::fs::File::create(&path).expect("oversized fixture");
    file.set_len(MAX_PROMETHEUS_MAPPING_BYTES + 1)
        .expect("extend oversized fixture");

    let error = load_prometheus_mapping_file(&path).expect_err("oversized mapping must fail");

    assert!(
        error
            .to_string()
            .contains("exceeds the 1048576-byte read limit"),
        "{error}"
    );
}

#[test]
fn mapping_loader_reports_utf8_and_json_failures_explicitly() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let invalid_utf8 = temp.path().join("invalid-utf8.json");
    let invalid_json = temp.path().join("invalid-json.json");
    std::fs::write(&invalid_utf8, [0xff]).expect("invalid UTF-8 fixture");
    std::fs::write(&invalid_json, b"{").expect("invalid JSON fixture");

    let utf8_error =
        load_prometheus_mapping_file(&invalid_utf8).expect_err("invalid UTF-8 must fail");
    let json_error =
        load_prometheus_mapping_file(&invalid_json).expect_err("invalid JSON must fail");

    assert!(utf8_error.to_string().contains("not valid UTF-8"));
    assert!(json_error.to_string().contains("not valid JSON"));
}

#[test]
fn mapping_loader_rejects_ambiguous_or_non_string_json() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let cases = [
        (
            r#"{"latency_ms":"first","latency_ms":"second"}"#,
            "duplicate canonical field",
        ),
        (r#"{"latency_ms":"value"} true"#, "not valid JSON"),
        (r#"{"latency_ms":42}"#, "string-map JSON schema"),
    ];

    for (index, (body, expected)) in cases.into_iter().enumerate() {
        let path = temp.path().join(format!("invalid-{index}.json"));
        std::fs::write(&path, body).expect("invalid mapping fixture");

        let error = load_prometheus_mapping_file(&path)
            .expect_err("ambiguous mapping JSON must fail closed");

        assert!(error.to_string().contains(expected), "{error}");
        assert!(!error.to_string().contains("second"));
        assert!(!error.to_string().contains("42"));
    }
}

#[test]
fn mapping_loader_rejects_unsupported_fields_without_echoing_them() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("unsupported.json");
    let sensitive = "private-canonical-field";
    std::fs::write(&path, format!(r#"{{"{sensitive}":"private-value"}}"#))
        .expect("unsupported mapping fixture");

    let error = load_prometheus_mapping_file(&path)
        .expect_err("unsupported canonical field must fail closed");
    let message = error.to_string();

    assert!(message.contains("unsupported canonical field"));
    assert!(!message.contains(sensitive));
    assert!(!message.contains("private-value"));
}

#[cfg(unix)]
#[test]
fn mapping_loader_rejects_symbolic_links_without_following_them() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("temporary directory");
    let target = temp.path().join("target.json");
    let link = temp.path().join("mapping.json");
    std::fs::write(&target, b"{}").expect("target fixture");
    symlink(&target, &link).expect("mapping symlink");

    let error = load_prometheus_mapping_file(&link).expect_err("mapping symlink must fail");

    assert!(
        error.to_string().contains("regular, non-symlink"),
        "{error}"
    );
}
