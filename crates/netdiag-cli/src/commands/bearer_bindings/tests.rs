use super::*;
use clap::Parser;

#[derive(Debug, Parser)]
struct TestArgs {
    #[command(flatten)]
    bindings: CliBearerBindings,
}

fn parse(values: &[&str]) -> anyhow::Result<BearerEnvironmentBindings> {
    TestArgs::try_parse_from(values)
        .map_err(anyhow::Error::from)?
        .bindings
        .build()
}

#[test]
fn no_binding_is_an_explicit_empty_set() {
    parse(&["test"]).expect("empty bindings");
}

#[test]
fn exact_canonical_http_bindings_are_accepted_for_every_supported_kind() {
    for (source_kind, origin) in [
        ("http-json", "https://collector.example.test"),
        ("prometheus-query", "https://metrics.example.test:8443"),
        ("prometheus-metrics", "http://[::1]:9100"),
    ] {
        parse(&[
            "test",
            "--bearer-binding",
            "gateway",
            source_kind,
            origin,
            "GATEWAY_TOKEN",
        ])
        .expect("exact binding");
    }
}

#[test]
fn clap_requires_all_four_identity_fields_per_occurrence() {
    let error = TestArgs::try_parse_from([
        "test",
        "--bearer-binding",
        "gateway",
        "http-json",
        "https://collector.example.test",
    ])
    .expect_err("partial binding must fail while parsing");
    assert!(error.to_string().contains("4 values required"), "{error}");
}

#[test]
fn non_http_and_noncanonical_origins_fail_closed() {
    let non_http = parse(&[
        "test",
        "--bearer-binding",
        "capture",
        "native-pcap",
        "https://collector.example.test",
        "CAPTURE_TOKEN",
    ])
    .expect_err("non-HTTP source kind must fail");
    assert!(non_http.to_string().contains("source kind"));

    for origin in [
        "https://collector.example.test/path",
        "https://COLLECTOR.example.test:443",
        " https://collector.example.test",
    ] {
        let error = parse(&[
            "test",
            "--bearer-binding",
            "gateway",
            "http-json",
            origin,
            "GATEWAY_TOKEN",
        ])
        .expect_err("noncanonical origin must fail");
        assert!(error.to_string().contains("must be canonical"), "{error}");
    }
}

#[test]
fn duplicate_and_insecure_bindings_fail_before_environment_access() {
    let duplicate = parse(&[
        "test",
        "--bearer-binding",
        "gateway",
        "http-json",
        "https://collector.example.test",
        "GATEWAY_TOKEN",
        "--bearer-binding",
        "gateway",
        "http-json",
        "https://collector.example.test",
        "GATEWAY_TOKEN",
    ])
    .expect_err("duplicate binding must fail");
    assert!(duplicate.to_string().contains("duplicate identity"));

    let insecure = parse(&[
        "test",
        "--bearer-binding",
        "gateway",
        "http-json",
        "http://collector.example.test",
        "PATH",
    ])
    .expect_err("insecure remote bearer origin must fail");
    assert!(insecure.to_string().contains("requires HTTPS"));
}
